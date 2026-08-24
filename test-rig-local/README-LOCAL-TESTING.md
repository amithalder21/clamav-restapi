# Local test setup — clamav-restapi with dummy AWS (LocalStack)

## Files in this kit

Drop these into the **repo root**:
```
clamav-restapi/
├── docker-compose.local.yml
├── test-endpoints.sh
├── localstack-init/
│   └── init-aws.sh
└── webhook-receiver/
    ├── Dockerfile
    └── server.py
```

## What it spins up

- **LocalStack** — fake S3 + SQS + SNS on `http://localhost:4566`. The init
  script auto-creates an S3 bucket (`clamrest-uploads`), an SQS queue
  (`clamrest-scan-queue`) wired to receive `ObjectCreated` events from that
  bucket, and an SNS topic (`clamrest-scan-results`).
- **webhook-receiver** — a tiny Python listener on `:8080` that logs every
  webhook POST the app sends it, so you can verify `/scan-async`,
  `/scan-url-async`, and S3-triggered scans actually deliver results.
- **clamav-rest** — your app, built from the existing `Dockerfile`, pointed
  at LocalStack via `AWS_ENDPOINT_URL` and dummy credentials
  (`AWS_ACCESS_KEY_ID=test` / `AWS_SECRET_ACCESS_KEY=test` — these are
  LocalStack's documented placeholder creds, not real AWS keys).

## ⚠️ One known gap: S3 calls need path-style addressing for LocalStack

`sqs_scanner.go` creates its S3 client with `s3.NewFromConfig(cfg)` and no
options. That's correct for real AWS, but LocalStack doesn't do
virtual-hosted-style bucket DNS (`bucket.s3.amazonaws.com`) by default —
from inside a Docker network there's nothing to resolve
`clamrest-uploads.localstack` to. The SDK needs to be told to use
path-style URLs (`localstack:4566/clamrest-uploads/...`) instead.

This can't be set via an environment variable in aws-sdk-go-v2 — it's a
client option. Two ways to handle it for local testing:

**Option A — temporary local-only patch (revert before committing):**
```go
// sqs_scanner.go, wherever s3.NewFromConfig(cfg) is called:
s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.UsePathStyle = true
})
```

**Option B — gate it behind the same env var you're already setting
(safe to leave in permanently, since it's a no-op against real AWS):**
```go
s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    if os.Getenv("AWS_ENDPOINT_URL") != "" {
        o.UsePathStyle = true
    }
})
```
Option B is worth actually keeping in the repo — it costs nothing in
production (real AWS deployments won't set `AWS_ENDPOINT_URL`) and makes
the S3 code path testable against LocalStack/MinIO indefinitely, not just
for this one session.

Apply this to **both** `s3.NewFromConfig` call sites in `sqs_scanner.go`
(`scanS3EventHandler` and `startSQSConsumer`). Without it, step 12 of the
test script (the full S3→SQS→scan→tag pipeline) will fail — everything
else in the kit works regardless.

## Running it

```bash
# 1. Get an EICAR test file (already in the repo: eicar.com.txt)
ls eicar.com.txt

# 2. (Optional but recommended) install the LocalStack CLI for the init
#    script and the test script's S3 pipeline check:
pip install awscli-local

# 3. Bring the stack up
docker compose -f docker-compose.local.yml up --build -d

# 4. Watch it come healthy (clamd + freshclam take ~30-60s on first boot)
docker compose -f docker-compose.local.yml logs -f clamav-rest

# 5. Run the test script
chmod +x test-endpoints.sh
./test-endpoints.sh
```

## What the test script covers

| # | Endpoint | What it checks |
|---|----------|-----------------|
| 1 | `GET /` | health check |
| 2 | `POST /scan-url` | unauthenticated request rejected (401) |
| 3 | `POST /scan` | clean file → CLEAN |
| 4 | `POST /scan` | EICAR test string → INFECTED (406) |
| 5 | `POST /scan` | 101MB upload rejected (413) — the DoS fix |
| 6 | `GET /scanPath` | `../../etc/passwd` blocked (403) — path traversal fix |
| 7 | `POST /scan-url` | `169.254.169.254` (cloud metadata) blocked (400) — SSRF fix |
| 8 | `POST /scan-url` | legitimate external URL scans successfully |
| 9 | `POST /scan-async` | EICAR upload → 202, webhook receives INFECTED result |
| 10 | `POST /scan-url-async` | same, via URL fetch |
| 11 | `GET /admin/status` | wrong admin key → 403, correct key → 200 |
| 12 | S3 upload → SQS → scan → tag → webhook | full async pipeline (needs the patch above) |

Everything is scriptable/idempotent — safe to re-run. `docker compose down -v`
wipes LocalStack state and the shared `scan-data` volume between runs.

## Running the Go unit tests too

The repo's own `security_test.go` (SSRF + path traversal unit tests) can run
without any of the above, directly against the Go toolchain:
```bash
go test ./... -v
```
Note: `go.mod` currently pins `go 1.25.0`. If your local Go toolchain is
older, either install 1.25+, or let `GOTOOLCHAIN=auto` (the Go default since
1.21) download it automatically — that requires outbound access to
`proxy.golang.org`, which may need allow-listing in restricted networks (it
was blocked in the sandbox I used to review this repo, for reference).

## Manually poking things

```bash
# Watch what the webhook receiver has gotten so far:
curl -s http://localhost:8080/ | jq .

# List what LocalStack thinks exists:
awslocal s3 ls
awslocal s3 ls s3://clamrest-uploads
awslocal sqs list-queues
awslocal sns list-topics

# Manually feed a fake S3 event straight into the HTTP endpoint
# (bypasses SQS entirely, useful for quick iteration):
curl -X POST http://localhost:9000/scan-s3-event \
  -H "X-API-Key: local-test-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "Records": [{
      "eventName": "ObjectCreated:Put",
      "s3": {
        "bucket": {"name": "clamrest-uploads"},
        "object": {"key": "eicar-test.txt"}
      }
    }]
  }'
```

## Teardown

```bash
docker compose -f docker-compose.local.yml down -v
```
