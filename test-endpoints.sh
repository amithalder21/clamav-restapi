#!/bin/bash
# Exercises every clamav-restapi endpoint against the local docker-compose
# stack (docker-compose.local.yml). Run from the repo root after:
#   docker compose -f docker-compose.local.yml up --build -d
#
# Requires: curl, jq (optional, for pretty output), awslocal or aws cli.

set -uo pipefail

HOST="http://localhost:9000"
API_KEY="local-test-api-key"
ADMIN_KEY="local-test-admin-key"
PASS=0
FAIL=0

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }

check() {
  # check "description" expected_status actual_status
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    green "  PASS  $desc (got $actual)"
    PASS=$((PASS+1))
  else
    red   "  FAIL  $desc (expected $expected, got $actual)"
    FAIL=$((FAIL+1))
  fi
}

echo "== 0. Waiting for app to be healthy =="
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/")
  [ "$code" = "200" ] && break
  sleep 2
done
curl -s "$HOST/" | jq . 2>/dev/null || curl -s "$HOST/"
echo

echo "== 1. Home / health check =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/")
check "GET / returns 200" 200 "$code"
echo

echo "== 2. Auth: unauthenticated request is rejected =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/scan-url" \
  -H "Content-Type: application/json" -d '{"url":"http://example.com"}')
check "POST /scan-url without API key -> 401" 401 "$code"
echo

echo "== 3. /scan — clean file =="
echo "this is a clean test file" > /tmp/clean.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/scan" \
  -H "X-API-Key: $API_KEY" -F "file=@/tmp/clean.txt")
check "POST /scan clean file -> 200" 200 "$code"
grep -q '"av-status":"CLEAN"' /tmp/out.json && green "  clean file correctly marked CLEAN"
echo

echo "== 4. /scan — EICAR test virus (expect INFECTED) =="
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/scan" \
  -H "X-API-Key: $API_KEY" -F "file=@eicar.com.txt")
check "POST /scan EICAR -> 406 (Not Acceptable / INFECTED)" 406 "$code"
grep -q '"av-status":"INFECTED"' /tmp/out.json && green "  EICAR correctly flagged INFECTED"
echo

echo "== 5. /scan — oversized upload is rejected (413) =="
# MAX_FILE_SIZE=100M in this stack; generate a 101MB file to trip the cap
dd if=/dev/zero of=/tmp/big.bin bs=1M count=101 2>/dev/null
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/scan" \
  -H "X-API-Key: $API_KEY" -F "file=@/tmp/big.bin")
check "POST /scan 101MB file -> 413" 413 "$code"
rm -f /tmp/big.bin
echo

echo "== 6. /scanPath — path traversal is blocked =="
code=$(curl -s -o /dev/null -w "%{http_code}" -G "$HOST/scanPath" \
  -H "X-API-Key: $API_KEY" --data-urlencode "path=../../etc/passwd")
check "GET /scanPath?path=../../etc/passwd -> 403" 403 "$code"
echo

echo "== 7. /scan-url — SSRF to internal/link-local address is blocked =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/scan-url" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}')
check "POST /scan-url to 169.254.169.254 -> 400 (blocked)" 400 "$code"
echo

echo "== 8. /scan-url — legitimate external URL scans clean =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/scan-url" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"url":"https://raw.githubusercontent.com/octocat/Hello-World/master/README"}')
check "POST /scan-url external file -> 200" 200 "$code"
echo

echo "== 9. /scan-async — upload triggers async scan + webhook =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/scan-async" \
  -H "X-API-Key: $API_KEY" \
  -F "file=@eicar.com.txt" \
  -F "webhook_url=http://webhook-receiver:8080/webhook")
check "POST /scan-async -> 202 Accepted" 202 "$code"
scan_id=$(jq -r .scan_id /tmp/out.json 2>/dev/null)
echo "  scan_id=$scan_id — waiting for webhook delivery..."
sleep 3
curl -s http://localhost:8080/ | grep -q "$scan_id" \
  && green "  PASS  webhook received result for $scan_id" \
  || red   "  FAIL  webhook never received result for $scan_id"
echo

echo "== 10. /scan-url-async — same, via URL fetch =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/scan-url-async" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"url":"https://raw.githubusercontent.com/octocat/Hello-World/master/README","webhook_url":"http://webhook-receiver:8080/webhook"}')
check "POST /scan-url-async -> 202 Accepted" 202 "$code"
echo

echo "== 11. /admin/* — wrong admin key rejected, right key works =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/admin/status" -H "X-API-Key: wrong-key")
check "GET /admin/status wrong key -> 403" 403 "$code"
code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/admin/status" -H "X-API-Key: $ADMIN_KEY")
check "GET /admin/status correct key -> 200" 200 "$code"
echo

echo "== 12. S3 -> SQS -> scan -> tag -> webhook (full pipeline) =="
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1
python3 -c "
import boto3, sys
try:
    s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
    s3.upload_file('eicar.com.txt', 'clamrest-uploads', 'eicar-test.txt')
except Exception as e:
    print(f'upload failed: {e}')
    sys.exit(1)
"
if [ $? -eq 0 ]; then
  echo "  uploaded eicar-test.txt to S3, waiting for SQS consumer to pick it up..."
  sleep 4
  
  # Check if S3 object was tagged properly
  TAGS=$(python3 -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
tags = s3.get_object_tagging(Bucket='clamrest-uploads', Key='eicar-test.txt')['TagSet']
print([t['Value'] for t in tags if t['Key'] == 'av-status'][0])
" 2>/dev/null)

  if [ "$TAGS" = "INFECTED" ]; then
    green "  PASS  S3 object was successfully tagged as INFECTED"
    PASS=$((PASS+1))
  else
    red   "  FAIL  S3 object was not tagged — check 'docker compose logs clamav-rest'"
    FAIL=$((FAIL+1))
  fi
else
  red   "  FAIL  S3 upload failed completely"
  FAIL=$((FAIL+1))
fi

echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

# Cleanup
rm -f /tmp/clean.txt /tmp/big.bin /tmp/out.json eicar.com.txt

if [ "$FAIL" -eq 0 ]; then
  exit 0
else
  exit 1
fi
