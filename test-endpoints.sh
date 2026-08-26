#!/bin/bash
# Exercises every clamav-restapi endpoint against the local docker-compose
# stack (docker-compose.local.yml). Run from the repo root after:
#   docker compose -f docker-compose.local.yml up --build -d
#
# Requires: curl, jq (optional, for pretty output), awslocal or aws cli.

set -uo pipefail

HOST="http://localhost:9000"

echo "Fetching JWT token from cognito-local..."
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
ENDPOINT="http://localhost:9229"
REGION="us-east-1"

# Provision Cognito pool and client
POOL_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool --pool-name test-pool --region $REGION --query 'UserPool.Id' --output text)
CLIENT_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool-client --user-pool-id $POOL_ID --client-name test-client --region $REGION --query 'UserPoolClient.ClientId' --output text)

# Restart clamav-rest with the dynamic pool ID so issuer validation passes
echo "Injecting dynamic POOL_ID ($POOL_ID) into clamav-rest environment..."
export COGNITO_JWKS_URL="http://cognito-local:9229/$POOL_ID/.well-known/jwks.json"
export COGNITO_ISSUER="http://0.0.0.0:9229/$POOL_ID"
docker compose -f docker-compose.local.yml up -d clamav-rest
sleep 3 # Wait for the app to pick up the new keys

# Provision admin user and group
aws --endpoint-url=$ENDPOINT cognito-idp admin-create-user --user-pool-id $POOL_ID --username "admin@test.com" --message-action SUPPRESS --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username "admin@test.com" --password "Password1!" --permanent --region $REGION >/dev/null
aws --endpoint-url=$ENDPOINT cognito-idp create-group --user-pool-id $POOL_ID --group-name "admin" --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-add-user-to-group --user-pool-id $POOL_ID --username "admin@test.com" --group-name "admin" --region $REGION >/dev/null

# Authenticate to get IdToken
JWT_TOKEN=$(aws --endpoint-url=$ENDPOINT cognito-idp initiate-auth \
  --client-id $CLIENT_ID \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="admin@test.com",PASSWORD="Password1!" \
  --region $REGION \
  --query 'AuthenticationResult.IdToken' --output text)

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
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/scan/url" \
  -H "Content-Type: application/json" -d '{"url":"http://example.com"}')
check "POST /api/v1/scan/url without API key -> 401" 401 "$code"
echo

echo "== 3. /api/v1/scan/file — clean file =="
echo "this is a clean test file" > /tmp/clean.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/scan/file" \
  -H "Authorization: Bearer $JWT_TOKEN" -F "file=@/tmp/clean.txt")
check "POST /api/v1/scan/file clean file -> 200" 200 "$code"
grep -q '"av-status":"CLEAN"' /tmp/out.json && green "  clean file correctly marked CLEAN"
echo

echo "== 4. /api/v1/scan/file — EICAR test virus (expect INFECTED) =="
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/scan/file" \
  -H "Authorization: Bearer $JWT_TOKEN" -F "file=@eicar.com.txt")
check "POST /api/v1/scan/file EICAR -> 406 (Not Acceptable / INFECTED)" 406 "$code"
grep -q '"av-status":"INFECTED"' /tmp/out.json && green "  EICAR correctly flagged INFECTED"
echo

echo "== 5. /api/v1/scan/file — oversized upload is rejected (413) =="
# MAX_FILE_SIZE=100M in this stack; generate a 101MB file to trip the cap
dd if=/dev/zero of=/tmp/big.bin bs=1M count=101 2>/dev/null
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/scan/file" \
  -H "Authorization: Bearer $JWT_TOKEN" -F "file=@/tmp/big.bin")
check "POST /api/v1/scan/file 101MB file -> 413" 413 "$code"
rm -f /tmp/big.bin
echo


echo "== 7. /api/v1/scan/url — SSRF to internal/link-local address is blocked =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/scan/url" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}')
check "POST /api/v1/scan/url to 169.254.169.254 -> 400 (blocked)" 400 "$code"
echo

echo "== 8. /api/v1/scan/url — legitimate external URL scans clean =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/scan/url" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://raw.githubusercontent.com/octocat/Hello-World/master/README"}')
check "POST /api/v1/scan/url external file -> 200" 200 "$code"
echo

echo "== 9. /api/v1/async-scan/file — upload triggers async scan + webhook =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/async-scan/file" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -F "file=@eicar.com.txt" \
  -F "webhook_url=http://webhook-receiver:8080/webhook")
check "POST /api/v1/async-scan/file -> 202 Accepted" 202 "$code"
scan_id=$(jq -r .scan_id /tmp/out.json 2>/dev/null)
echo "  scan_id=$scan_id — waiting for webhook delivery..."
sleep 3
curl -s http://localhost:8080/ | grep -q "$scan_id" \
  && green "  PASS  webhook received result for $scan_id" \
  || red   "  FAIL  webhook never received result for $scan_id"
echo

echo "== 10. /api/v1/async-scan/url — same, via URL fetch =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/async-scan/url" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" \
  -d '{"url":"https://raw.githubusercontent.com/octocat/Hello-World/master/README","webhook_url":"http://webhook-receiver:8080/webhook"}')
check "POST /api/v1/async-scan/url -> 202 Accepted" 202 "$code"
echo

echo "== 11. /admin/* — wrong admin key rejected, right key works =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/api/v1/admin/status" -H "Authorization: Bearer wrong-token")
check "GET /api/v1/admin/status wrong key -> 403" 403 "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/api/v1/admin/status" -H "Authorization: Bearer $JWT_TOKEN")
check "GET /api/v1/admin/status correct key -> 200" 200 "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/admin/update-signatures" -H "Authorization: Bearer $JWT_TOKEN")
check "POST /api/v1/admin/update-signatures -> 202 Accepted" 202 "$code"

code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/admin/reload" -H "Authorization: Bearer $JWT_TOKEN")
check "POST /api/v1/admin/reload -> 200 OK" 200 "$code"
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
  
  # Check if S3 object was deleted from source bucket
  STATUS=$(python3 -c "
import boto3, botocore
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
try:
    s3.head_object(Bucket='clamrest-uploads', Key='eicar-test.txt')
    print('EXISTS')
except botocore.exceptions.ClientError as e:
    if e.response['Error']['Code'] == '404':
        print('DELETED')
    else:
        print('ERROR')
" 2>/dev/null)

  if [ "$STATUS" = "DELETED" ]; then
    green "  PASS  Infected S3 object was successfully auto-deleted from source bucket"
    PASS=$((PASS+1))
  else
    red   "  FAIL  S3 object was NOT deleted from source bucket (got $STATUS)"
    FAIL=$((FAIL+1))
  fi
  
  # Check if S3 object exists in quarantine bucket and has INFECTED tag
  QTAGS=$(python3 -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
try:
    tags = s3.get_object_tagging(Bucket='clamrest-quarantine', Key='eicar-test.txt')['TagSet']
    print([t['Value'] for t in tags if t['Key'] == 'av-status'][0])
except Exception as e:
    print('ERROR')
" 2>/dev/null)

  if [ "$QTAGS" = "INFECTED" ]; then
    green "  PASS  Infected S3 object was successfully quarantined with INFECTED tag preserved"
    PASS=$((PASS+1))
  else
    red   "  FAIL  S3 object was not correctly quarantined (got $QTAGS)"
    FAIL=$((FAIL+1))
  fi

  # Check if SNS notification reached webhook-receiver
  curl -s http://localhost:8080/ | grep -q 'clamrest-uploads/eicar-test.txt' \
    && green "  PASS  SNS notification successfully delivered to webhook" \
    || red   "  FAIL  SNS notification missing from webhook logs"
else
  red   "  FAIL  S3 upload failed completely"
  FAIL=$((FAIL+1))
fi
echo

echo "== 13. EventBridge Webhook -> POST /api/v1/events/s3 (clean file) =="
echo "clean file" > clean-test.txt
python3 -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
s3.upload_file('clean-test.txt', 'clamrest-uploads', 'clean-test.txt')
"

# Send a fake EventBridge / S3 Notification payload
EVENT_PAYLOAD='{
  "Records": [
    {
      "eventName": "ObjectCreated:Put",
      "s3": {
        "bucket": { "name": "clamrest-uploads" },
        "object": { "key": "clean-test.txt" }
      }
    }
  ]
}'

code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/events/s3" \
  -H "Authorization: Bearer $JWT_TOKEN" -H "Content-Type: application/json" -d "$EVENT_PAYLOAD")
check "POST /api/v1/events/s3 -> 202 Accepted" 202 "$code"

echo "  waiting for background EventBridge processing to finish..."
sleep 4

TAGS=$(python3 -c "
import boto3
s3 = boto3.client('s3', endpoint_url='http://localhost:4566', region_name='us-east-1', aws_access_key_id='test', aws_secret_access_key='test')
try:
    tags = s3.get_object_tagging(Bucket='clamrest-uploads', Key='clean-test.txt')['TagSet']
    print([t['Value'] for t in tags if t['Key'] == 'av-status'][0])
except Exception:
    print('ERROR')
" 2>/dev/null)

if [ "$TAGS" = "CLEAN" ]; then
  green "  PASS  Clean S3 object was correctly processed and tagged as CLEAN via Webhook"
  PASS=$((PASS+1))
else
  red   "  FAIL  S3 object was not tagged correctly via Webhook (got $TAGS)"
  FAIL=$((FAIL+1))
fi

echo "=============================="
echo "Results: $PASS passed, $FAIL failed"
echo "=============================="

# Cleanup
rm -f /tmp/clean.txt /tmp/big.bin /tmp/out.json eicar.com.txt clean-test.txt

if [ "$FAIL" -eq 0 ]; then
  exit 0
else
  exit 1
fi
