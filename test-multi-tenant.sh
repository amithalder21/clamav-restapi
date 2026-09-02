#!/bin/bash
# test-multi-tenant.sh
# Tests the Multi-Tenancy Architecture (Cognito Client IDs, Dragonfly Isolation, S3 Isolation)

set -uo pipefail

HOST="http://localhost:9000"
ENDPOINT="http://localhost:9229"
REGION="us-east-1"

green() { printf "\033[32m%s\033[0m\n" "$1"; }
red()   { printf "\033[31m%s\033[0m\n" "$1"; }
check() {
  local desc="$1" expected="$2" actual="$3"
  if [ "$expected" = "$actual" ]; then
    green "  PASS  $desc (got $actual)"
  else
    red   "  FAIL  $desc (expected $expected, got $actual)"
  fi
}

echo "1. Provisioning Cognito User Pool..."
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
POOL_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool --pool-name polestar-pool --region $REGION --query 'UserPool.Id' --output text)

echo "2. Provisioning PurpleTrac and DocIntel App Clients..."
PURPLETRAC_CLIENT_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool-client --user-pool-id $POOL_ID --client-name purpletrac --region $REGION --query 'UserPoolClient.ClientId' --output text)
DOCINTEL_CLIENT_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool-client --user-pool-id $POOL_ID --client-name docintel --region $REGION --query 'UserPoolClient.ClientId' --output text)

echo "   PurpleTrac Client ID: $PURPLETRAC_CLIENT_ID"
echo "   DocIntel Client ID: $DOCINTEL_CLIENT_ID"

echo "3. Seeding Dragonfly DB Tenant Configs..."
# PurpleTrac uses port 8000 for webhooks, DocIntel uses port 8001 (mock endpoints)
docker exec clamrest-dragonfly redis-cli SET "tenant:${PURPLETRAC_CLIENT_ID}:config" '{"webhook_url":"http://webhook-receiver:8000/purpletrac"}' > /dev/null
docker exec clamrest-dragonfly redis-cli SET "tenant:${DOCINTEL_CLIENT_ID}:config" '{"webhook_url":"http://webhook-receiver:8000/docintel"}' > /dev/null

echo "4. Authenticating and fetching JWTs..."
aws --endpoint-url=$ENDPOINT cognito-idp admin-create-user --user-pool-id $POOL_ID --username "purpletrac@polestar.com" --message-action SUPPRESS --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username "purpletrac@polestar.com" --password "Password1!" --permanent --region $REGION >/dev/null
aws --endpoint-url=$ENDPOINT cognito-idp admin-create-user --user-pool-id $POOL_ID --username "docintel@polestar.com" --message-action SUPPRESS --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username "docintel@polestar.com" --password "Password1!" --permanent --region $REGION >/dev/null

PURPLETRAC_JWT=$(aws --endpoint-url=$ENDPOINT cognito-idp initiate-auth --client-id $PURPLETRAC_CLIENT_ID --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME="purpletrac@polestar.com",PASSWORD="Password1!" --region $REGION --query 'AuthenticationResult.IdToken' --output text)
DOCINTEL_JWT=$(aws --endpoint-url=$ENDPOINT cognito-idp initiate-auth --client-id $DOCINTEL_CLIENT_ID --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME="docintel@polestar.com",PASSWORD="Password1!" --region $REGION --query 'AuthenticationResult.IdToken' --output text)

echo "5. Rebuilding and Reloading ClamTrac API with new Multi-Tenant Config..."
export COGNITO_JWKS_URL="http://cognito-local:9229/$POOL_ID/.well-known/jwks.json"
export COGNITO_ISSUER="http://0.0.0.0:9229/$POOL_ID"
docker compose -f docker-compose.local.yml up --build -d clamav-rest

echo "Waiting for ClamAV API to be healthy..."
while ! curl -s http://localhost:9000/ | grep -q 'OK'; do
  sleep 2
done
echo "ClamTrac API is ready!"

echo "6. Testing PurpleTrac Async Scan Upload..."
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > purpletrac_payload.html
scan_resp=$(curl -s -X POST "$HOST/api/v1/async-scan/file" -H "Authorization: Bearer $PURPLETRAC_JWT" -F "file=@purpletrac_payload.html")
echo "RAW RESP: $scan_resp"
PURPLETRAC_SCAN_ID=$(echo $scan_resp | jq -r .scan_id)

echo "   PurpleTrac Scan ID: $PURPLETRAC_SCAN_ID"
sleep 5 # wait for scan to finish

echo "7. Testing Tenant Data Isolation in Dragonfly DB..."
# PurpleTrac should be able to query its own scan
pt_code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/api/v1/async-scan/file?scan_id=${PURPLETRAC_SCAN_ID}" -H "Authorization: Bearer $PURPLETRAC_JWT")
check "PurpleTrac fetching its own scan -> 200" 200 "$pt_code"

# DocIntel should get a 404 Not Found if they try to look up PurpleTrac's scan ID
di_code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/api/v1/async-scan/file?scan_id=${PURPLETRAC_SCAN_ID}" -H "Authorization: Bearer $DOCINTEL_JWT")
check "DocIntel attempting to fetch PurpleTrac's scan -> 404" 404 "$di_code"

echo "8. Verifying S3 Quarantine Folder Prefix Isolation..."
AWS_ENDPOINT="http://localhost:4566"
DATE_STR=$(date -u +%Y/%m/%d)
# We expect the file to be under: s3://clamrest-quarantine/<PURPLETRAC_CLIENT_ID>/<DATE>/...
s3_ls=$(aws --endpoint-url=$AWS_ENDPOINT s3 ls s3://clamrest-quarantine/${PURPLETRAC_CLIENT_ID}/${DATE_STR}/ --region us-east-1)
if [[ "$s3_ls" == *"${PURPLETRAC_SCAN_ID}"* ]]; then
  green "  PASS  S3 Quarantine file correctly partitioned under /${PURPLETRAC_CLIENT_ID}/"
else
  red "  FAIL  S3 Quarantine file NOT FOUND in expected tenant partition"
fi

echo "Test complete!"
