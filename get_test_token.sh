#!/bin/bash
set -e

ENDPOINT="http://localhost:9229"
REGION="us-east-1"
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test

POOL_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool --pool-name test-pool --region $REGION --query 'UserPool.Id' --output text)
CLIENT_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool-client --user-pool-id $POOL_ID --client-name test-client --region $REGION --query 'UserPoolClient.ClientId' --output text)

aws --endpoint-url=$ENDPOINT cognito-idp admin-create-user --user-pool-id $POOL_ID --username "admin@test.com" --message-action SUPPRESS --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username "admin@test.com" --password "Password1!" --permanent --region $REGION >/dev/null

aws --endpoint-url=$ENDPOINT cognito-idp create-group --user-pool-id $POOL_ID --group-name "admin" --region $REGION >/dev/null 2>&1 || true
aws --endpoint-url=$ENDPOINT cognito-idp admin-add-user-to-group --user-pool-id $POOL_ID --username "admin@test.com" --group-name "admin" --region $REGION >/dev/null

# cognito-local puts 'cognito:groups' in the IdToken mostly, but we use IdToken for our tests to ensure it passes the admin check. 
# Alternatively, for real M2M we use AccessToken with scopes. Since it's local mocking, we can just use the IdToken for both regular and admin tests.
TOKEN=$(aws --endpoint-url=$ENDPOINT cognito-idp initiate-auth \
  --client-id $CLIENT_ID \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME="admin@test.com",PASSWORD="Password1!" \
  --region $REGION \
  --query 'AuthenticationResult.IdToken' --output text)

echo "$TOKEN|$POOL_ID"
