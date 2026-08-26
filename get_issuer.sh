export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
ENDPOINT="http://localhost:9229"
REGION="us-east-1"
POOL_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool --pool-name test-pool2 --region $REGION --query 'UserPool.Id' --output text)
CLIENT_ID=$(aws --endpoint-url=$ENDPOINT cognito-idp create-user-pool-client --user-pool-id $POOL_ID --client-name test-client2 --region $REGION --query 'UserPoolClient.ClientId' --output text)
aws --endpoint-url=$ENDPOINT cognito-idp admin-create-user --user-pool-id $POOL_ID --username "admin2@test.com" --message-action SUPPRESS --region $REGION >/dev/null 2>&1
aws --endpoint-url=$ENDPOINT cognito-idp admin-set-user-password --user-pool-id $POOL_ID --username "admin2@test.com" --password "Password1!" --permanent --region $REGION >/dev/null
TOKEN=$(aws --endpoint-url=$ENDPOINT cognito-idp initiate-auth --client-id $CLIENT_ID --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME="admin2@test.com",PASSWORD="Password1!" --query 'AuthenticationResult.AccessToken' --output text)
python3 -c "import sys, jwt; print(jwt.decode('$TOKEN', options={'verify_signature': False})['iss'])"
