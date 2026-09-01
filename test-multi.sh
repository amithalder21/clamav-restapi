echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com.txt
TOKEN=$(curl -s -X POST http://localhost:9000/oauth2/token -d "client_id=test_client&client_secret=test_secret" | jq -r .access_token)
RESPONSE=$(curl -s -X POST http://localhost:9000/api/v1/async-scan/file -H "Authorization: Bearer $TOKEN" -F "file=@eicar.com.txt")
echo "Upload response: $RESPONSE"
SCAN_ID=$(echo $RESPONSE | jq -r .scan_id)
echo "Polling for scan_id: $SCAN_ID"
sleep 5
curl -s "http://localhost:9000/api/v1/async-scan/file?scan_id=$SCAN_ID" -H "Authorization: Bearer $TOKEN" | jq .
