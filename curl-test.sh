#!/bin/bash

# Configuration
HOST="http://localhost:9090"
ADMIN_KEY="secret"  # Change this to match your ADMIN_API_KEY environment variable
WEBHOOK_URL="http://httpbin.org/post"

echo "=========================================="
echo "🛡️  ClamAV REST API - Full Test Suite"
echo "=========================================="

echo -e "\n[1/8] Testing Application Health (GET /)"
curl -s $HOST/ | jq

echo -e "\n[2/8] Testing Synchronous File Scan (POST /api/v1/scan/file)"
echo "This is a clean test file." > clean_test.txt
curl -s -X POST -F "file=@clean_test.txt" $HOST/api/v1/scan/file | jq
rm clean_test.txt

echo -e "\n[3/8] Testing Asynchronous File Scan (POST /api/v1/async-scan/file)"
echo "This is a clean test file." > clean_async.txt
curl -i -X POST -F "file=@clean_async.txt" -F "webhook_url=$WEBHOOK_URL" $HOST/api/v1/async-scan/file
rm clean_async.txt

echo -e "\n[4/8] Testing Synchronous Remote URL Scan (POST /api/v1/scan/url)"
curl -s -X POST -H "Content-Type: application/json" -d '{"url":"https://secure.eicar.org/eicar.com.txt"}' $HOST/api/v1/scan/url | jq

echo -e "\n[5/8] Testing Asynchronous Remote URL Scan (POST /api/v1/async-scan/url)"
curl -i -X POST -H "Content-Type: application/json" -d "{\"url\":\"https://secure.eicar.org/eicar.com.txt\", \"webhook_url\":\"$WEBHOOK_URL\"}" $HOST/api/v1/async-scan/url

echo -e "\n[6/8] Testing AWS EventBridge S3 Payload Simulation (POST /api/v1/events/s3)"
curl -i -X POST -H "Content-Type: application/json" -d '{
  "Records": [{
    "eventName": "ObjectCreated:Put",
    "s3": { "bucket": { "name": "my-test-bucket" }, "object": { "key": "test-file.txt" } }
  }]
}' $HOST/api/v1/events/s3

echo -e "\n\n=========================================="
echo "🛠️  Admin API Endpoints"
echo "=========================================="

echo -e "\n[7/8] Testing Daemon Status & Analytics (GET /api/v1/admin/status)"
curl -s -H "Authorization: Bearer $ADMIN_KEY" $HOST/api/v1/admin/status | jq

echo -e "\n[8/8] Testing Signature Updates (POST /api/v1/admin/update-signatures)"
curl -s -X POST -H "Authorization: Bearer $ADMIN_KEY" $HOST/api/v1/admin/update-signatures | jq

# Note: Deliberately skipping /api/v1/admin/reload in this automated suite to prevent 
# interrupting the background signature update we just triggered above.

echo -e "\n=========================================="
echo "✅ Test Suite Complete!"
echo "Run 'docker logs clamav-restapi' to view the structured JSON audit logs for these events."
echo "=========================================="