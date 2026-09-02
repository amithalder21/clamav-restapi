#!/bin/bash
set -eo pipefail

HOST="http://clamav-api.example.com"
COGNITO_URL="https://test-clamav-rest-api.auth.us-east-1.amazoncognito.com/oauth2/token"

SCAN_CLIENT_ID="47csli4is2590iumqf9hobh3kj"
SCAN_CLIENT_SECRET="<YOUR_SCAN_SECRET>"

ADMIN_CLIENT_ID="3svl567u5jhgmrgrgcu4n7krfg"
ADMIN_CLIENT_SECRET="<YOUR_ADMIN_SECRET>"

# Helper for colored output
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

echo "1. Fetching SCAN JWT Token..."
SCAN_AUTH=$(echo -n "${SCAN_CLIENT_ID}:${SCAN_CLIENT_SECRET}" | base64)
SCAN_TOKEN=$(curl -s -X POST "$COGNITO_URL" \
  -H "Authorization: Basic $SCAN_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$SCAN_TOKEN" ]; then
    red "Failed to get scan token!"
    exit 1
fi
green "  Successfully retrieved SCAN token."

echo "2. Fetching ADMIN JWT Token..."
ADMIN_AUTH=$(echo -n "${ADMIN_CLIENT_ID}:${ADMIN_CLIENT_SECRET}" | base64)
ADMIN_TOKEN=$(curl -s -X POST "$COGNITO_URL" \
  -H "Authorization: Basic $ADMIN_AUTH" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$ADMIN_TOKEN" ]; then
    red "Failed to get admin token!"
    exit 1
fi
green "  Successfully retrieved ADMIN token."

echo ""
echo "--- Testing Core API Endpoints ---"

echo "== A. Health Check =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$HOST/")
check "GET / -> 200" 200 "$code"

echo "== B. Unauthorized Access =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HOST/api/v1/scan/file")
check "POST /api/v1/scan/file without token -> 401" 401 "$code"

echo "== C. Scan Clean File =="
echo "This is a safe file" > /tmp/clean.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/scan/file" \
  -H "Authorization: Bearer $SCAN_TOKEN" -F "file=@/tmp/clean.txt")
check "POST /api/v1/scan/file (clean file) -> 200" 200 "$code"
grep -q '"av-status":"CLEAN"' /tmp/out.json && green "  File correctly marked CLEAN" || red "  Failed to mark CLEAN"

echo "== D. Scan Infected File (EICAR) =="
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X POST "$HOST/api/v1/scan/file" \
  -H "Authorization: Bearer $SCAN_TOKEN" -F "file=@/tmp/eicar.txt")
check "POST /api/v1/scan/file (EICAR) -> 406" 406 "$code"
grep -q '"av-status":"INFECTED"' /tmp/out.json && green "  File correctly marked INFECTED" || red "  Failed to mark INFECTED"

echo "== E. Admin API (Wrong Token) =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X GET "$HOST/api/v1/admin/status" \
  -H "Authorization: Bearer $SCAN_TOKEN")
check "GET /api/v1/admin/status (Scan Token) -> 403 Forbidden" 403 "$code"

echo "== F. Admin API (Correct Token) =="
code=$(curl -s -o /tmp/out.json -w "%{http_code}" -X GET "$HOST/api/v1/admin/status" \
  -H "Authorization: Bearer $ADMIN_TOKEN")
check "GET /api/v1/admin/status (Admin Token) -> 200" 200 "$code"

echo "== G. Async Scan & Polling (Infected PDF) =="
cat << 'EOF' > /tmp/eicar.pdf
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 68 >>
stream
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000214 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
333
%%EOF
EOF
code=$(curl -s -o /tmp/async_out.json -w "%{http_code}" -X POST "$HOST/api/v1/async-scan/file" \
  -H "Authorization: Bearer $SCAN_TOKEN" -F "file=@/tmp/eicar.pdf")
check "POST /api/v1/async-scan/file (PDF) -> 202 Accepted" 202 "$code"

scan_id=$(grep -o '"scan_id":"[^"]*"' /tmp/async_out.json | cut -d'"' -f4)
if [ -z "$scan_id" ]; then
    red "  Failed to extract scan_id from response!"
else
    echo "  Got scan_id: $scan_id"
    echo "  Polling for results (max 10 seconds)..."
    poll_success=0
    for i in {1..5}; do
        sleep 2
        poll_code=$(curl -s -o /tmp/poll_out.json -w "%{http_code}" -X GET "$HOST/api/v1/async-scan/file?scan_id=$scan_id" \
          -H "Authorization: Bearer $SCAN_TOKEN")
        
        if [ "$poll_code" = "200" ]; then
            check "GET /api/v1/async-scan/file?scan_id=$scan_id -> 200 OK" 200 "$poll_code"
            grep -q '"av-status":"INFECTED"' /tmp/poll_out.json && green "  Async PDF correctly marked INFECTED" || red "  Failed to mark INFECTED asynchronously"
            poll_success=1
            break
        elif [ "$poll_code" = "404" ]; then
            echo "    Scan still processing (404)... retrying..."
        else
            red "    Unexpected polling response: $poll_code"
            cat /tmp/poll_out.json
            break
        fi
    done
    
    if [ "$poll_success" -eq 0 ]; then
        red "  FAIL  Polling timed out or failed to return 200 OK"
    fi
fi

echo ""
green "All AWS tests completed!"
