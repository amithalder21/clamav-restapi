#!/bin/bash
# P2 (HIGH) - Verify real ClamAV signatures with wildcard offsets are NOT
# subject to EICAR's exact-68-byte-match design quirk.
#
# The 2026-09-01 AppSec adversarial test found all 6 position/obfuscation
# EICAR variants (cat4_*) returned CLEAN, and flagged this as
# "context-dependent - EICAR requires exact 68B match... verify with Amit."
#
# EICAR is deliberately designed by the EICAR/CARO standard to require an
# exact match so it does NOT accidentally trigger on modified/partial
# content - that's a property of the EICAR test string itself, not a general
# limitation of ClamAV's signature engine. Real ClamAV .ndb signatures
# commonly use wildcard offsets that match a pattern anywhere in a file.
#
# This script proves that directly: it scans the same position/padding
# variants as the report's cat4 category (start/middle/end/null-padded), but
# using a real ClamAV signature (test-signatures/local.ndb, offset "*")
# instead of relying on EICAR. All variants below MUST be caught if
# local.ndb is loaded - that isolates the report's finding to EICAR's own
# design, not a scanning gap.
#
# Requires: the API built from this repo's current Dockerfile (which now
# bakes test-signatures/local.ndb into /var/lib/clamav) and restarted so
# clamd loads it. Run: ./clamtrac docker restart && ./clamtrac test p2
# (or invoke this script directly with BASE_URL/JWT_TOKEN set).

set -eo pipefail
BASE_URL="${BASE_URL:-http://localhost:9000}"
JWT_TOKEN="${JWT_TOKEN:-}"

TEST_STRING="CLAMREST_TEST_SIG_7f3a9c2e"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

pass=0
fail=0

check() {
  local name="$1" expected="$2" file="$3"
  local out="$TMP_DIR/resp.json"
  curl -s -o "$out" \
    -H "Authorization: Bearer $JWT_TOKEN" -F "file=@$file" "$BASE_URL/api/v1/scan/file" >/dev/null
  local status
  status=$(grep -o '"av-status":"[A-Z]*"' "$out" | cut -d'"' -f4)
  if [ "$status" == "$expected" ]; then
    echo "PASS  $name -> $status"
    pass=$((pass + 1))
  else
    echo "FAIL  $name -> expected $expected, got '$status' (raw: $(cat "$out"))"
    fail=$((fail + 1))
  fi
}

# Mirrors the report's cat4 position/obfuscation test cases exactly, but
# with a signature ClamAV can match anywhere (offset "*"), unlike EICAR.
printf '%s' "$TEST_STRING" > "$TMP_DIR/p2_start.txt"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%sBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' "$TEST_STRING" > "$TMP_DIR/p2_middle.txt"
printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%s' "$TEST_STRING" > "$TMP_DIR/p2_end.txt"
python3 -c "import sys; sys.stdout.buffer.write(b'\x00'*512 + b'$TEST_STRING'.encode())" > "$TMP_DIR/p2_leading_null.bin"
python3 -c "import sys; sys.stdout.buffer.write(b'$TEST_STRING'.encode() + b'\x00'*1024)" > "$TMP_DIR/p2_trailing_pad.bin"
echo "this file has no test signature in it at all" > "$TMP_DIR/p2_clean.txt"

check "signature at file start"           "INFECTED" "$TMP_DIR/p2_start.txt"
check "signature embedded in middle"      "INFECTED" "$TMP_DIR/p2_middle.txt"
check "signature at file end"             "INFECTED" "$TMP_DIR/p2_end.txt"
check "512 leading null bytes + sig"      "INFECTED" "$TMP_DIR/p2_leading_null.bin"
check "sig + 1KB trailing null padding"   "INFECTED" "$TMP_DIR/p2_trailing_pad.bin"
check "clean file (negative control)"     "CLEAN"    "$TMP_DIR/p2_clean.txt"

echo ""
echo "P2 result: $pass passed, $fail failed"
if [ "$fail" -eq 0 ]; then
  echo "CONFIRMED: position/padding does not evade a real wildcard-offset ClamAV signature."
  echo "The report's cat4 findings are attributable to EICAR's own exact-match design, not a scanning gap."
else
  echo "UNEXPECTED: a wildcard-offset signature was evaded. This would indicate a real ClamAV"
  echo "scanning gap (not an EICAR quirk) and needs investigation before closing P2."
fi
[ "$fail" -eq 0 ]
