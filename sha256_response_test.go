package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	clamd "github.com/dutchcoders/go-clamd"
)

func TestScanResponseSHA256Integrity(t *testing.T) {
	// 1. Create a dummy file with known content
	content := []byte("%PDF-1.4\nTest file for SHA256 verification\n%%EOF")
	hasher := sha256.New()
	hasher.Write(content)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	tmpFile, err := os.CreateTemp("", "test-sha256-*.pdf")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Write(content)
	tmpFile.Close()

	// 2. Test persistScannedFile returns the exact hash
	timings := ScanTimings{Total: 10 * time.Millisecond}
	_, _, returnedHash := persistScannedFile("CLEAN", "tenant-test", "test.pdf", tmpFile.Name(), "req-test", "scan-test", "CLEAN", timings)
	if returnedHash != expectedHash {
		t.Errorf("persistScannedFile sha256 = %q, want %q", returnedHash, expectedHash)
	}

	// 3. Test writeScanResponse includes sha256 in the response JSON
	w := httptest.NewRecorder()
	scanRes := &clamd.ScanResult{Status: clamd.RES_OK, Description: "OK"}
	extra := ExtraFields{
		S3Path:      "s3://clean-bucket/test.pdf",
		DownloadURL: "https://clean-bucket.s3.amazonaws.com/test.pdf",
		SHA256:      expectedHash,
	}
	writeScanResponse(w, scanRes, "test.pdf", extra)

	var resp ScanResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse writeScanResponse JSON: %v", err)
	}
	if resp.SHA256 != expectedHash {
		t.Errorf("writeScanResponse SHA256 = %q, want %q", resp.SHA256, expectedHash)
	}
	if resp.Status != "CLEAN" {
		t.Errorf("writeScanResponse Status = %q, want CLEAN", resp.Status)
	}

	// 4. Test formatScanResponse includes sha256 in the JSON string
	jsonStr, code := formatScanResponse(scanRes, "scan-123", "test.pdf", extra)
	if code != 200 {
		t.Errorf("formatScanResponse code = %d, want 200", code)
	}
	var asyncResp ScanResponse
	if err := json.Unmarshal([]byte(jsonStr), &asyncResp); err != nil {
		t.Fatalf("failed to parse formatScanResponse JSON: %v", err)
	}
	if asyncResp.SHA256 != expectedHash {
		t.Errorf("formatScanResponse SHA256 = %q, want %q", asyncResp.SHA256, expectedHash)
	}
}
