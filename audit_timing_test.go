package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	server  *httptest.Server
}

func newFakeS3(t *testing.T) *fakeS3 {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			body, _ := io.ReadAll(r.Body)
			f.mu.Lock()
			f.objects[strings.TrimPrefix(r.URL.Path, "/")] = body
			f.mu.Unlock()
			w.Header().Set("ETag", `"fake"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			bucket := strings.TrimPrefix(strings.SplitN(r.URL.Path, "/", 3)[1], "/")
			prefix := r.URL.Query().Get("prefix")
			f.mu.Lock()
			var contents strings.Builder
			for k := range f.objects {
				if strings.HasPrefix(k, bucket+"/"+prefix) {
					contents.WriteString("<Contents><Key>" + strings.TrimPrefix(k, bucket+"/") + "</Key></Contents>")
				}
			}
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/xml")
			io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><IsTruncated>false</IsTruncated>`+contents.String()+`</ListBucketResult>`)
			return
		}
		if r.Method == http.MethodGet {
			f.mu.Lock()
			body, ok := f.objects[strings.TrimPrefix(r.URL.Path, "/")]
			f.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(f.server.Close)
	t.Setenv("AWS_ENDPOINT_URL", f.server.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	return f
}

func (f *fakeS3) keysWithPrefix(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.objects {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	return out
}

func writeTempScanFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scan-file")
	if err := os.WriteFile(p, []byte("hello pdf"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPersistScannedFileWritesTimingsToAuditRecord(t *testing.T) {
	s3 := newFakeS3(t)
	opts = map[string]string{"AWS_S3_CLEAN_BUCKET": "clean-bucket"}

	timings := ScanTimings{
		Total:         1234 * time.Millisecond,
		ClamAV:        120 * time.Millisecond,
		YARA:          210 * time.Millisecond,
		Maldet:        1100 * time.Millisecond,
		MalwareBazaar: 480 * time.Millisecond,
	}

	_, _ = persistScannedFile("CLEAN", "tenant-a", "invoice.pdf", writeTempScanFile(t), "req-1", "scan-1", "CLEAN", timings)

	keys := s3.keysWithPrefix("clean-bucket/audit/tenant-a/")
	if len(keys) != 1 {
		t.Fatalf("expected exactly one audit record, got %v", keys)
	}
	var got struct {
		ScanID   string `json:"scan_id"`
		Filename string `json:"filename"`
		ScanMS   int64  `json:"scan_ms"`
		Engines  struct {
			ClamAV        int64 `json:"clamav"`
			YARA          int64 `json:"yara"`
			Maldet        int64 `json:"maldet"`
			MalwareBazaar int64 `json:"malwarebazaar"`
		} `json:"engine_ms"`
	}
	if err := json.Unmarshal(s3.objects[keys[0]], &got); err != nil {
		t.Fatalf("audit record is not valid JSON: %v", err)
	}
	if got.ScanID != "scan-1" || got.Filename != "invoice.pdf" {
		t.Errorf("unexpected identity fields: %+v", got)
	}
	if got.ScanMS != 1234 {
		t.Errorf("scan_ms = %d, want 1234", got.ScanMS)
	}
	if got.Engines.ClamAV != 120 || got.Engines.YARA != 210 || got.Engines.Maldet != 1100 || got.Engines.MalwareBazaar != 480 {
		t.Errorf("engine_ms = %+v", got.Engines)
	}
}
