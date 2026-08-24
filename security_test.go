package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestSafeHTTPClient(t *testing.T) {
	client := SafeHTTPClient()

	urls := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1:9000",
		"http://localhost:9000",
		"http://[::1]:9000",
	}

	for _, u := range urls {
		_, err := client.Get(u)
		if err == nil {
			t.Errorf("Expected error for internal URL %s, got none", u)
		}
	}
}

func TestPathTraversalBlock(t *testing.T) {
	// Set SCAN_BASE_DIR to /tmp for testing
	os.Setenv("SCAN_BASE_DIR", "/tmp")
	opts = make(map[string]string)
	opts["SCAN_BASE_DIR"] = "/tmp"

	req, err := http.NewRequest("GET", "/scanPath?path=../../etc/passwd", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanPathHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}

	expected := `{"error":"Access denied: path is outside allowed directory"}`
	if rr.Body.String() != expected+"\n" {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestPathTraversalBlockAbsolute(t *testing.T) {
	os.Setenv("SCAN_BASE_DIR", "/tmp")
	opts = make(map[string]string)
	opts["SCAN_BASE_DIR"] = "/tmp"

	req, err := http.NewRequest("GET", "/scanPath?path=/etc/passwd", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(scanPathHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusForbidden)
	}
}
