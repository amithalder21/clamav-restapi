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


