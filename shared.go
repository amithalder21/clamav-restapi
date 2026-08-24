package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dutchcoders/go-clamd"
)

// writeScanResponse writes the backward-compatible JSON response and status code
func writeScanResponse(w http.ResponseWriter, s *clamd.ScanResult, filename string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// The original code uses a JSON format with unquoted keys, maintaining this for backwards compatibility
	respJson := fmt.Sprintf("{ Status: \"%s\", Description: \"%s\" }", s.Status, s.Description)
	
	switch s.Status {
	case clamd.RES_OK:
		w.WriteHeader(http.StatusOK)
	case clamd.RES_FOUND:
		w.WriteHeader(http.StatusNotAcceptable)
	case clamd.RES_ERROR:
		w.WriteHeader(http.StatusBadRequest)
	case clamd.RES_PARSE_ERROR:
		w.WriteHeader(http.StatusPreconditionFailed)
	default:
		w.WriteHeader(http.StatusNotImplemented)
	}
	fmt.Fprint(w, respJson)
	fmt.Printf(time.Now().Format(time.RFC3339)+" Scan result for: %v, %v\n", filename, s)
}

// formatScanResponse returns the JSON string and HTTP status code without writing to a ResponseWriter (useful for webhooks)
func formatScanResponse(s *clamd.ScanResult) (string, int) {
	respJson := fmt.Sprintf("{ Status: \"%s\", Description: \"%s\" }", s.Status, s.Description)
	statusCode := http.StatusNotImplemented
	switch s.Status {
	case clamd.RES_OK:
		statusCode = http.StatusOK
	case clamd.RES_FOUND:
		statusCode = http.StatusNotAcceptable
	case clamd.RES_ERROR:
		statusCode = http.StatusBadRequest
	case clamd.RES_PARSE_ERROR:
		statusCode = http.StatusPreconditionFailed
	}
	return respJson, statusCode
}
