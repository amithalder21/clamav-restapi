package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dutchcoders/go-clamd"
)

// writeJSONError writes a standard JSON error response
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// ScanResponse is the standard response payload for all scan endpoints
type ScanResponse struct {
	Status      string `json:"status"`
	Description string `json:"description"`
}

// writeScanResponse writes a standardized JSON response and status code
func writeScanResponse(w http.ResponseWriter, s *clamd.ScanResult, filename string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	
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
	
	json.NewEncoder(w).Encode(ScanResponse{
		Status:      s.Status,
		Description: s.Description,
	})
	fmt.Printf(time.Now().Format(time.RFC3339)+" Scan result for: %v, %v\n", filename, s)
}

// formatScanResponse returns the JSON string and HTTP status code without writing to a ResponseWriter (useful for webhooks)
func formatScanResponse(s *clamd.ScanResult) (string, int) {
	respBytes, _ := json.Marshal(ScanResponse{
		Status:      s.Status,
		Description: s.Description,
	})
	respJson := string(respBytes)
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
