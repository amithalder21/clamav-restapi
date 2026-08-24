package main

import (
	"encoding/json"
	"log/slog"
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
	Filename    string `json:"filename,omitempty"`
	ScanID      string `json:"scan_id,omitempty"`
	Status      string `json:"av-status"`
	Description string `json:"av-signature"`
	Timestamp   string `json:"av-timestamp"`
}

// formatStatus normalizes the raw ClamAV status into a consistent API status
func formatStatus(status string) string {
	switch status {
	case clamd.RES_OK:
		return "CLEAN"
	case clamd.RES_FOUND:
		return "INFECTED"
	default:
		return status
	}
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
	
	normalizedStatus := formatStatus(s.Status)
	signature := s.Description
	if signature == "" {
		signature = "CLEAN"
	}
	
	json.NewEncoder(w).Encode(ScanResponse{
		Filename:    filename,
		Status:      normalizedStatus,
		Description: signature,
		Timestamp:   time.Now().UTC().Format("2006/01/02 15:04:05 UTC"),
	})
	
	slog.Info("Scan result",
		slog.String("filename", filename),
		slog.String("result", normalizedStatus),
		slog.String("description", signature),
	)
}

// formatScanResponse returns the JSON string and HTTP status code without writing to a ResponseWriter (useful for webhooks)
func formatScanResponse(s *clamd.ScanResult, scanID string, filename string) (string, int) {
	normalizedStatus := formatStatus(s.Status)
	signature := s.Description
	if signature == "" {
		signature = "CLEAN"
	}
	respBytes, _ := json.Marshal(ScanResponse{
		Filename:    filename,
		ScanID:      scanID,
		Status:      normalizedStatus,
		Description: signature,
		Timestamp:   time.Now().UTC().Format("2006/01/02 15:04:05 UTC"),
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
