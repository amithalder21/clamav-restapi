package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/google/uuid"
)

type AsyncURLScanRequest struct {
	URL        string `json:"url"`
	WebhookURL string `json:"webhook_url"`
}

type AsyncResponse struct {
	ScanID   string `json:"scan_id"`
	Message  string `json:"message"`
	Filename string `json:"filename,omitempty"`
}

func sendWebhook(webhookURL string, s *clamd.ScanResult, scanID string, filename string) {
	if webhookURL == "" {
		return
	}
	payload, _ := formatScanResponse(s, scanID, filename)
	// We run this in a fire-and-forget goroutine to avoid blocking the clamd stream processing
	go func() {
		resp, err := SafeHTTPClient().Post(webhookURL, "application/json", bytes.NewBufferString(payload))
		if err != nil {
			slog.Error("Failed to send webhook", slog.String("scan_id", scanID), slog.String("webhook_url", webhookURL), slog.Any("error", err))
			return
		}
		defer resp.Body.Close()
		slog.Info("Successfully sent result to webhook", slog.String("webhook_url", webhookURL), slog.Int("status_code", resp.StatusCode))
	}()
}

func scanURLAsyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AsyncURLScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}
	if req.URL == "" || req.WebhookURL == "" {
		writeJSONError(w, "URL and webhook_url are required", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()

	// Send immediate response
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(AsyncResponse{
		ScanID:   scanID,
		Message:  "Scan started asynchronously",
		Filename: req.URL,
	})

	// Process in background
	go func() {
		slog.Info("Started scanning URL", slog.String("scan_id", scanID), slog.String("url", req.URL))
		start := time.Now()
		
		resp, err := SafeHTTPClient().Get(req.URL)
		if err != nil {
			slog.Error("Failed to fetch URL", slog.String("scan_id", scanID), slog.String("url", req.URL), slog.Any("error", err))
			sendWebhook(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("Failed to fetch URL: %v", err)}, scanID, req.URL)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			slog.Error("URL returned non-200 status", slog.String("scan_id", scanID), slog.String("url", req.URL), slog.Int("status_code", resp.StatusCode))
			sendWebhook(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("URL returned non-200 status: %d", resp.StatusCode)}, scanID, req.URL)
			return
		}

		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(resp.Body, abort)
		if err != nil {
			slog.Error("ScanStream error", slog.String("scan_id", scanID), slog.Any("error", err))
			sendWebhook(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}, scanID, req.URL)
			return
		}
		
		for s := range clamdResponse {
			slog.Info("Finished scanning URL", 
				slog.String("scan_id", scanID), 
				slog.String("url", req.URL), 
				slog.String("result", formatStatus(s.Status)), 
				slog.String("description", s.Description),
				slog.Duration("duration_ms", time.Since(start)),
			)
			sendWebhook(req.WebhookURL, s, scanID, req.URL)
		}
	}()
}

func scanAsyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	err := r.ParseMultipartForm(32 << 20) // 32MB max in-memory
	if err != nil {
		writeJSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	webhookURL := r.FormValue("webhook_url")
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, "Missing 'file' field", http.StatusBadRequest)
		return
	}
	
	// Create a temp file to hold the upload so we can return HTTP 202 immediately and free the connection
	tempFile, err := os.CreateTemp("", "clamav-async-upload-*")
	if err != nil {
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	_, err = io.Copy(tempFile, file)
	file.Close()
	if err != nil {
		os.Remove(tempFile.Name())
		writeJSONError(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	tempFile.Close() // close it for now, we will open it in the goroutine
	
	scanID := uuid.New().String()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(AsyncResponse{
		ScanID:   scanID,
		Message:  "Scan started asynchronously",
		Filename: header.Filename,
	})

	go func(filename string, originalName string) {
		defer os.Remove(filename)
		
		f, err := os.Open(filename)
		if err != nil {
			slog.Error("Failed to open temp file", slog.String("scan_id", scanID), slog.Any("error", err))
			sendWebhook(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: "Failed to read uploaded file"}, scanID, originalName)
			return
		}
		defer f.Close()

		slog.Info("Started scanning", slog.String("scan_id", scanID), slog.String("filename", originalName))
		start := time.Now()
		
		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(f, abort)
		if err != nil {
			slog.Error("ScanStream error", slog.String("scan_id", scanID), slog.Any("error", err))
			sendWebhook(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}, scanID, originalName)
			return
		}
		
		for s := range clamdResponse {
			slog.Info("Finished scanning", 
				slog.String("scan_id", scanID), 
				slog.String("filename", originalName), 
				slog.String("result", formatStatus(s.Status)), 
				slog.String("description", s.Description),
				slog.Duration("duration_ms", time.Since(start)),
			)
			sendWebhook(webhookURL, s, scanID, originalName)
		}
	}(tempFile.Name(), header.Filename)
}
