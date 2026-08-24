package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	ScanID  string `json:"scan_id"`
	Message string `json:"message"`
}

func sendWebhook(webhookURL string, s *clamd.ScanResult, scanID string, filename string) {
	if webhookURL == "" {
		return
	}
	payload, _ := formatScanResponse(s, scanID, filename)
	// We run this in a fire-and-forget goroutine to avoid blocking the clamd stream processing
	go func() {
		resp, err := http.Post(webhookURL, "application/json", bytes.NewBufferString(payload))
		if err != nil {
			fmt.Printf("[Webhook] Failed to send webhook to %s: %v\n", webhookURL, err)
			return
		}
		defer resp.Body.Close()
		fmt.Printf("[Webhook] Successfully sent result to %s (Status: %d)\n", webhookURL, resp.StatusCode)
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
		ScanID:  scanID,
		Message: "Scan started asynchronously",
	})

	// Process in background
	go func() {
		fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Started scanning URL: %s\n", scanID, req.URL)
		
		resp, err := http.Get(req.URL)
		if err != nil {
			fmt.Printf("[Async %s] Failed to fetch URL: %v\n", scanID, err)
			return
		}
		defer resp.Body.Close()

		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(resp.Body, abort)
		if err != nil {
			fmt.Printf("[Async %s] ScanStream error: %v\n", scanID, err)
			return
		}
		
		for s := range clamdResponse {
			fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Scan result: %v\n", scanID, s)
			sendWebhook(req.WebhookURL, s, scanID, req.URL)
		}
		fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Finished scanning URL: %s\n", scanID, req.URL)
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
		ScanID:  scanID,
		Message: "Scan started asynchronously",
	})

	go func(filename string, originalName string) {
		defer os.Remove(filename)
		
		f, err := os.Open(filename)
		if err != nil {
			fmt.Printf("[Async %s] Failed to open temp file: %v\n", scanID, err)
			return
		}
		defer f.Close()

		fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Started scanning: %s\n", scanID, originalName)
		
		c := clamd.NewClamd(opts["CLAMD_PORT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(f, abort)
		if err != nil {
			fmt.Printf("[Async %s] ScanStream error: %v\n", scanID, err)
			return
		}
		
		for s := range clamdResponse {
			fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Scan result for %s: %v\n", scanID, originalName, s)
			sendWebhook(webhookURL, s, scanID, originalName)
		}
		fmt.Printf(time.Now().Format(time.RFC3339)+" [Async %s] Finished scanning: %s\n", scanID, originalName)
	}(tempFile.Name(), header.Filename)
}
