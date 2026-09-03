package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/dutchcoders/go-clamd"
)

type URLScanRequest struct {
	URL string `json:"url"`
}

func scanURLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req URLScanRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit for JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if checkMaxBytesError(w, err) {
			return
		}
		writeJSONError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		writeJSONError(w, "URL is required", http.StatusBadRequest)
		return
	}

	slog.Info("Started downloading and scanning URL", slog.String("url", req.URL))
	start := time.Now()

	resp, err := SafeHTTPClient().Get(req.URL)
	if err != nil {
		slog.Error("Failed to fetch URL", slog.String("url", req.URL), slog.Any("error", err))
		writeJSONError(w, fmt.Sprintf("Failed to fetch URL: %v", err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Error("URL returned non-200 status", slog.String("url", req.URL), slog.Int("status_code", resp.StatusCode))
		writeJSONError(w, fmt.Sprintf("URL returned non-200 status: %d", resp.StatusCode), http.StatusBadRequest)
		return
	}

	maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
	if maxFileSizeBytes == 0 {
		maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
	}
	limitedBody := http.MaxBytesReader(nil, resp.Body, maxFileSizeBytes+1024*1024)

	c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
	
	tempFile, err := os.CreateTemp(opts["ASYNC_TEMP_DIR"], "sync-url-*")
	if err != nil {
		slog.Error("Failed to create temp file for URL scan", slog.Any("error", err))
		writeJSONError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tempFilePath := tempFile.Name()
	defer os.Remove(tempFilePath)
	
	_, err = io.Copy(tempFile, limitedBody)
	if err != nil {
		slog.Error("Failed to save URL stream to temp file", slog.Any("error", err))
		writeJSONError(w, "Failed to read URL stream", http.StatusInternalServerError)
		tempFile.Close()
		return
	}

	aggregatedResult, err := RunMultiEngineScan(tempFile, tempFilePath, c)
	tempFile.Close()

	if err != nil {
		slog.Error("RunMultiEngineScan error", slog.String("url", req.URL), slog.Any("error", err))
		writeJSONError(w, "Scan engine error", http.StatusInternalServerError)
		return
	}

	s := aggregatedResult

	slog.Info("Finished scanning URL", 
		slog.String("url", req.URL), 
		slog.String("result", formatStatus(s.Status)), 
		slog.String("description", s.Description),
		slog.Duration("duration_ms", time.Since(start)),
	)
	writeScanResponse(w, s, req.URL)
}
