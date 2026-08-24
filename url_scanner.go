package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		writeJSONError(w, "URL is required", http.StatusBadRequest)
		return
	}

	slog.Info("Started downloading and scanning URL", slog.String("url", req.URL))
	start := time.Now()

	resp, err := http.Get(req.URL)
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

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	var abort chan bool
	clamdResponse, err := c.ScanStream(resp.Body, abort)
	
	if err != nil {
		slog.Error("ScanStream error", slog.String("url", req.URL), slog.Any("error", err))
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for s := range clamdResponse {
		slog.Info("Finished scanning URL", 
			slog.String("url", req.URL), 
			slog.String("result", formatStatus(s.Status)), 
			slog.String("description", s.Description),
			slog.Duration("duration_ms", time.Since(start)),
		)
		writeScanResponse(w, s, req.URL)
		break
	}
}
