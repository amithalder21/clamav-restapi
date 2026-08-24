package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/dutchcoders/go-clamd"
)

type URLScanRequest struct {
	URL string `json:"url"`
}

func scanURLHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req URLScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	fmt.Printf(time.Now().Format(time.RFC3339)+" Started downloading and scanning URL: %s\n", req.URL)

	resp, err := http.Get(req.URL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch URL: %v", err), http.StatusBadRequest)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("URL returned non-200 status: %d", resp.StatusCode), http.StatusBadRequest)
		return
	}

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	var abort chan bool
	clamdResponse, err := c.ScanStream(resp.Body, abort)
	
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for s := range clamdResponse {
		writeScanResponse(w, s, req.URL)
	}
	
	fmt.Printf(time.Now().Format(time.RFC3339)+" Finished scanning URL: %s\n", req.URL)
}
