package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/dutchcoders/go-clamd"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
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

func publishAsyncResult(webhookURL string, s *clamd.ScanResult, scanID string, filename string) {
	payload, _ := formatScanResponse(s, scanID, filename)
	
	// Cache the result in Redis if configured
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := redisClient.Set(ctx, scanID, payload, 24*time.Hour).Err()
		if err != nil {
			slog.Error("Failed to cache scan result in Redis", slog.String("scan_id", scanID), slog.Any("error", err))
		}
	}

	if webhookURL == "" {
		return
	}

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
	if r.Method == "GET" {
		handleAsyncPolling(w, r)
		return
	}
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AsyncURLScanRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB limit for JSON
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if checkMaxBytesError(w, err) {
			return
		}
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
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("Failed to fetch URL: %v", err)}, scanID, req.URL)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			slog.Error("URL returned non-200 status", slog.String("scan_id", scanID), slog.String("url", req.URL), slog.Int("status_code", resp.StatusCode))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("URL returned non-200 status: %d", resp.StatusCode)}, scanID, req.URL)
			return
		}

		maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
		if maxFileSizeBytes == 0 {
			maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
		}
		limitedBody := http.MaxBytesReader(nil, resp.Body, maxFileSizeBytes+1024*1024)

		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(limitedBody, abort)
		if err != nil {
			slog.Error("ScanStream error", slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}, scanID, req.URL)
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
			publishAsyncResult(req.WebhookURL, s, scanID, req.URL)
		}
	}()
}

func scanAsyncHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		handleAsyncPolling(w, r)
		return
	}
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
	if maxFileSizeBytes == 0 {
		maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
	}
	// Add 1MB overhead for multipart boundaries
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSizeBytes + 1024*1024)

	err := r.ParseMultipartForm(32 << 20) // 32MB max in-memory
	if err != nil {
		if checkMaxBytesError(w, err) {
			return
		}
		slog.Error("Failed to parse multipart form", slog.Any("error", err))
		writeJSONError(w, "Failed to process file upload", http.StatusBadRequest)
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
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
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
			publishAsyncResult(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: "Failed to read uploaded file"}, scanID, originalName)
			return
		}
		defer f.Close()

		slog.Info("Started scanning", slog.String("scan_id", scanID), slog.String("filename", originalName))
		start := time.Now()
		
		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
		var abort chan bool
		clamdResponse, err := c.ScanStream(f, abort)
		if err != nil {
			slog.Error("ScanStream error", slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}, scanID, originalName)
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
			publishAsyncResult(webhookURL, s, scanID, originalName)
			
			if s.Status == clamd.RES_FOUND {
				quarantineBucket := opts["AWS_S3_QUARANTINE_BUCKET"]
				if quarantineBucket != "" {
					cfg, err := config.LoadDefaultConfig(context.TODO())
					if err != nil {
						slog.Error("Failed to load AWS config for quarantine", slog.Any("error", err))
					} else {
						s3Client := s3.NewFromConfig(cfg)
						f.Seek(0, 0)
						key := scanID + "-" + originalName
						_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
							Bucket: aws.String(quarantineBucket),
							Key:    aws.String(key),
							Body:   f,
						})
						if err != nil {
							slog.Error("Failed to upload to quarantine bucket", slog.String("bucket", quarantineBucket), slog.String("key", key), slog.Any("error", err))
						} else {
							slog.Info("Successfully uploaded infected file to quarantine bucket", slog.String("bucket", quarantineBucket), slog.String("key", key))
						}
					}
				}
			}
		}
	}(tempFile.Name(), header.Filename)
}

func handleAsyncPolling(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		writeJSONError(w, "scan_id query parameter is required for polling", http.StatusBadRequest)
		return
	}
	if redisClient == nil {
		writeJSONError(w, "Polling is disabled because REDIS_URL is not configured", http.StatusNotImplemented)
		return
	}
	
	val, err := redisClient.Get(r.Context(), scanID).Result()
	if err == redis.Nil {
		writeJSONError(w, "Scan not found or still processing", http.StatusNotFound)
		return
	} else if err != nil {
		slog.Error("Failed to get scan result from Redis", slog.String("scan_id", scanID), slog.Any("error", err))
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(val))
}
