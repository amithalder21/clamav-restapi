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
	"path/filepath"
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

type TenantConfig struct {
	WebhookURL string `json:"webhook_url"`
}

// scanProcessingStatus is the av-status sentinel written to Redis the moment
// a scan is accepted, before the background scan has run. It lets
// handleAsyncPolling tell "submitted but still running" (202) apart from
// "this scan_id was never submitted" (404) - previously both cases returned
// an identical 404, since nothing was written to Redis until the scan
// actually completed.
//
// The marker is a full ScanResponse (same shape/field names as the completed
// result, e.g. av-status/av-signature/av-timestamp) rather than a bespoke
// {"status":"processing"} object - a machine client that deserializes into
// one fixed schema would otherwise see a different field name (status vs
// av-status) depending on whether the scan had finished yet, silently
// breaking on the in-progress case.
const scanProcessingStatus = "PROCESSING"

func markScanProcessing(tenantID, scanID, filename string) {
	if redisClient == nil {
		return
	}
	payload, _ := json.Marshal(ScanResponse{
		ScanID:   scanID,
		Filename: filename,
		Status:   scanProcessingStatus,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Set(ctx, "tenant:"+tenantID+":scan:"+scanID, string(payload), 24*time.Hour).Err(); err != nil {
		slog.Error("Failed to mark scan as processing in Redis", slog.String("scan_id", scanID), slog.String("tenant_id", tenantID), slog.Any("error", err))
	}
}

func publishAsyncResult(webhookURL string, s *clamd.ScanResult, scanID string, filename string, tenantID string) {
	payload, _ := formatScanResponse(s, scanID, filename)
	
	// Fetch Tenant Config from Redis for dynamic Webhook URL if available
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		configVal, err := redisClient.Get(ctx, "tenant:"+tenantID+":config").Result()
		if err == nil && configVal != "" {
			var tc TenantConfig
			if json.Unmarshal([]byte(configVal), &tc) == nil && tc.WebhookURL != "" {
				webhookURL = tc.WebhookURL // Override with authoritative tenant config
			}
		}
	}

	// Cache the result in Redis with Tenant partitioning
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := redisClient.Set(ctx, "tenant:"+tenantID+":scan:"+scanID, payload, 24*time.Hour).Err()
		if err != nil {
			slog.Error("Failed to cache scan result in Redis", slog.String("scan_id", scanID), slog.String("tenant_id", tenantID), slog.Any("error", err))
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
		slog.Info("Successfully sent result to webhook", slog.String("webhook_url", webhookURL), slog.String("tenant_id", tenantID), slog.Int("status_code", resp.StatusCode))
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
	if req.URL == "" {
		writeJSONError(w, "URL is required", http.StatusBadRequest)
		return
	}
	
	if req.WebhookURL == "" {
		req.WebhookURL = opts["APP_WEBHOOK_URL"]
	}

	tenantID, ok := r.Context().Value(TenantContextKey).(string)
	if !ok || tenantID == "" {
		tenantID = "default"
	}
	requestID := requestIDFromContext(r.Context())

	scanID := uuid.New().String()
	markScanProcessing(tenantID, scanID, req.URL)

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
		slog.Info("Started scanning URL", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("url", req.URL))
		start := time.Now()

		resp, err := SafeHTTPClient().Get(req.URL)
		if err != nil {
			slog.Error("Failed to fetch URL", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("url", req.URL), slog.Any("error", err))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("Failed to fetch URL: %v", err)}, scanID, req.URL, tenantID)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			slog.Error("URL returned non-200 status", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("url", req.URL), slog.Int("status_code", resp.StatusCode))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("URL returned non-200 status: %d", resp.StatusCode)}, scanID, req.URL, tenantID)
			return
		}

		maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
		if maxFileSizeBytes == 0 {
			maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
		}
		limitedBody := http.MaxBytesReader(nil, resp.Body, maxFileSizeBytes+1024*1024)

		// Stage to disk so YARA/Maldet (which need a file path, not a stream) also
		// run on this endpoint - previously this handler only ever ran ClamAV,
		// silently skipping YARA/Maldet coverage for async URL scans.
		tempFile, err := os.CreateTemp(opts["ASYNC_TEMP_DIR"], "async-url-*")
		if err != nil {
			slog.Error("Failed to create temp file for URL scan", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: "Internal server error"}, scanID, req.URL, tenantID)
			return
		}
		tempFilePath := tempFile.Name()
		defer os.Remove(tempFilePath)

		downloadStart := time.Now()
		_, err = io.Copy(tempFile, limitedBody)
		downloadDuration := time.Since(downloadStart)
		if err != nil {
			tempFile.Close()
			slog.Error("Failed to save URL stream to temp file", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("Failed to read URL stream: %v", err)}, scanID, req.URL, tenantID)
			return
		}

		if IsEncryptedZip(tempFilePath) {
			tempFile.Close()
			slog.Warn("Rejected encrypted archive", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("url", req.URL))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_FOUND, Description: encryptedArchiveSignature}, scanID, req.URL, tenantID)
			return
		}

		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
		aggregatedResult, err := RunMultiEngineScan(tempFile, tempFilePath, req.URL, c, requestID)
		tempFile.Close()
		if err != nil {
			slog.Error("RunMultiEngineScan error", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(req.WebhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}, scanID, req.URL, tenantID)
			return
		}

		slog.Info("Finished scanning URL",
			slog.String("request_id", requestID),
			slog.String("scan_id", scanID),
			slog.String("tenant_id", tenantID),
			slog.String("url", req.URL),
			slog.String("result", formatStatus(aggregatedResult.Status)),
			slog.String("description", aggregatedResult.Description),
			slog.Int64("download_ms", downloadDuration.Milliseconds()),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
		publishAsyncResult(req.WebhookURL, aggregatedResult, scanID, req.URL, tenantID)
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
	if webhookURL == "" {
		webhookURL = opts["APP_WEBHOOK_URL"]
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeJSONError(w, "Missing 'file' field", http.StatusBadRequest)
		return
	}
	
	tenantID, ok := r.Context().Value(TenantContextKey).(string)
	if !ok || tenantID == "" {
		tenantID = "default"
	}
	requestID := requestIDFromContext(r.Context())

	// Create a temp file to hold the upload so we can return HTTP 202 immediately and free the connection
	tempFile, err := os.CreateTemp(opts["ASYNC_TEMP_DIR"], "clamav-async-upload-*")
	if err != nil {
		slog.Error("Failed to create temp file", slog.String("request_id", requestID), slog.Any("error", err))
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	uploadStart := time.Now()
	_, err = io.Copy(tempFile, file)
	uploadDuration := time.Since(uploadStart)
	file.Close()
	if err != nil {
		os.Remove(tempFile.Name())
		slog.Error("Failed to copy to temp file", slog.String("request_id", requestID), slog.Any("error", err))
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	tempFile.Close() // close it for now, we will open it in the goroutine

	if IsEncryptedZip(tempFile.Name()) {
		os.Remove(tempFile.Name())
		slog.Warn("Rejected encrypted archive", slog.String("request_id", requestID), slog.String("filename", header.Filename))
		writeJSONError(w, encryptedArchiveMessage, http.StatusUnsupportedMediaType)
		return
	}

	scanID := uuid.New().String()
	markScanProcessing(tenantID, scanID, header.Filename)

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
			slog.Error("Failed to open temp file", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: "Failed to read uploaded file"}, scanID, originalName, tenantID)
			return
		}
		defer f.Close()

		slog.Info("Started scanning", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("filename", originalName))
		start := time.Now()

		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])

		aggregatedResult, err := RunMultiEngineScan(f, filename, originalName, c, requestID)
		if err != nil {
			slog.Error("RunMultiEngineScan error", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.Any("error", err))
			publishAsyncResult(webhookURL, &clamd.ScanResult{Status: clamd.RES_ERROR, Description: "Scan engine error"}, scanID, originalName, tenantID)
			return
		}

		slog.Info("Finished scanning",
			slog.String("request_id", requestID),
			slog.String("scan_id", scanID),
			slog.String("tenant_id", tenantID),
			slog.String("filename", originalName),
			slog.String("result", formatStatus(aggregatedResult.Status)),
			slog.String("description", aggregatedResult.Description),
			slog.Int64("upload_ms", uploadDuration.Milliseconds()),
			slog.Int64("duration_ms", time.Since(start).Milliseconds()),
		)
		publishAsyncResult(webhookURL, aggregatedResult, scanID, originalName, tenantID)

		if aggregatedResult.Status == clamd.RES_FOUND {
				quarantineBucket := opts["AWS_S3_QUARANTINE_BUCKET"]
				if quarantineBucket != "" {
					cfg, err := config.LoadDefaultConfig(context.TODO())
					if err != nil {
						slog.Error("Failed to load AWS config for quarantine", slog.String("request_id", requestID), slog.Any("error", err))
					} else {
						s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
							if os.Getenv("AWS_ENDPOINT_URL") != "" {
								o.UsePathStyle = true
							}
						})
						f.Seek(0, 0)
						// Partition Quarantine by Tenant ID and Date
						dateStr := time.Now().Format("2006/01/02")
						// originalName is the caller-supplied multipart filename - sanitize
						// with filepath.Base so a crafted name (e.g. containing "../") can't
						// escape the tenant/date-scoped key prefix used for isolation.
						safeName := filepath.Base(originalName)
						key := tenantID + "/" + dateStr + "/" + scanID + "-" + safeName
						_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
							Bucket: aws.String(quarantineBucket),
							Key:    aws.String(key),
							Body:   f,
						})
						if err != nil {
							slog.Error("Failed to upload to quarantine bucket", slog.String("request_id", requestID), slog.String("bucket", quarantineBucket), slog.String("key", key), slog.String("tenant_id", tenantID), slog.Any("error", err))
						} else {
							slog.Info("Successfully uploaded infected file to quarantine bucket", slog.String("request_id", requestID), slog.String("bucket", quarantineBucket), slog.String("key", key), slog.String("tenant_id", tenantID))
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
	
	tenantID, ok := r.Context().Value(TenantContextKey).(string)
	if !ok || tenantID == "" {
		tenantID = "default"
	}

	requestID := requestIDFromContext(r.Context())
	val, err := redisClient.Get(r.Context(), "tenant:"+tenantID+":scan:"+scanID).Result()
	if err == redis.Nil {
		writeJSONError(w, "Scan not found", http.StatusNotFound)
		return
	} else if err != nil {
		slog.Error("Failed to get scan result from Redis", slog.String("request_id", requestID), slog.String("scan_id", scanID), slog.String("tenant_id", tenantID), slog.Any("error", err))
		writeJSONError(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	var parsed ScanResponse
	isProcessing := json.Unmarshal([]byte(val), &parsed) == nil && parsed.Status == scanProcessingStatus
	if isProcessing {
		// Submitted and known, but the background scan hasn't finished yet -
		// distinct from 404 (scan_id never existed) so callers can safely
		// poll-and-retry instead of treating this as a bad/expired scan_id.
		w.WriteHeader(http.StatusAccepted)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	w.Write([]byte(val))
}
