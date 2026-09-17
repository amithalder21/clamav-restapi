package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/google/uuid"
)

type contextKey string

const TenantContextKey contextKey = "tenant_id"
const RequestIDContextKey contextKey = "request_id"

// requestIDFromContext returns the per-request trace ID set by
// RequestLoggingMiddleware, or "" if called outside that middleware (e.g.
// the background SQS poller, which has no originating HTTP request).
func requestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDContextKey).(string); ok {
		return v
	}
	return ""
}

// statusRecorder wraps http.ResponseWriter to capture the status code actually
// written, so RequestLoggingMiddleware can log it after the handler returns.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// RequestLoggingMiddleware is the outermost wrapper on every route: it assigns
// a request_id threaded through every downstream log line (auth, upload,
// per-engine scan timing, result) via context, and logs a start/end pair with
// the method, path, final status code, and total wall time. This is what lets
// every phase of a single request be correlated and diagnosed from logs alone
// instead of guessing from timestamps, which is how the auth-latency and
// upload-time investigations in this codebase's history had to be done.
func RequestLoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.New().String()
		start := time.Now()
		ctx := context.WithValue(r.Context(), RequestIDContextKey, requestID)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// Surface the request_id to the caller too, not just server-side logs -
		// otherwise tracing is one-directional: if a client hits an error, they
		// have no way to tell you which request was theirs. Must be set before
		// any handler writes the status/body (headers are frozen after
		// WriteHeader), so this happens before next() runs.
		rec.Header().Set("X-Request-Id", requestID)

		slog.Info("Request received",
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
		)

		next(rec, r.WithContext(ctx))

		slog.Info("Request completed",
			slog.String("request_id", requestID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status_code", rec.status),
			slog.Int64("total_ms", time.Since(start).Milliseconds()),
		)
	}
}

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
	// S3Path is the full s3://bucket/key URI. Always populated for the
	// S3/SQS-triggered scan flow (the file already has a real S3 location).
	// For direct upload/URL scans (sync and async), populated only if the
	// relevant bucket (AWS_S3_CLEAN_BUCKET/AWS_S3_QUARANTINE_BUCKET) is
	// configured - otherwise nothing is uploaded and this stays empty.
	S3Path string `json:"s3_path,omitempty"`
	// FileContent is the base64-encoded file body. Opt-in only (callers pass
	// ?include_file=true) - embedding every scanned file's bytes in every
	// response by default would inflate every payload by ~33% (base64
	// overhead) for callers who never asked for it, and could be significant
	// for anything near the configured MAX_FILE_SIZE ceiling.
	FileContent string `json:"file_content,omitempty"`
	// DownloadURL is a presigned, time-limited S3 URL for the scanned file
	// (CLEAN -> AWS_S3_CLEAN_BUCKET, INFECTED -> AWS_S3_QUARANTINE_BUCKET).
	// Empty if the relevant bucket isn't configured, or the upload/presign
	// step failed - a storage problem never blocks the verdict itself.
	DownloadURL string `json:"download_url,omitempty"`
}

// wantsFileContent reports whether the caller opted into having the scanned
// file's bytes embedded in the response (?include_file=true). Off by default.
func wantsFileContent(r *http.Request) bool {
	return r.URL.Query().Get("include_file") == "true"
}

// readFileBase64 reads filePath and returns its contents base64-encoded, or
// "" (with a logged error) if the file can't be read - a failure here should
// never block returning the scan verdict itself.
func readFileBase64(filePath string, requestID string) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("Failed to read file for include_file response", slog.String("request_id", requestID), slog.String("file", filePath), slog.Any("error", err))
		return ""
	}
	return base64.StdEncoding.EncodeToString(data)
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

// ExtraFields bundles the optional ScanResponse fields (S3Path, FileContent,
// DownloadURL) so writeScanResponse/formatScanResponse don't keep growing
// positional string parameters as more optional fields get added. Zero value
// (all fields "") omits all three.
type ExtraFields struct {
	S3Path      string
	FileContent string
	DownloadURL string
}

// writeScanResponse writes a standardized JSON response and status code.
func writeScanResponse(w http.ResponseWriter, s *clamd.ScanResult, filename string, extra ExtraFields) {
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
		S3Path:      extra.S3Path,
		FileContent: extra.FileContent,
		DownloadURL: extra.DownloadURL,
	})

	slog.Info("Scan result",
		slog.String("filename", filename),
		slog.String("result", normalizedStatus),
		slog.String("description", signature),
	)
}

// formatScanResponse returns the JSON string and HTTP status code without
// writing to a ResponseWriter (useful for webhooks).
func formatScanResponse(s *clamd.ScanResult, scanID string, filename string, extra ExtraFields) (string, int) {
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
		S3Path:      extra.S3Path,
		FileContent: extra.FileContent,
		DownloadURL: extra.DownloadURL,
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

type ErrorInterceptingReader struct {
	io.Reader
	Err error
}

func (r *ErrorInterceptingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		r.Err = err
	}
	return n, err
}

// isPrivateIP checks if an IP belongs to private, loopback, link-local or unspecified ranges
func isPrivateIP(ip net.IP) bool {
	if os.Getenv("APP_ALLOW_PRIVATE_IPS") == "true" {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() || ip.IsUnspecified()
}

// SafeHTTPClient returns an http.Client that prevents Server-Side Request Forgery (SSRF)
// by refusing to connect to any internal/private IP addresses.
func SafeHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}

			if len(ips) == 0 {
				return nil, errors.New("no IP addresses found for host")
			}

			// Pre-flight check to strictly block SSRF payload targets
			for _, ip := range ips {
				if isPrivateIP(ip) {
					return nil, fmt.Errorf("SSRF blocked: attempt to connect to private/internal IP: %s", ip.String())
				}
			}

			// Connect securely to the validated IP to prevent DNS rebinding
			for _, ip := range ips {
				if !isPrivateIP(ip) {
					safeAddr := net.JoinHostPort(ip.String(), port)
					return dialer.DialContext(ctx, network, safeAddr)
				}
			}
			return nil, errors.New("no public IP addresses found")
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   5 * time.Minute, // Max 5 minutes for downloading large files
	}
}

// parseSize parses size strings like "25M", "1G" into bytes.
func parseSize(sizeStr string) int64 {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))
	if sizeStr == "" {
		return 0
	}
	
	multiplier := int64(1)
	if strings.HasSuffix(sizeStr, "G") || strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "GB")
		sizeStr = strings.TrimSuffix(sizeStr, "G")
	} else if strings.HasSuffix(sizeStr, "M") || strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "MB")
		sizeStr = strings.TrimSuffix(sizeStr, "M")
	} else if strings.HasSuffix(sizeStr, "K") || strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		sizeStr = strings.TrimSuffix(sizeStr, "KB")
		sizeStr = strings.TrimSuffix(sizeStr, "K")
	}
	
	var val int64
	fmt.Sscanf(sizeStr, "%d", &val)
	return val * multiplier
}

// checkMaxBytesError checks if the error is an http.MaxBytesError and returns 413.
// Returns true if the error was handled.
func checkMaxBytesError(w http.ResponseWriter, err error) bool {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeJSONError(w, "Payload Too Large", http.StatusRequestEntityTooLarge)
		return true
	}
	return false
}
