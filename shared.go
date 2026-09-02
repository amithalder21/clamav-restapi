package main

import (
	"context"
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
)

type contextKey string

const TenantContextKey contextKey = "tenant_id"

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
