package main

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dutchcoders/go-clamd"
	"github.com/redis/go-redis/v9"
)

var opts map[string]string
var redisClient *redis.Client

func init() {
	log.SetOutput(io.Discard)
}

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSONError(w, "Not Found", http.StatusNotFound)
		return
	}

	c := clamd.NewClamd(opts["CLAMD_PORT"])

	// Ping clamd to ensure it is responsive
	err := c.Ping()
	if err != nil {
		writeJSONError(w, "ClamAV daemon is unreachable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK", "message": "ClamAV REST API is ready and ClamAV daemon is responsive"}`))
}

func scanPathHandler(w http.ResponseWriter, r *http.Request) {
	paths, ok := r.URL.Query()["path"]
	if !ok || len(paths[0]) < 1 {
		writeJSONError(w, "Url Param 'path' is missing", http.StatusBadRequest)
		return
	}

	requestedPath := paths[0]

	baseDir := opts["SCAN_BASE_DIR"]
	if baseDir == "" {
		baseDir = "/tmp" // Secure default
	}

	cleanBase := filepath.Clean(baseDir)
	targetPath := filepath.Clean(requestedPath)

	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(cleanBase, targetPath)
	}

	if !strings.HasPrefix(targetPath, cleanBase+string(filepath.Separator)) && targetPath != cleanBase {
		slog.Warn("Path traversal attempt blocked", slog.String("path", requestedPath))
		writeJSONError(w, "Access denied: path is outside allowed directory", http.StatusForbidden)
		return
	}

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	response, err := c.AllMatchScanFile(targetPath)

	if err != nil {
		slog.Error("ClamAV scan failed", slog.Any("error", err))
		writeJSONError(w, "Scan engine error", http.StatusInternalServerError)
		return
	}

	for responseItem := range response {
		writeScanResponse(w, responseItem, requestedPath)
		return // Return immediately after the first result to guarantee valid JSON
	}
}

//This is where the action happens.
func scanHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	//POST takes the uploaded file(s) and saves it to disk.
	case "POST":
		maxFileSizeBytes := parseSize(opts["MAX_FILE_SIZE"])
		if maxFileSizeBytes == 0 {
			maxFileSizeBytes = 100 * 1024 * 1024 // default 100M
		}
		// Bound the stream length to the MAX_FILE_SIZE + 1MB overhead
		r.Body = http.MaxBytesReader(w, r.Body, maxFileSizeBytes + 1024*1024)

		c := clamd.NewClamd(opts["CLAMD_PORT"])
		//get the multipart reader for the request.
		reader, err := r.MultipartReader()

		if err != nil {
			if checkMaxBytesError(w, err) {
				return
			}
			slog.Error("Failed to parse multipart form", slog.Any("error", err))
			writeJSONError(w, "Failed to process file upload", http.StatusInternalServerError)
			return
		}

		//copy each part to destination.
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}

			//if part.FileName() is empty, skip this iteration.
			if part.FileName() == "" {
				continue
			}

			start := time.Now()
			slog.Info("Started scanning file", slog.String("filename", part.FileName()))
			interceptReader := &ErrorInterceptingReader{Reader: part}
			var abort chan bool
			response, err := c.ScanStream(interceptReader, abort)
			if err != nil {
				slog.Error("ScanStream error", slog.Any("error", err))
				writeJSONError(w, "Scan engine error", http.StatusInternalServerError)
				return
			}
			
			for s := range response {
				if interceptReader.Err != nil {
					if checkMaxBytesError(w, interceptReader.Err) {
						return
					}
				}
				if s.Status == clamd.RES_PARSE_ERROR {
					// Fallback check if ClamAV's own limit was hit but MaxBytesReader didn't trip (e.g. decompression limit)
					writeJSONError(w, "Payload Too Large or Parse Error", http.StatusRequestEntityTooLarge)
					return
				}
				slog.Info("Finished scanning file", 
					slog.String("filename", part.FileName()),
					slog.String("result", formatStatus(s.Status)),
					slog.String("description", s.Description),
					slog.Duration("duration_ms", time.Since(start)),
				)
				writeScanResponse(w, s, part.FileName())
				break
			}
			return // Process only the first uploaded file to prevent invalid JSON streaming
		}
	default:
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func waitForClamD(port string, times int) {
	clamdTest := clamd.NewClamd(port)
	clamdTest.Ping()
	version, err := clamdTest.Version()

	if err != nil {
		if times < 30 {
			slog.Info("clamD not running, waiting", slog.Int("attempt", times))
			time.Sleep(time.Second * 4)
			waitForClamD(port, times+1)
		} else {
			slog.Error("Error getting clamd version", slog.Any("error", err))
			os.Exit(1)
		}
	} else {
		for version_string := range version {
			slog.Info("Clamd version", slog.String("version", version_string.Raw))
		}
	}
}

func main() {
	// Configure slog for JSON output to os.Stdout
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	const (
		PORT     = ":9000"
		SSL_PORT = ":9443"
	)

	opts = make(map[string]string)

	for _, e := range os.Environ() {
		pair := strings.Split(e, "=")
		opts[pair[0]] = pair[1]
	}

	if opts["CLAMD_PORT"] == "" {
		opts["CLAMD_PORT"] = "tcp://localhost:3310"
	}

	slog.Info("Starting clamav-restapi", slog.String("port", PORT), slog.String("clamd_port", opts["CLAMD_PORT"]))

	if redisURL := opts["REDIS_URL"]; redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Error("Failed to parse REDIS_URL", slog.Any("error", err))
		} else {
			redisClient = redis.NewClient(opt)
			slog.Info("Redis/Dragonfly caching enabled", slog.String("redis_url", redisURL))
		}
	}

	if sqsQueueURL, ok := opts["SQS_QUEUE_URL"]; ok && sqsQueueURL != "" {
		go startSQSConsumer(sqsQueueURL)
	}
	
	waitForClamD(opts["CLAMD_PORT"], 1)

	slog.Info("Connected to clamd", slog.String("port", opts["CLAMD_PORT"]))

	http.HandleFunc("/api/v1/scan/file", AuthMiddleware(scanHandler))
	http.HandleFunc("/api/v1/scan/local-path", AuthMiddleware(scanPathHandler))
	http.HandleFunc("/api/v1/scan/url", AuthMiddleware(scanURLHandler))
	http.HandleFunc("/api/v1/async-scan/file", AuthMiddleware(scanAsyncHandler))
	http.HandleFunc("/api/v1/async-scan/url", AuthMiddleware(scanURLAsyncHandler))
	http.HandleFunc("/api/v1/events/s3", AuthMiddleware(scanS3EventHandler))
	
	// Admin Endpoints
	http.HandleFunc("/api/v1/admin/status", AdminAuthMiddleware(adminStatusHandler))
	http.HandleFunc("/api/v1/admin/reload", AdminAuthMiddleware(adminReloadHandler))
	http.HandleFunc("/api/v1/admin/update-signatures", AdminAuthMiddleware(adminUpdateSignaturesHandler))
	
	http.HandleFunc("/api/v1/health", home)
	http.HandleFunc("/", home)

	// Start the HTTPS server in a goroutine
	go http.ListenAndServeTLS(SSL_PORT, "/etc/ssl/clamav-rest/server.crt", "/etc/ssl/clamav-rest/server.key", nil)

	// Start the HTTP server
	http.ListenAndServe(PORT, nil)
}
