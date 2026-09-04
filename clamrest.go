package main

import (
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
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
	// "/" is registered as Go's classic ServeMux catch-all pattern (it matches
	// any path with no more specific registered handler), so without this
	// check every unmatched path would silently reach here instead of 404ing.
	// "/api/v1/health" is also intentionally registered to this handler and
	// must be allowed through, or the documented health check endpoint is
	// unreachable via the app's own routing.
	if r.URL.Path != "/" && r.URL.Path != "/api/v1/health" {
		writeJSONError(w, "Not Found", http.StatusNotFound)
		return
	}

	c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])

	// Ping clamd to ensure it is responsive
	err := c.Ping()
	if err != nil {
		// This hits an ALB health check every 10-30s per task - only log the
		// failure case (which is genuinely actionable), not every success.
		slog.Error("Health check failed: ClamAV daemon unreachable", slog.Any("error", err))
		writeJSONError(w, "ClamAV daemon is unreachable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "OK", "message": "ClamAV REST API is ready and ClamAV daemon is responsive"}`))
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

		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
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

			requestID := requestIDFromContext(r.Context())
			start := time.Now()
			slog.Info("Started scanning file", slog.String("request_id", requestID), slog.String("filename", part.FileName()))
			interceptReader := &ErrorInterceptingReader{Reader: part}

			tempFile, err := os.CreateTemp(opts["ASYNC_TEMP_DIR"], "sync-scan-*")
			if err != nil {
				slog.Error("Failed to create temp file", slog.String("request_id", requestID), slog.Any("error", err))
				writeJSONError(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			tempFilePath := tempFile.Name()
			defer os.Remove(tempFilePath)

			uploadStart := time.Now()
			_, err = io.Copy(tempFile, interceptReader)
			uploadDuration := time.Since(uploadStart)
			if err != nil {
				if interceptReader.Err != nil && checkMaxBytesError(w, interceptReader.Err) {
					tempFile.Close()
					return
				}
				slog.Error("Failed to save temp file", slog.String("request_id", requestID), slog.Any("error", err))
				writeJSONError(w, "Failed to read upload", http.StatusInternalServerError)
				tempFile.Close()
				return
			}

			if interceptReader.Err != nil && checkMaxBytesError(w, interceptReader.Err) {
				tempFile.Close()
				return
			}

			if IsEncryptedZip(tempFilePath) {
				tempFile.Close()
				slog.Warn("Rejected encrypted archive", slog.String("request_id", requestID), slog.String("filename", part.FileName()))
				writeJSONError(w, encryptedArchiveMessage, http.StatusUnsupportedMediaType)
				return
			}

			aggregatedResult, err := RunMultiEngineScan(tempFile, tempFilePath, part.FileName(), c, requestID)
			tempFile.Close()

			if err != nil {
				slog.Error("RunMultiEngineScan error", slog.String("request_id", requestID), slog.Any("error", err))
				writeJSONError(w, "Scan engine error", http.StatusInternalServerError)
				return
			}

			s := aggregatedResult

			if s.Status == clamd.RES_PARSE_ERROR {
				writeJSONError(w, "Payload Too Large or Parse Error", http.StatusRequestEntityTooLarge)
				return
			}
			slog.Info("Finished scanning file",
				slog.String("request_id", requestID),
				slog.String("filename", part.FileName()),
				slog.String("result", formatStatus(s.Status)),
				slog.String("description", s.Description),
				slog.Int64("upload_ms", uploadDuration.Milliseconds()),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()),
			)
			writeScanResponse(w, s, part.FileName())
			break
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
		if times < 90 {
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

	if opts["APP_CLAMD_ENDPOINT"] == "" {
		opts["APP_CLAMD_ENDPOINT"] = "tcp://localhost:3310"
	}

	slog.Info("Starting ClamAV REST API")

	InitJWKS()

	if redisURL := opts["REDIS_URL"]; redisURL != "" {
		opt, err := redis.ParseURL(redisURL)
		if err != nil {
			slog.Error("Failed to parse REDIS_URL", slog.Any("error", err))
		} else {
			redisClient = redis.NewClient(opt)
			slog.Info("Redis/Dragonfly caching enabled", slog.String("redis_url", redisURL))
		}
	}

	if sqsQueueURL, ok := opts["AWS_SQS_QUEUE_URL"]; ok && sqsQueueURL != "" {
		go startSQSConsumer(sqsQueueURL)
	}
	
	waitForClamD(opts["APP_CLAMD_ENDPOINT"], 1)

	slog.Info("Connected to clamd", slog.String("port", opts["APP_CLAMD_ENDPOINT"]))

	// RequestLoggingMiddleware is the outermost wrapper on every route (auth
	// included) so a single request_id ties together auth timing, upload
	// timing, per-engine scan timing, and the final result across every log
	// line for that request.
	http.HandleFunc("/api/v1/scan/file", RequestLoggingMiddleware(AuthMiddleware(scanHandler)))
	http.HandleFunc("/api/v1/scan/url", RequestLoggingMiddleware(AuthMiddleware(scanURLHandler)))
	http.HandleFunc("/api/v1/async-scan/file", RequestLoggingMiddleware(AuthMiddleware(scanAsyncHandler)))
	http.HandleFunc("/api/v1/async-scan/url", RequestLoggingMiddleware(AuthMiddleware(scanURLAsyncHandler)))
	http.HandleFunc("/api/v1/events/s3", RequestLoggingMiddleware(AuthMiddleware(scanS3EventHandler)))

	// Admin Endpoints
	http.HandleFunc("/api/v1/admin/status", RequestLoggingMiddleware(AdminAuthMiddleware(adminStatusHandler)))
	http.HandleFunc("/api/v1/admin/reload", RequestLoggingMiddleware(AdminAuthMiddleware(adminReloadHandler)))
	http.HandleFunc("/api/v1/admin/update-signatures", RequestLoggingMiddleware(AdminAuthMiddleware(adminUpdateSignaturesHandler)))

	// Not wrapped in RequestLoggingMiddleware: an ALB target-group health
	// check hits this every 10-30s per task, forever. There's no meaningful
	// lifecycle to trace in a single clamd.Ping() call, and logging two INFO
	// lines per ping would drown out everything else in CloudWatch for
	// essentially zero diagnostic value. Failures are still logged, in home().
	http.HandleFunc("/api/v1/health", home)
	http.HandleFunc("/", home)

	// Explicit timeouts: without these, the default http.Server has none, so a
	// single crafted upload that makes a scan engine hang (see engineTimeout in
	// multi_engine.go) can also tie up the client connection/server goroutine
	// indefinitely on top of it. ReadTimeout/WriteTimeout are generous to allow
	// large legitimate uploads on slow links plus the full scan lifecycle;
	// ReadHeaderTimeout specifically bounds slow-header (slowloris-style) requests.
	httpsServer := &http.Server{
		Addr:              SSL_PORT,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
	httpServer := &http.Server{
		Addr:              PORT,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}

	// Start the HTTPS server in a goroutine
	go httpsServer.ListenAndServeTLS("/etc/ssl/clamav-rest/server.crt", "/etc/ssl/clamav-rest/server.key")

	// Start the HTTP server
	httpServer.ListenAndServe()
}
