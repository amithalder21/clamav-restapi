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
)

var opts map[string]string

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

	path := paths[0]

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	response, err := c.AllMatchScanFile(path)

	if err != nil {
		writeJSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for responseItem := range response {
		writeScanResponse(w, responseItem, path)
		return // Return immediately after the first result to guarantee valid JSON
	}
}

//This is where the action happens.
func scanHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	//POST takes the uploaded file(s) and saves it to disk.
	case "POST":
		c := clamd.NewClamd(opts["CLAMD_PORT"])
		//get the multipart reader for the request.
		reader, err := r.MultipartReader()

		if err != nil {
			writeJSONError(w, err.Error(), http.StatusInternalServerError)
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
			var abort chan bool
			response, err := c.ScanStream(part, abort)
			if err != nil {
				slog.Error("ScanStream error", slog.String("filename", part.FileName()), slog.Any("error", err))
				writeJSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}
			
			for s := range response {
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

	slog.Info("Starting clamav rest bridge")
	slog.Info("Connecting to clamd", slog.String("port", opts["CLAMD_PORT"]))
	
	if sqsQueueURL, ok := opts["SQS_QUEUE_URL"]; ok && sqsQueueURL != "" {
		go startSQSConsumer(sqsQueueURL)
	}
	
	waitForClamD(opts["CLAMD_PORT"], 1)

	slog.Info("Connected to clamd", slog.String("port", opts["CLAMD_PORT"]))

	http.HandleFunc("/scan", AuthMiddleware(scanHandler))
	http.HandleFunc("/scanPath", AuthMiddleware(scanPathHandler))
	http.HandleFunc("/scan-url", AuthMiddleware(scanURLHandler))
	http.HandleFunc("/scan-async", AuthMiddleware(scanAsyncHandler))
	http.HandleFunc("/scan-url-async", AuthMiddleware(scanURLAsyncHandler))
	http.HandleFunc("/scan-s3-event", AuthMiddleware(scanS3EventHandler))
	
	// Admin Endpoints
	http.HandleFunc("/admin/status", AdminAuthMiddleware(adminStatusHandler))
	http.HandleFunc("/admin/reload", AdminAuthMiddleware(adminReloadHandler))
	http.HandleFunc("/admin/update-signatures", AdminAuthMiddleware(adminUpdateSignaturesHandler))
	
	http.HandleFunc("/", home)

	// Start the HTTPS server in a goroutine
	go http.ListenAndServeTLS(SSL_PORT, "/etc/ssl/clamav-rest/server.crt", "/etc/ssl/clamav-rest/server.key", nil)

	// Start the HTTP server
	http.ListenAndServe(PORT, nil)
}
