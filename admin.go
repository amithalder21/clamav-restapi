package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/dutchcoders/go-clamd"
)

var apiStartTime = time.Now()

type AdminClamAVInfo struct {
	EngineVersion    string `json:"engine_version"`
	SignatureVersion string `json:"signature_version"`
	SignatureDate    string `json:"signature_date"`
}

type AdminGoMetrics struct {
	UptimeSeconds     int     `json:"uptime_seconds"`
	UptimeHuman       string  `json:"uptime_human"`
	Goroutines        int     `json:"goroutines"`
	MemoryAllocatedMB float64 `json:"memory_allocated_mb"`
}

type AdminStatusResponse struct {
	RawVersion string            `json:"raw_version"`
	ClamAV     AdminClamAVInfo   `json:"clamav"`
	Stats      *clamd.Stats      `json:"stats,omitempty"`
	Config     map[string]string `json:"config"`
	GoMetrics  AdminGoMetrics    `json:"go_metrics"`
	Error      string            `json:"error,omitempty"`
}

type AdminGenericResponse struct {
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

func adminStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
	
	versionChan, err := c.Version()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AdminStatusResponse{Error: fmt.Sprintf("Failed to get version: %v", err)})
		return
	}
	
	var versionStr string
	for v := range versionChan {
		versionStr += v.Raw
	}

	var clamavInfo AdminClamAVInfo
	parts := strings.Split(versionStr, "/")
	if len(parts) >= 3 {
		clamavInfo.EngineVersion = strings.TrimSpace(strings.TrimPrefix(parts[0], "ClamAV "))
		clamavInfo.SignatureVersion = strings.TrimSpace(parts[1])
		clamavInfo.SignatureDate = strings.TrimSpace(strings.Join(parts[2:], "/"))
	} else {
		clamavInfo.EngineVersion = versionStr
	}

	stats, _ := c.Stats()
	if stats != nil {
		stats.State = strings.TrimSpace(strings.TrimPrefix(stats.State, "STATE:"))
		stats.Threads = strings.TrimSpace(strings.TrimPrefix(stats.Threads, "THREADS:"))
		stats.Memstats = strings.TrimSpace(strings.TrimPrefix(stats.Memstats, "MEMSTATS:"))
		stats.Queue = strings.TrimSpace(strings.TrimPrefix(stats.Queue, "QUEUE:"))
	}

	safeConfig := make(map[string]string)
	for k, v := range opts {
		if strings.HasPrefix(k, "MAX_") || strings.HasPrefix(k, "PCRE_") || strings.HasPrefix(k, "SIGNATURE_") || k == "PORT" || k == "APP_CLAMD_ENDPOINT" {
			safeConfig[k] = v
		}
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	uptime := time.Since(apiStartTime)
	
	goMetrics := AdminGoMetrics{
		UptimeSeconds:     int(uptime.Seconds()),
		UptimeHuman:       uptime.Round(time.Second).String(),
		Goroutines:        runtime.NumGoroutine(),
		MemoryAllocatedMB: float64(m.Alloc) / 1024 / 1024,
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(AdminStatusResponse{
		RawVersion: versionStr,
		ClamAV:     clamavInfo,
		Stats:      stats,
		Config:     safeConfig,
		GoMetrics:  goMetrics,
	})
}

func adminReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
	err := c.Reload()
	
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		slog.Error("Failed to reload daemon", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AdminGenericResponse{
			Error: fmt.Sprintf("Failed to reload daemon: %v", err),
		})
		return
	}

	slog.Info("Reload command sent to ClamAV successfully")
	json.NewEncoder(w).Encode(AdminGenericResponse{
		Message: "Reload command sent to ClamAV successfully.",
	})
}

func adminUpdateSignaturesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(AdminGenericResponse{
		Message: "Signature update (freshclam) started in the background.",
	})

	go func() {
		slog.Info("Triggering freshclam update")
		cmd := exec.Command("freshclam")
		out, err := cmd.CombinedOutput()
		if err != nil {
			slog.Error("freshclam failed", slog.Any("error", err), slog.String("output", string(out)))
			return
		}
		slog.Info("freshclam succeeded", slog.String("output", string(out)))
		
		// Optionally reload clamd after update
		c := clamd.NewClamd(opts["APP_CLAMD_ENDPOINT"])
		c.Reload()
	}()
}
