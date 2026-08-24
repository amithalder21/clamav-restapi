package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/dutchcoders/go-clamd"
)

type AdminStatusResponse struct {
	Version string       `json:"version"`
	Stats   *clamd.Stats `json:"stats,omitempty"`
	Error   string       `json:"error,omitempty"`
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

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	
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

	stats, _ := c.Stats()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(AdminStatusResponse{
		Version: versionStr,
		Stats:   stats,
	})
}

func adminReloadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSONError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	c := clamd.NewClamd(opts["CLAMD_PORT"])
	err := c.Reload()
	
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(AdminGenericResponse{
			Error: fmt.Sprintf("Failed to reload daemon: %v", err),
		})
		return
	}

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
		fmt.Printf(time.Now().Format(time.RFC3339)+" [Admin] Triggering freshclam update...\n")
		cmd := exec.Command("freshclam")
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf(time.Now().Format(time.RFC3339)+" [Admin] freshclam failed: %v\nOutput: %s\n", err, string(out))
			return
		}
		fmt.Printf(time.Now().Format(time.RFC3339)+" [Admin] freshclam succeeded:\n%s\n", string(out))
		
		// Optionally reload clamd after update
		c := clamd.NewClamd(opts["CLAMD_PORT"])
		c.Reload()
	}()
}
