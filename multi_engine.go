package main

import (
	"log/slog"
	"os/exec"
	"strings"
)

// EngineResult holds the output from a scanning engine
type EngineResult struct {
	Engine    string
	IsInfected bool
	Signature string
	Error     error
}

func RunYaraScan(filePath string) EngineResult {
	// Execute YARA with the rules directory
	// #nosec G204
	cmd := exec.Command("yara", "-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "owner=", "-d", "filetype=", "/var/lib/yara_rules/index.yar", filePath)
	output, err := cmd.CombinedOutput()
	
	result := EngineResult{
		Engine: "YARA",
	}

	if err != nil {
		// YARA exits with code 1 if it finds no matches, but combinedOutput will return an error if exit code != 0
		// Wait, YARA exits with 0 on success, 1 on error (syntax etc). 
		// Actually yara returns 0 on both matches and no matches unless there's an error.
		slog.Error("YARA execution error or match issue", slog.Any("error", err), slog.String("output", string(output)))
	}

	outStr := strings.TrimSpace(string(output))
	if outStr != "" {
		// YARA outputs the matching rule name followed by the file path
		// e.g. "eicar_av_test /tmp/scan-123"
		lines := strings.Split(outStr, "\n")
		signatures := []string{}
		for _, line := range lines {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				signatures = append(signatures, parts[0])
			}
		}
		if len(signatures) > 0 {
			result.IsInfected = true
			result.Signature = strings.Join(signatures, ",")
		}
	}

	return result
}

func RunMaldetScan(filePath string) EngineResult {
	// Execute Maldet against the specific file
	// #nosec G204
	cmd := exec.Command("maldet", "-a", filePath)
	output, err := cmd.CombinedOutput()
	
	result := EngineResult{
		Engine: "Maldet",
	}

	if err != nil {
		slog.Error("Maldet execution error", slog.Any("error", err), slog.String("output", string(output)))
		// Maldet might return non-zero if hits are found, we need to check output anyway
	}

	outStr := string(output)
	
	// Maldet outputs a summary report. We can parse for "malware hits"
	if strings.Contains(outStr, "malware hits 1") || strings.Contains(outStr, "malware hits") && !strings.Contains(outStr, "malware hits 0") {
		result.IsInfected = true
		// It's hard to extract the exact signature from standard maldet output without parsing the report file,
		// but we can just flag it as Maldet.Hit for now.
		result.Signature = "Maldet.Malware.Hit"
	}

	return result
}
