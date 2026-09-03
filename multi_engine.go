package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	
	"github.com/dutchcoders/go-clamd"
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

func RunMultiEngineScan(f *os.File, filePath string, c *clamd.Clamd) (*clamd.ScanResult, error) {
	var abort chan bool
	var wg sync.WaitGroup
	wg.Add(3)

	var clamResult *clamd.ScanResult
	var yaraResult EngineResult
	var maldetResult EngineResult
	var clamErr error

	// Worker 1: ClamAV
	go func() {
		defer wg.Done()
		f.Seek(0, 0)
		clamdResponse, err := c.ScanStream(f, abort)
		if err != nil {
			clamErr = err
			clamResult = &clamd.ScanResult{Status: clamd.RES_ERROR, Description: fmt.Sprintf("ScanStream error: %v", err)}
			return
		}
		for s := range clamdResponse {
			clamResult = s
		}
	}()

	// Worker 2: YARA
	go func() {
		defer wg.Done()
		yaraResult = RunYaraScan(filePath)
	}()

	// Worker 3: Maldet
	go func() {
		defer wg.Done()
		maldetResult = RunMaldetScan(filePath)
	}()

	wg.Wait()

	if clamErr != nil {
		return clamResult, clamErr
	}

	// Aggregate results
	finalStatus := clamd.RES_OK
	var descriptions []string

	if clamResult != nil {
		if clamResult.Status == clamd.RES_FOUND {
			finalStatus = clamd.RES_FOUND
			descriptions = append(descriptions, "ClamAV:" + clamResult.Description)
		}
	}

	if yaraResult.IsInfected {
		finalStatus = clamd.RES_FOUND
		descriptions = append(descriptions, "YARA:" + yaraResult.Signature)
	}

	if maldetResult.IsInfected {
		finalStatus = clamd.RES_FOUND
		descriptions = append(descriptions, "Maldet:" + maldetResult.Signature)
	}

	finalDescription := "CLEAN"
	if finalStatus == clamd.RES_FOUND {
		finalDescription = strings.Join(descriptions, " | ")
	} else if clamResult != nil && clamResult.Status == clamd.RES_ERROR {
		finalStatus = clamd.RES_ERROR
		finalDescription = clamResult.Description
	} else if clamResult != nil && clamResult.Status == clamd.RES_PARSE_ERROR {
		finalStatus = clamd.RES_PARSE_ERROR
		finalDescription = "Parse Error"
	}

	aggregatedResult := &clamd.ScanResult{
		Status:      finalStatus,
		Description: finalDescription,
	}

	return aggregatedResult, nil
}
