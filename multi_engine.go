package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dutchcoders/go-clamd"
)

// engineTimeout bounds how long a single YARA or Maldet invocation may run.
// Without this, a crafted input that makes either engine hang (e.g. pathological
// regex backtracking in YARA, deep archive recursion in Maldet) blocks the scan
// goroutine - and for synchronous endpoints, the client connection - forever.
func engineTimeout() time.Duration {
	if v := opts["SCAN_ENGINE_TIMEOUT_SECONDS"]; v != "" {
		var secs int
		if _, err := fmt.Sscanf(v, "%d", &secs); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 5 * time.Minute
}

// EngineResult holds the output from a scanning engine
type EngineResult struct {
	Engine     string
	IsInfected bool
	Signature  string
	Error      error
	Duration   time.Duration
}

func RunYaraScan(filePath string, originalFilename string) (result EngineResult) {
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	// The staged file on disk has a randomly generated name with no extension
	// (e.g. "sync-scan-873421"), so populate YARA's external variables from the
	// real, original filename/extension. Without this, any signature-base rule
	// that gates on filename/extension (common for .exe/.dll triage rules) can
	// never match, regardless of file content.
	baseName := filepath.Base(originalFilename)
	extension := strings.TrimPrefix(strings.ToLower(filepath.Ext(baseName)), ".")

	result.Engine = "YARA"

	ctx, cancel := context.WithTimeout(context.Background(), engineTimeout())
	defer cancel()

	// -C loads a precompiled ruleset (yara_compiled.yarc, built at image-build
	// time and refreshed by update_signatures.sh) instead of recompiling the
	// entire signature-base source tree from scratch on every single scan.
	// Compiling a multi-thousand-rule set from text is the expensive part of
	// using YARA; loading precompiled bytecode and just scanning is fast.
	// #nosec G204
	cmd := exec.CommandContext(ctx, "yara", "-C",
		"-d", "filename="+baseName,
		"-d", "filepath="+originalFilename,
		"-d", "extension="+extension,
		"-d", "owner=",
		"-d", "filetype=",
		"/var/lib/yara_rules/compiled.yarc", filePath)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		slog.Error("YARA scan timed out", slog.String("file", filePath), slog.String("timeout", engineTimeout().String()))
		result.Error = ctx.Err()
		return result
	}

	if err != nil {
		// YARA exits 0 on both matches and no matches; a non-zero exit always
		// means a genuine problem (missing/broken rules file, binary missing,
		// bad arguments) - not "no threats found". Treat it as an engine
		// failure rather than silently reporting clean.
		slog.Error("YARA execution error", slog.Any("error", err), slog.String("output", string(output)))
		result.Error = err
		return result
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

func RunMaldetScan(filePath string) (result EngineResult) {
	start := time.Now()
	defer func() { result.Duration = time.Since(start) }()

	result.Engine = "Maldet"

	ctx, cancel := context.WithTimeout(context.Background(), engineTimeout())
	defer cancel()

	// Maldet's default config has scan_ignore_root=1 ("LMD typically only scans
	// user space paths... it makes sense to ignore files that are root owned").
	// This app always runs as root and every staged file it writes is therefore
	// root-owned, so without this override Maldet silently reports 0 hits on
	// every scan regardless of content.
	// #nosec G204
	cmd := exec.CommandContext(ctx, "maldet", "-co", "scan_ignore_root=0", "-a", filePath)
	output, err := cmd.CombinedOutput()
	outStr := string(output)

	if ctx.Err() == context.DeadlineExceeded {
		slog.Error("Maldet scan timed out", slog.String("file", filePath), slog.String("timeout", engineTimeout().String()))
		result.Error = ctx.Err()
		return result
	}

	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) || strings.TrimSpace(outStr) == "" {
			// maldet couldn't even run (binary missing/not executable) or produced
			// no output at all - a genuine engine failure, distinct from the
			// non-zero exit code Maldet is known to return when hits are found.
			slog.Error("Maldet execution error", slog.Any("error", err), slog.String("output", outStr))
			result.Error = err
			return result
		}
		slog.Warn("Maldet exited non-zero; parsing output anyway (may indicate hits)", slog.Any("error", err))
	}

	// Maldet outputs a summary report. We can parse for "malware hits"
	if strings.Contains(outStr, "malware hits 1") || strings.Contains(outStr, "malware hits") && !strings.Contains(outStr, "malware hits 0") {
		result.IsInfected = true
		// It's hard to extract the exact signature from standard maldet output without parsing the report file,
		// but we can just flag it as Maldet.Hit for now.
		result.Signature = "Maldet.Malware.Hit"
	}

	return result
}

func RunMultiEngineScan(f *os.File, filePath string, originalFilename string, c *clamd.Clamd) (*clamd.ScanResult, error) {
	var abort chan bool
	var wg sync.WaitGroup
	wg.Add(3)

	var clamResult *clamd.ScanResult
	var yaraResult EngineResult
	var maldetResult EngineResult
	var clamErr error
	var clamDuration time.Duration

	// Worker 1: ClamAV
	go func() {
		defer wg.Done()
		clamStart := time.Now()
		defer func() { clamDuration = time.Since(clamStart) }()
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
		yaraResult = RunYaraScan(filePath, originalFilename)
	}()

	// Worker 3: Maldet
	go func() {
		defer wg.Done()
		maldetResult = RunMaldetScan(filePath)
	}()

	wg.Wait()

	// Per-engine breakdown so a slow scan is diagnosable directly from logs
	// (which engine dominated the total) instead of just seeing one combined
	// duration and having to guess.
	slog.Info("Multi-engine scan timing",
		slog.String("file", filePath),
		slog.Int64("clamav_ms", clamDuration.Milliseconds()),
		slog.Int64("yara_ms", yaraResult.Duration.Milliseconds()),
		slog.Int64("maldet_ms", maldetResult.Duration.Milliseconds()),
	)

	if clamErr != nil {
		return clamResult, clamErr
	}

	// Aggregate results
	finalStatus := clamd.RES_OK
	var descriptions []string
	var warnings []string

	if clamResult != nil {
		if clamResult.Status == clamd.RES_FOUND {
			finalStatus = clamd.RES_FOUND
			descriptions = append(descriptions, "ClamAV:" + clamResult.Description)
		}
	}

	if yaraResult.Error != nil {
		warnings = append(warnings, "YARA")
	} else if yaraResult.IsInfected {
		finalStatus = clamd.RES_FOUND
		descriptions = append(descriptions, "YARA:" + yaraResult.Signature)
	}

	if maldetResult.Error != nil {
		warnings = append(warnings, "Maldet")
	} else if maldetResult.IsInfected {
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

	// Surface engine failures instead of silently reporting a complete result
	// when one or more engines never actually ran (binary missing, crashed, or
	// timed out) - without this, a file could come back CLEAN having only
	// actually been checked by ClamAV, with YARA/Maldet coverage silently lost.
	if len(warnings) > 0 {
		finalDescription += " | WARNING: " + strings.Join(warnings, ",") + " engine(s) did not complete - scan coverage reduced"
		slog.Error("Multi-engine scan degraded: one or more engines failed",
			slog.String("failed_engines", strings.Join(warnings, ",")),
			slog.String("file", filePath))
	}

	aggregatedResult := &clamd.ScanResult{
		Status:      finalStatus,
		Description: finalDescription,
	}

	return aggregatedResult, nil
}
