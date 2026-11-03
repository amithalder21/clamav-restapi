package main

import (
	"log/slog"
	"os"
	"strings"
	"time"
)

// RunYaraScanWithViews scans the uploaded file as-is and, concurrently, its
// decoded content (see buildDecodedBundle). YARA matches raw bytes, and most
// PDF generators compress their content streams, so without the second pass a
// rule can never see text inside a compressed stream. Any rule hit in either
// pass is a hit.
func RunYaraScanWithViews(filePath string, originalFilename string, requestID string) EngineResult {
	start := time.Now()

	rawDone := make(chan EngineResult, 1)
	go func() { rawDone <- RunYaraScan(filePath, originalFilename, requestID) }()

	view := scanDecodedView(filePath, originalFilename, requestID)
	result := <-rawDone

	merged := mergeYaraResults(result, view)
	merged.Duration = time.Since(start)
	return merged
}

func scanDecodedView(filePath string, originalFilename string, requestID string) *EngineResult {
	info, err := os.Stat(filePath)
	if err != nil {
		slog.Error("Could not stat file for decoded-content scan", slog.String("request_id", requestID), slog.Any("error", err))
		return nil
	}
	if limit := decodeLimitBytes(); info.Size() > limit {
		slog.Warn("File over the decoded-content scan size limit; scanning as uploaded only", slog.String("request_id", requestID), slog.Int64("size_bytes", info.Size()), slog.Int64("limit_bytes", limit))
		return nil
	}
	raw, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("Could not read file for decoded-content scan", slog.String("request_id", requestID), slog.Any("error", err))
		return nil
	}
	bundle := buildDecodedBundle(raw, defaultDecodeLimits())
	if bundle.truncated {
		slog.Warn("Decoded-content scan hit a decode limit; scanning what was decoded", slog.String("request_id", requestID))
	}
	if len(bundle.data) == 0 {
		return nil
	}

	tmp, err := os.CreateTemp(opts["ASYNC_TEMP_DIR"], "yara-view-*")
	if err != nil {
		slog.Error("Could not stage decoded content for YARA", slog.String("request_id", requestID), slog.Any("error", err))
		return nil
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(bundle.data)
	if closeErr := tmp.Close(); writeErr != nil || closeErr != nil {
		slog.Error("Could not write decoded content for YARA", slog.String("request_id", requestID))
		return nil
	}

	res := RunYaraScan(tmp.Name(), originalFilename, requestID)
	return &res
}

func mergeYaraResults(raw EngineResult, view *EngineResult) EngineResult {
	if view == nil {
		return raw
	}
	merged := raw
	infected := (raw.IsInfected && raw.Error == nil) || (view.IsInfected && view.Error == nil)
	if infected {
		merged.Error = nil
		merged.IsInfected = true
		merged.Signature = joinUnique(raw.Signature, view.Signature)
		return merged
	}
	if merged.Error == nil {
		merged.Error = view.Error
	}
	return merged
}

func joinUnique(lists ...string) string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, sig := range strings.Split(l, ",") {
			if sig != "" && !seen[sig] {
				seen[sig] = true
				out = append(out, sig)
			}
		}
	}
	return strings.Join(out, ",")
}
