package main

import (
	"net/url"
	"path/filepath"
	"strings"
)

// disallowedFileTypeMessage is returned (415) when ALLOWED_FILE_TYPES is
// configured and a submitted file's extension isn't in it.
const disallowedFileTypeMessage = "File type not permitted"

// allowedFileTypes parses ALLOWED_FILE_TYPES (a comma-separated list of
// extensions, e.g. "pdf,docx,zip,txt") into a lowercase, dot-free set. A nil
// return (as opposed to an empty, non-nil map) means the env var is unset -
// i.e. no restriction is configured - so this stays opt-in and backward
// compatible with every deployment that hasn't set it.
func allowedFileTypes() map[string]bool {
	raw := opts["ALLOWED_FILE_TYPES"]
	if raw == "" {
		return nil
	}
	allowed := make(map[string]bool)
	for _, ext := range strings.Split(raw, ",") {
		ext = strings.ToLower(strings.TrimSpace(ext))
		ext = strings.TrimPrefix(ext, ".")
		if ext != "" {
			allowed[ext] = true
		}
	}
	return allowed
}

// isFileTypeAllowed reports whether name's extension is permitted by
// ALLOWED_FILE_TYPES. When the env var is unset, every type is allowed.
//
// This checks the caller-supplied filename extension only, not file content
// or magic bytes - a file renamed to a permitted extension bypasses it. It's
// meant to reject obviously out-of-policy uploads (e.g. a .exe on an
// endpoint meant for documents) before spending any I/O on them, not to
// serve as the sole line of defense - ClamAV/YARA/Maldet still run on
// everything that passes this gate.
func isFileTypeAllowed(name string) bool {
	allowed := allowedFileTypes()
	if allowed == nil {
		return true
	}
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return allowed[ext]
}

// extensionCheckName returns the best string to run isFileTypeAllowed
// against for a URL-based scan target: the URL's path component, so a query
// string (e.g. "?token=abc") after the real extension doesn't corrupt the
// check. Falls back to the raw URL if it doesn't parse.
func extensionCheckName(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Path != "" {
		return u.Path
	}
	return rawURL
}
