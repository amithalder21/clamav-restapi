package main

import (
	"net/http"
	"os"
)

// AuthMiddleware requires an API key if the API_KEY environment variable is set.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := os.Getenv("API_KEY")
		if apiKey != "" {
			reqKey := r.Header.Get("X-API-Key")
			if reqKey == "" {
				reqKey = r.Header.Get("Authorization")
			}
			// Allow either simple key or Bearer token
			if reqKey != apiKey && reqKey != "Bearer "+apiKey {
				writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next.ServeHTTP(w, r)
	}
}

// AdminAuthMiddleware strictly requires the ADMIN_API_KEY environment variable to be set.
// If it is not set, the endpoints are completely disabled (404).
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adminKey := os.Getenv("ADMIN_API_KEY")
		if adminKey == "" {
			// Fail secure: if no key is configured, admin endpoints do not exist.
			writeJSONError(w, "Admin API is disabled", http.StatusNotFound)
			return
		}

		reqKey := r.Header.Get("X-API-Key")
		if reqKey == "" {
			reqKey = r.Header.Get("Authorization")
		}

		if reqKey != adminKey && reqKey != "Bearer "+adminKey {
			writeJSONError(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
