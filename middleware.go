package main

import (
	"crypto/subtle"
	"net/http"
	"os"
)

// AuthMiddleware requires an API key to be set via the API_KEY environment variable.
// If it is not set, it fails closed to prevent unauthenticated access.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		apiKey := os.Getenv("API_KEY")
		if apiKey == "" {
			writeJSONError(w, "API is disabled (API_KEY not configured)", http.StatusForbidden)
			return
		}

		reqKey := r.Header.Get("X-API-Key")
		if reqKey == "" {
			reqKey = r.Header.Get("Authorization")
		}

		match1 := subtle.ConstantTimeCompare([]byte(reqKey), []byte(apiKey)) == 1
		match2 := subtle.ConstantTimeCompare([]byte(reqKey), []byte("Bearer "+apiKey)) == 1

		if !match1 && !match2 {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
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

		match1 := subtle.ConstantTimeCompare([]byte(reqKey), []byte(adminKey)) == 1
		match2 := subtle.ConstantTimeCompare([]byte(reqKey), []byte("Bearer "+adminKey)) == 1

		if !match1 && !match2 {
			writeJSONError(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
