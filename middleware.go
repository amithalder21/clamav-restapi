package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

var jwks *keyfunc.JWKS

// InitJWKS initializes the global JWKS fetcher for JWT validation
func InitJWKS() {
	jwksURL := os.Getenv("COGNITO_JWKS_URL")
	if jwksURL == "" {
		slog.Warn("COGNITO_JWKS_URL not set, JWT authentication is disabled")
		return
	}

	options := keyfunc.Options{
		Ctx: context.Background(),
		RefreshErrorHandler: func(err error) {
			slog.Error("There was an error with the jwt.Keyfunc", slog.Any("error", err))
		},
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	var err error
	jwks, err = keyfunc.Get(jwksURL, options)
	if err != nil {
		slog.Error("Failed to create JWKS from resource at the given URL.", slog.Any("error", err))
	} else {
		slog.Info("Successfully initialized JWKS from", slog.String("url", jwksURL))
	}
}

func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return authHeader
}

// AuthMiddleware requires a valid JWT Bearer token
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if jwks == nil {
			writeJSONError(w, "API is disabled (COGNITO_JWKS_URL not configured)", http.StatusForbidden)
			return
		}

		tokenStr := extractToken(r)
		if tokenStr == "" {
			writeJSONError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenStr, jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !token.Valid {
			slog.Error("Invalid JWT", slog.Any("error", err))
			writeJSONError(w, "Unauthorized (invalid token)", http.StatusUnauthorized)
			return
		}

		expectedIssuer := os.Getenv("COGNITO_ISSUER")
		if expectedIssuer == "" {
			slog.Error("COGNITO_ISSUER is not configured")
			writeJSONError(w, "Internal Server Error (auth misconfigured)", http.StatusInternalServerError)
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeJSONError(w, "Unauthorized (invalid claims)", http.StatusUnauthorized)
			return
		}
		iss, _ := claims["iss"].(string)
		if iss != expectedIssuer {
			writeJSONError(w, "Unauthorized (invalid issuer)", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// AdminAuthMiddleware requires a valid JWT with the 'admin' scope or group
func AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if jwks == nil {
			writeJSONError(w, "Admin API is disabled (COGNITO_JWKS_URL not configured)", http.StatusNotFound)
			return
		}

		tokenStr := extractToken(r)
		if tokenStr == "" {
			writeJSONError(w, "Forbidden (missing token)", http.StatusForbidden)
			return
		}

		token, err := jwt.Parse(tokenStr, jwks.Keyfunc, jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !token.Valid {
			slog.Error("Invalid admin JWT", slog.Any("error", err))
			writeJSONError(w, "Forbidden (invalid token)", http.StatusForbidden)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			writeJSONError(w, "Forbidden (invalid claims)", http.StatusForbidden)
			return
		}

		expectedIssuer := os.Getenv("COGNITO_ISSUER")
		if expectedIssuer == "" {
			slog.Error("COGNITO_ISSUER is not configured")
			writeJSONError(w, "Internal Server Error (auth misconfigured)", http.StatusInternalServerError)
			return
		}
		iss, _ := claims["iss"].(string)
		if iss != expectedIssuer {
			writeJSONError(w, "Forbidden (invalid issuer)", http.StatusForbidden)
			return
		}

		isAdmin := false
		if scope, ok := claims["scope"].(string); ok && strings.Contains(scope, "admin") {
			isAdmin = true
		}
		if groups, ok := claims["cognito:groups"].([]interface{}); ok {
			for _, g := range groups {
				if str, ok := g.(string); ok && str == "admin" {
					isAdmin = true
				}
			}
		}

		if !isAdmin {
			writeJSONError(w, "Forbidden (requires admin scope)", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}
}
