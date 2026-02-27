// Package main demonstrates a minimal MCP server with bearer auth and metadata endpoints.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/keycardai/go-sdk/mcp"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	mux := http.NewServeMux()

	// Serve OAuth metadata endpoints
	mux.Handle("/.well-known/", mcp.AuthMetadataHandler(
		mcp.WithIssuer(zoneURL),
		mcp.WithScopesSupported([]string{"mcp:tools"}),
		mcp.WithResourceName("Hello World MCP Server"),
	))

	// Protected endpoint with bearer auth
	protected := mcp.RequireBearerAuth(
		mcp.WithRequiredScopes("mcp:tools"),
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authInfo := mcp.AuthInfoFromRequest(r)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message":   "Hello from Keycard MCP Server!",
			"client_id": authInfo.ClientID,
			"scopes":    authInfo.Scopes,
		})
	}))

	mux.Handle("GET /api/hello", protected)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("Listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
