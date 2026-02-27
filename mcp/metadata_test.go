package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMetadataHandler_ProtectedResource(t *testing.T) {
	handler := AuthMetadataHandler(
		WithScopesSupported([]string{"mcp:tools", "read"}),
		WithResourceName("Test Server"),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}

	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(rec.Body).Decode(&metadata); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if metadata.ResourceName != "Test Server" {
		t.Errorf("resource_name: got %q", metadata.ResourceName)
	}
	if len(metadata.ScopesSupported) != 2 {
		t.Errorf("scopes: got %v", metadata.ScopesSupported)
	}
}

func TestAuthMetadataHandler_MCPProtocolVersion(t *testing.T) {
	handler := AuthMetadataHandler(
		WithScopesSupported([]string{"mcp:tools"}),
	)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	req.Header.Set("MCP-Protocol-Version", "2025-03-26")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	var metadata ProtectedResourceMetadata
	json.NewDecoder(rec.Body).Decode(&metadata)

	if len(metadata.AuthorizationServers) != 1 {
		t.Errorf("expected 1 authorization server for 2025-03-26, got %d", len(metadata.AuthorizationServers))
	}
}

func TestAuthMetadataHandler_CORSHeaders(t *testing.T) {
	handler := AuthMetadataHandler()

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("missing CORS origin header")
	}
}
