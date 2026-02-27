package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchAuthorizationServerMetadata(t *testing.T) {
	metadata := AuthorizationServerMetadata{
		Issuer:            "https://auth.example.com",
		TokenEndpoint:     "https://auth.example.com/token",
		JWKSURI:           "https://auth.example.com/.well-known/jwks.json",
		AuthorizationEndpoint: "https://auth.example.com/authorize",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}))
	defer server.Close()

	result, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Issuer != metadata.Issuer {
		t.Errorf("issuer: got %q, want %q", result.Issuer, metadata.Issuer)
	}
	if result.TokenEndpoint != metadata.TokenEndpoint {
		t.Errorf("token_endpoint: got %q, want %q", result.TokenEndpoint, metadata.TokenEndpoint)
	}
	if result.JWKSURI != metadata.JWKSURI {
		t.Errorf("jwks_uri: got %q, want %q", result.JWKSURI, metadata.JWKSURI)
	}
}

func TestFetchAuthorizationServerMetadata_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	_, err := FetchAuthorizationServerMetadata(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected error")
	}

	var httpErr *HTTPError
	if ok := err.(*HTTPError); ok == nil {
		t.Errorf("expected HTTPError, got %T", err)
	} else {
		httpErr = ok
		if httpErr.Status != 404 {
			t.Errorf("status: got %d, want 404", httpErr.Status)
		}
	}
}
