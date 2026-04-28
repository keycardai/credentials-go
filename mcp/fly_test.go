package mcp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestFlyWorkloadIdentity_PrepareTokenExchangeRequest(t *testing.T) {
	socketPath, cleanup := startFakeOIDCServer(t, "fly-oidc-token-123")
	defer cleanup()

	cred := NewFlyWorkloadIdentity(
		WithFlySocketPath(socketPath),
		WithFlyAudience("https://zone.keycard.cloud"),
	)

	req, err := cred.PrepareTokenExchangeRequest(context.Background(), "user-token", "urn:secret:test", nil)
	if err != nil {
		t.Fatalf("PrepareTokenExchangeRequest: %v", err)
	}

	if req.ClientAssertion != "fly-oidc-token-123" {
		t.Errorf("client_assertion: got %q, want %q", req.ClientAssertion, "fly-oidc-token-123")
	}
	if req.ClientAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type: got %q", req.ClientAssertionType)
	}
	if req.SubjectToken != "user-token" {
		t.Errorf("subject_token: got %q, want %q", req.SubjectToken, "user-token")
	}
	if req.Resource != "urn:secret:test" {
		t.Errorf("resource: got %q", req.Resource)
	}
}

func TestFlyWorkloadIdentity_Auth(t *testing.T) {
	cred := NewFlyWorkloadIdentity()
	if cred.Auth() != nil {
		t.Error("Auth() should return nil for assertion-based credential")
	}
}

func TestFlyWorkloadIdentity_SocketNotAvailable(t *testing.T) {
	cred := NewFlyWorkloadIdentity(
		WithFlySocketPath("/tmp/nonexistent-fly-socket-test"),
	)

	_, err := cred.PrepareTokenExchangeRequest(context.Background(), "", "urn:secret:test", nil)
	if err == nil {
		t.Fatal("expected error when socket is unavailable")
	}

	var configErr *FlyWorkloadIdentityConfigurationError
	if !errors.As(err, &configErr) {
		t.Fatalf("expected *FlyWorkloadIdentityConfigurationError, got %T: %v", err, err)
	}
}

func TestFlyWorkloadIdentity_DefaultSocketPath(t *testing.T) {
	cred := NewFlyWorkloadIdentity()
	if cred.socketPath != "/.fly/api" {
		t.Errorf("default socket path: got %q, want %q", cred.socketPath, "/.fly/api")
	}
}

// startFakeOIDCServer starts a Unix socket HTTP server that mimics the
// Fly.io OIDC token endpoint. Returns the socket path and a cleanup function.
func startFakeOIDCServer(t *testing.T, tokenToReturn string) (string, func()) {
	t.Helper()

	dir, err := os.MkdirTemp("", "fly-oidc-test")
	if err != nil {
		t.Fatalf("creating temp dir: %v", err)
	}

	socketPath := filepath.Join(dir, "api.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("listening on unix socket: %v", err)
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/tokens/oidc" && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(tokenToReturn))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}),
	}

	go server.Serve(listener)

	return socketPath, func() {
		server.Close()
		os.RemoveAll(dir)
	}
}
