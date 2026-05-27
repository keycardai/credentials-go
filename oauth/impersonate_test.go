package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildSubstituteUserToken(t *testing.T) {
	token := buildSubstituteUserToken("user-42")

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 dot-separated parts, got %d: %q", len(parts), token)
	}
	if parts[2] != "" {
		t.Errorf("signature part must be empty (trailing dot), got %q", parts[2])
	}

	headerBytes, err := Base64URLDecode(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]string
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("unmarshaling header: %v", err)
	}
	if header["typ"] != "vnd.kc.su+jwt" {
		t.Errorf("header typ: got %q, want %q", header["typ"], "vnd.kc.su+jwt")
	}
	if header["alg"] != "none" {
		t.Errorf("header alg: got %q, want %q", header["alg"], "none")
	}

	payloadBytes, err := Base64URLDecode(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]string
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshaling payload: %v", err)
	}
	if payload["sub"] != "user-42" {
		t.Errorf("payload sub: got %q, want %q", payload["sub"], "user-42")
	}
}

func TestBuildSubstituteUserToken_Deterministic(t *testing.T) {
	a := buildSubstituteUserToken("alice")
	b := buildSubstituteUserToken("alice")
	if a != b {
		t.Errorf("expected deterministic output, got %q and %q", a, b)
	}
}

// mockImpersonateServer returns an httptest.Server that handles:
//   - /.well-known/oauth-authorization-server  → token endpoint discovery
//   - /token with grant_type=client_credentials → actor token
//   - /token with grant_type=token-exchange     → impersonated token (or error)
func mockImpersonateServer(t *testing.T, exchangeHandler func(w http.ResponseWriter, r *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parsing form: %v", err)
			}
			switch r.Form.Get("grant_type") {
			case "client_credentials":
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"access_token": "actor-token-abc",
					"token_type":   "bearer",
					"expires_in":   3600,
				})
			case "urn:ietf:params:oauth:grant-type:token-exchange":
				exchangeHandler(w, r)
			default:
				t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
				http.Error(w, "bad grant_type", http.StatusBadRequest)
			}
		}
	}))
}

func TestImpersonateClient_Success(t *testing.T) {
	var capturedSubjectToken, capturedSubjectTokenType, capturedActorToken string

	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedSubjectToken = r.Form.Get("subject_token")
		capturedSubjectTokenType = r.Form.Get("subject_token_type")
		capturedActorToken = r.Form.Get("actor_token")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "impersonated-token-xyz",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("admin-svc", "secret"))
	resp, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "user-42",
		Resource:       "https://api.example.com",
		Scopes:         []string{"read:orders"},
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if resp.AccessToken != "impersonated-token-xyz" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}

	// Verify subject_token is a valid trailing-dot unsigned JWT with correct sub
	parts := strings.Split(capturedSubjectToken, ".")
	if len(parts) != 3 || parts[2] != "" {
		t.Errorf("subject_token format wrong: %q", capturedSubjectToken)
	}
	payloadBytes, _ := Base64URLDecode(parts[1])
	var payload map[string]string
	json.Unmarshal(payloadBytes, &payload)
	if payload["sub"] != "user-42" {
		t.Errorf("subject_token sub: got %q, want %q", payload["sub"], "user-42")
	}

	if capturedSubjectTokenType != SubstituteUserTokenType {
		t.Errorf("subject_token_type: got %q, want %q", capturedSubjectTokenType, SubstituteUserTokenType)
	}
	if capturedActorToken != "actor-token-abc" {
		t.Errorf("actor_token: got %q, want %q", capturedActorToken, "actor-token-abc")
	}
}

func TestImpersonateClient_ResourceAndScopes(t *testing.T) {
	var capturedResource, capturedScope string

	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedResource = r.Form.Get("resource")
		capturedScope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "bearer"})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("svc", "s"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "u1",
		Resource:       "https://api.example.com",
		Scopes:         []string{"read:orders", "write:orders"},
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if capturedResource != "https://api.example.com" {
		t.Errorf("resource: got %q", capturedResource)
	}
	if capturedScope != "read:orders write:orders" {
		t.Errorf("scope: got %q", capturedScope)
	}
}

func TestImpersonateClient_ResourceOmitted(t *testing.T) {
	var capturedResource string

	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedResource = r.Form.Get("resource")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "bearer"})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("svc", "s"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "u1",
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if capturedResource != "" {
		t.Errorf("expected resource omitted, got %q", capturedResource)
	}
}

func TestImpersonateClient_ScopesOmitted(t *testing.T) {
	var capturedScope string

	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		capturedScope = r.Form.Get("scope")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "token_type": "bearer"})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("svc", "s"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{
		UserIdentifier: "u1",
		Resource:       "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("Impersonate: %v", err)
	}
	if capturedScope != "" {
		t.Errorf("expected scope omitted, got %q", capturedScope)
	}
}

func TestImpersonateClient_InvalidGrant(t *testing.T) {
	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "user not impersonatable",
		})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("svc", "s"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{UserIdentifier: "unknown-user"})
	if err == nil {
		t.Fatal("expected error")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("error code: got %q, want %q", oauthErr.ErrorCode, "invalid_grant")
	}
}

func TestImpersonateClient_UnauthorizedClient(t *testing.T) {
	srv := mockImpersonateServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "unauthorized_client",
			"error_description": "client not permitted to impersonate",
		})
	})
	defer srv.Close()

	client := NewImpersonateClient(srv.URL, WithImpersonateCredentials("unprivileged-svc", "s"))
	_, err := client.Impersonate(context.Background(), ImpersonateRequest{UserIdentifier: "any-user"})
	if err == nil {
		t.Fatal("expected error")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("expected *OAuthError, got %T: %v", err, err)
	}
	if oauthErr.ErrorCode != "unauthorized_client" {
		t.Errorf("error code: got %q, want %q", oauthErr.ErrorCode, "unauthorized_client")
	}
}
