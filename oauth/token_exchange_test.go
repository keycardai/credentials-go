package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenExchangeClient_ExchangeToken(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parsing form: %v", err)
			}
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
				t.Errorf("unexpected grant_type: %s", r.Form.Get("grant_type"))
			}
			if r.Form.Get("subject_token") != "user-token-123" {
				t.Errorf("unexpected subject_token: %s", r.Form.Get("subject_token"))
			}
			if r.Form.Get("resource") != "https://api.github.com" {
				t.Errorf("unexpected resource: %s", r.Form.Get("resource"))
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "exchanged-token-456",
				"token_type":   "bearer",
				"expires_in":   3600,
				"scope":        "repo user",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	resp, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "user-token-123",
		Resource:     "https://api.github.com",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if resp.AccessToken != "exchanged-token-456" {
		t.Errorf("access_token: got %q", resp.AccessToken)
	}
	if resp.TokenType != "bearer" {
		t.Errorf("token_type: got %q", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("expires_in: got %d", resp.ExpiresIn)
	}
	if len(resp.Scope) != 2 || resp.Scope[0] != "repo" || resp.Scope[1] != "user" {
		t.Errorf("scope: got %v", resp.Scope)
	}
}

func TestTokenExchangeClient_BasicAuth(t *testing.T) {
	var receivedAuth string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			receivedAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL,
		WithClientCredentials("my-client", "my-secret"),
	)

	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "user-token",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if receivedAuth == "" {
		t.Error("expected Authorization header")
	}
	if receivedAuth != "Basic bXktY2xpZW50Om15LXNlY3JldA==" {
		t.Errorf("unexpected Authorization header: %s", receivedAuth)
	}
}

func TestTokenExchangeClient_ErrorResponse(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "token expired",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)

	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken: "expired-token",
	})
	if err == nil {
		t.Fatal("expected error")
	}

	expected := "token exchange failed (HTTP 400): token expired"
	if err.Error() != expected {
		t.Errorf("error: got %q, want %q", err.Error(), expected)
	}
}

func TestTokenExchangeClient_ClientAssertionFields(t *testing.T) {
	var receivedAssertion, receivedAssertionType string

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]string{
				"issuer":         "http://" + r.Host,
				"token_endpoint": "http://" + r.Host + "/token",
			})
		case "/token":
			r.ParseForm()
			receivedAssertion = r.FormValue("client_assertion")
			receivedAssertionType = r.FormValue("client_assertion_type")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "token",
				"token_type":   "bearer",
			})
		}
	}))
	defer tokenServer.Close()

	client := NewTokenExchangeClient(tokenServer.URL)
	_, err := client.ExchangeToken(context.Background(), TokenExchangeRequest{
		SubjectToken:        "user-token",
		Resource:            "https://api.github.com",
		ClientAssertion:     "jwt-assertion-here",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	if receivedAssertion != "jwt-assertion-here" {
		t.Errorf("client_assertion: got %q", receivedAssertion)
	}
	if receivedAssertionType != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Errorf("client_assertion_type: got %q", receivedAssertionType)
	}
}
