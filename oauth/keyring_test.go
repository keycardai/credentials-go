package oauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJWKSOAuthKeyring_Key(t *testing.T) {
	// Generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
						"alg": "RS256",
						"use": "sig",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   r.URL.Query().Get("issuer"),
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Minute),
		WithDiscoveryTTL(1*time.Minute),
		WithFetchTimeout(5*time.Second),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	key, err := keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("resolving key: %v", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}

	if rsaKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		t.Error("public key modulus mismatch")
	}
}

func TestJWKSOAuthKeyring_KeyNotFound(t *testing.T) {
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			jwks := map[string]any{"keys": []map[string]any{}}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	_, err := keyring.Key(context.Background(), jwksServer.URL, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

func TestJWKSOAuthKeyring_CachesKeys(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetchCount := 0

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			fetchCount++
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Hour),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	// First call
	_, err := keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Second call should use cache
	_, err = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("JWKS should be fetched once (cached), got %d fetches", fetchCount)
	}
}

func TestJWKSOAuthKeyring_Invalidate(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	fetchCount := 0

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			fetchCount++
			jwks := map[string]any{
				"keys": []map[string]any{
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"n":   Base64URLEncode(privateKey.PublicKey.N.Bytes()),
						"e":   Base64URLEncode(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(jwks)
		} else if r.URL.Path == "/.well-known/oauth-authorization-server" {
			metadata := map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/.well-known/jwks.json",
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		}
	}))
	defer jwksServer.Close()

	keyring := NewJWKSOAuthKeyring(
		WithKeyTTL(1*time.Hour),
		WithKeyringHTTPClient(jwksServer.Client()),
	)

	_, _ = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")
	keyring.Invalidate(jwksServer.URL, "test-key-1")
	_, _ = keyring.Key(context.Background(), jwksServer.URL, "test-key-1")

	if fetchCount != 2 {
		t.Errorf("JWKS should be fetched twice after invalidation, got %d", fetchCount)
	}
}

func TestAssertSameOrigin(t *testing.T) {
	tests := []struct {
		name    string
		issuer  string
		jwksURI string
		wantErr bool
	}{
		{"same origin", "https://auth.example.com", "https://auth.example.com/.well-known/jwks.json", false},
		{"different host", "https://auth.example.com", "https://evil.example.com/jwks.json", true},
		{"different scheme", "https://auth.example.com", "http://auth.example.com/jwks.json", true},
		{"different port", "https://auth.example.com:8443", "https://auth.example.com:9443/jwks.json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := assertSameOrigin(tt.issuer, tt.jwksURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("assertSameOrigin(%q, %q) error = %v, wantErr %v", tt.issuer, tt.jwksURI, err, tt.wantErr)
			}
		})
	}
}
