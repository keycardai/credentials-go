package oauth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

type testPrivateKeyring struct {
	key    *rsa.PrivateKey
	issuer string
}

func (r *testPrivateKeyring) Key(_ context.Context, _ string) (IdentifiableKey, error) {
	return IdentifiableKey{
		Key:    r.key,
		Issuer: r.issuer,
		KID:    "test-key-1",
	}, nil
}

func TestJWTSignAndVerify(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	now := time.Now().Unix()
	claims := JWTClaims{
		Subject:  "user-123",
		Audience: []string{"https://api.example.com"},
		Expiry:   now + 3600,
		IssuedAt: now,
		Scope:    "read write",
		ClientID: "client-456",
	}

	token, err := signer.Sign(context.Background(), claims)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	if token == "" {
		t.Fatal("token should not be empty")
	}

	// Verify with a keyring that returns the public key
	keyring := &staticTestKeyring{publicKey: &privateKey.PublicKey}
	verifier := NewJWTVerifier(keyring)

	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	if verified.Issuer != "https://auth.example.com" {
		t.Errorf("issuer: got %q, want %q", verified.Issuer, "https://auth.example.com")
	}
	if verified.Subject != "user-123" {
		t.Errorf("subject: got %q, want %q", verified.Subject, "user-123")
	}
	if verified.Scope != "read write" {
		t.Errorf("scope: got %q, want %q", verified.Scope, "read write")
	}
	if verified.ClientID != "client-456" {
		t.Errorf("client_id: got %q, want %q", verified.ClientID, "client-456")
	}
}

func TestJWTSignerSetsIssuerFromKeyring(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auto-issuer.example.com"})

	// Sign without setting issuer in claims
	token, err := signer.Sign(context.Background(), JWTClaims{Subject: "user-123"})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &privateKey.PublicKey})
	verified, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verifying: %v", err)
	}

	if verified.Issuer != "https://auto-issuer.example.com" {
		t.Errorf("issuer should be set from keyring: got %q", verified.Issuer)
	}
}

func TestJWTVerifier_InvalidSignature(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: "https://auth.example.com"})
	token, err := signer.Sign(context.Background(), JWTClaims{Subject: "user-123"})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &wrongKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_MissingIssuer(t *testing.T) {
	signingKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create a token without an issuer
	signer := NewJWTSigner(&testPrivateKeyring{key: signingKey, issuer: ""})
	token, err := signer.Sign(context.Background(), JWTClaims{Subject: "user-123"})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &signingKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

// staticTestKeyring implements OAuthKeyring with a fixed public key.
type staticTestKeyring struct {
	publicKey crypto.PublicKey
}

func (r *staticTestKeyring) Key(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return r.publicKey, nil
}
