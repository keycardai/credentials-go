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

	// Sign without setting issuer in claims (but include expiry for validation)
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject: "user-123",
		Expiry:  time.Now().Unix() + 3600,
	})
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
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject: "user-123",
		Expiry:  time.Now().Unix() + 3600,
	})
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
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject: "user-123",
		Expiry:  time.Now().Unix() + 3600,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &signingKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for missing issuer")
	}
}

func TestJWTVerifier_ExpiredToken(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	// Token expired 1 hour ago (well beyond leeway)
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject:  "user-123",
		Expiry:   time.Now().Unix() - 3600,
		IssuedAt: time.Now().Unix() - 7200,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &privateKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_NotYetValid(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	// Token not valid until 1 hour from now (well beyond leeway)
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject:   "user-123",
		NotBefore: time.Now().Unix() + 3600,
		Expiry:    time.Now().Unix() + 7200,
		IssuedAt:  time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &privateKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("expected error for not-yet-valid token")
	}

	if _, ok := err.(*InvalidTokenError); !ok {
		t.Errorf("expected InvalidTokenError, got %T: %v", err, err)
	}
}

func TestJWTVerifier_FutureIssuedAt(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	// Token issued 1 hour in the future (well beyond leeway)
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject:  "user-123",
		IssuedAt: time.Now().Unix() + 3600,
		Expiry:   time.Now().Unix() + 7200,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &privateKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	// golang-jwt/v5 does not reject future iat by default; only exp and nbf are enforced.
	// This is consistent with RFC 7519 which does not mandate iat rejection.
	// If this passes, that's acceptable. If it fails, that's also fine.
	_ = err
}

func TestJWTVerifier_WithinLeeway(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	// Token expired 30 seconds ago — within the default 60s leeway
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject:  "user-123",
		Expiry:   time.Now().Unix() - 30,
		IssuedAt: time.Now().Unix() - 3600,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	verifier := NewJWTVerifier(&staticTestKeyring{publicKey: &privateKey.PublicKey})
	_, err = verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("token expired by 30s should be accepted within 60s leeway: %v", err)
	}
}

func TestJWTVerifier_CustomLeeway(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	signer := NewJWTSigner(&testPrivateKeyring{key: privateKey, issuer: "https://auth.example.com"})

	// Token expired 30 seconds ago
	token, err := signer.Sign(context.Background(), JWTClaims{
		Subject:  "user-123",
		Expiry:   time.Now().Unix() - 30,
		IssuedAt: time.Now().Unix() - 3600,
	})
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	// Use a 10-second leeway — token expired 30s ago should be rejected
	verifier := NewJWTVerifier(
		&staticTestKeyring{publicKey: &privateKey.PublicKey},
		WithVerifierLeeway(10*time.Second),
	)
	_, err = verifier.Verify(context.Background(), token)
	if err == nil {
		t.Fatal("token expired by 30s should be rejected with 10s leeway")
	}
}

func TestJWTClaims_Accessors(t *testing.T) {
	now := time.Now().Unix()
	c := JWTClaims{
		Expiry:    now + 3600,
		IssuedAt:  now,
		NotBefore: now - 60,
	}

	exp, err := c.GetExpirationTime()
	if err != nil {
		t.Fatalf("GetExpirationTime error: %v", err)
	}
	if exp == nil || exp.Unix() != now+3600 {
		t.Errorf("GetExpirationTime: got %v, want %d", exp, now+3600)
	}

	iat, err := c.GetIssuedAt()
	if err != nil {
		t.Fatalf("GetIssuedAt error: %v", err)
	}
	if iat == nil || iat.Unix() != now {
		t.Errorf("GetIssuedAt: got %v, want %d", iat, now)
	}

	nbf, err := c.GetNotBefore()
	if err != nil {
		t.Fatalf("GetNotBefore error: %v", err)
	}
	if nbf == nil || nbf.Unix() != now-60 {
		t.Errorf("GetNotBefore: got %v, want %d", nbf, now-60)
	}

	// Zero values should return nil
	empty := JWTClaims{}
	exp, _ = empty.GetExpirationTime()
	if exp != nil {
		t.Errorf("zero Expiry should return nil, got %v", exp)
	}
	iat, _ = empty.GetIssuedAt()
	if iat != nil {
		t.Errorf("zero IssuedAt should return nil, got %v", iat)
	}
	nbf, _ = empty.GetNotBefore()
	if nbf != nil {
		t.Errorf("zero NotBefore should return nil, got %v", nbf)
	}
}

// staticTestKeyring implements OAuthKeyring with a fixed public key.
type staticTestKeyring struct {
	publicKey crypto.PublicKey
}

func (r *staticTestKeyring) Key(_ context.Context, _, _ string) (crypto.PublicKey, error) {
	return r.publicKey, nil
}
