package oauth

import (
	"strings"
	"testing"
)

func TestGenerateCodeVerifier(t *testing.T) {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

	v, err := GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier: %v", err)
	}
	if len(v) < 43 || len(v) > 128 {
		t.Errorf("verifier length %d outside RFC 7636 range 43-128", len(v))
	}
	for _, c := range v {
		if !strings.ContainsRune(unreserved, c) {
			t.Errorf("verifier contains non-unreserved character %q", c)
		}
	}

	// Two verifiers should differ.
	v2, _ := GenerateCodeVerifier()
	if v == v2 {
		t.Error("two generated verifiers were identical")
	}
}

func TestGenerateCodeChallenge_S256(t *testing.T) {
	// RFC 7636 Appendix B known-answer vector.
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	got, err := GenerateCodeChallenge(verifier, PKCEMethodS256)
	if err != nil {
		t.Fatalf("GenerateCodeChallenge: %v", err)
	}
	if got != challenge {
		t.Errorf("S256 challenge: got %q, want %q", got, challenge)
	}
}

func TestGenerateCodeChallenge_Plain(t *testing.T) {
	got, err := GenerateCodeChallenge("verifier-value", PKCEMethodPlain)
	if err != nil {
		t.Fatalf("GenerateCodeChallenge: %v", err)
	}
	if got != "verifier-value" {
		t.Errorf("plain challenge: got %q, want the verifier unchanged", got)
	}
}

func TestGenerateCodeChallenge_Unsupported(t *testing.T) {
	if _, err := GenerateCodeChallenge("v", "RS256"); err == nil {
		t.Error("expected error for an unsupported PKCE method")
	}
}

func TestGeneratePKCEPair(t *testing.T) {
	pair, err := GeneratePKCEPair()
	if err != nil {
		t.Fatalf("GeneratePKCEPair: %v", err)
	}
	if pair.CodeChallengeMethod != PKCEMethodS256 {
		t.Errorf("method: got %q, want S256", pair.CodeChallengeMethod)
	}
	want, _ := GenerateCodeChallenge(pair.CodeVerifier, PKCEMethodS256)
	if pair.CodeChallenge != want {
		t.Errorf("challenge does not match S256(verifier): got %q, want %q", pair.CodeChallenge, want)
	}
}
