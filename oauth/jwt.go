package oauth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultLeeway is the default time leeway used when validating
// token temporal claims (exp, nbf, iat).
const DefaultLeeway = 60 * time.Second

// JWTClaims represents standard JWT claims with optional extra fields.
type JWTClaims struct {
	Issuer   string   `json:"iss,omitempty"`
	Subject  string   `json:"sub,omitempty"`
	Audience []string `json:"aud,omitempty"`
	Expiry   int64    `json:"exp,omitempty"`
	NotBefore int64   `json:"nbf,omitempty"`
	IssuedAt int64    `json:"iat,omitempty"`
	JWTID    string   `json:"jti,omitempty"`
	Scope    string   `json:"scope,omitempty"`
	ClientID string   `json:"client_id,omitempty"`

	// Extra holds additional claims not covered by the standard fields.
	Extra map[string]any `json:"-"`
}

// GetExpirationTime implements jwt.Claims.
func (c JWTClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.Expiry == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.Expiry, 0)), nil
}

// GetIssuedAt implements jwt.Claims.
func (c JWTClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims.
func (c JWTClaims) GetNotBefore() (*jwt.NumericDate, error) {
	if c.NotBefore == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.NotBefore, 0)), nil
}

// GetIssuer implements jwt.Claims.
func (c JWTClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims.
func (c JWTClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims.
func (c JWTClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings(c.Audience), nil
}

// jwtClaimsForSigning builds a jwt.MapClaims from JWTClaims for signing.
func jwtClaimsForSigning(c JWTClaims) jwt.MapClaims {
	m := jwt.MapClaims{}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if len(c.Audience) == 1 {
		m["aud"] = c.Audience[0]
	} else if len(c.Audience) > 1 {
		m["aud"] = c.Audience
	}
	if c.Expiry != 0 {
		m["exp"] = c.Expiry
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.JWTID != "" {
		m["jti"] = c.JWTID
	}
	if c.Scope != "" {
		m["scope"] = c.Scope
	}
	if c.ClientID != "" {
		m["client_id"] = c.ClientID
	}
	for k, v := range c.Extra {
		m[k] = v
	}
	return m
}

// jwtClaimsFromMap parses a jwt.MapClaims into JWTClaims.
func jwtClaimsFromMap(m jwt.MapClaims) *JWTClaims {
	c := &JWTClaims{Extra: make(map[string]any)}

	if v, ok := m["iss"].(string); ok {
		c.Issuer = v
	}
	if v, ok := m["sub"].(string); ok {
		c.Subject = v
	}
	if v, ok := m["aud"]; ok {
		switch aud := v.(type) {
		case string:
			c.Audience = []string{aud}
		case []any:
			for _, a := range aud {
				if s, ok := a.(string); ok {
					c.Audience = append(c.Audience, s)
				}
			}
		}
	}
	if v, ok := m["exp"].(float64); ok {
		c.Expiry = int64(v)
	}
	if v, ok := m["nbf"].(float64); ok {
		c.NotBefore = int64(v)
	}
	if v, ok := m["iat"].(float64); ok {
		c.IssuedAt = int64(v)
	}
	if v, ok := m["jti"].(string); ok {
		c.JWTID = v
	}
	if v, ok := m["scope"].(string); ok {
		c.Scope = v
	}
	if v, ok := m["client_id"].(string); ok {
		c.ClientID = v
	}

	// Collect extra claims
	standard := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true,
		"nbf": true, "iat": true, "jti": true, "scope": true, "client_id": true,
	}
	for k, v := range m {
		if !standard[k] {
			c.Extra[k] = v
		}
	}
	if len(c.Extra) == 0 {
		c.Extra = nil
	}

	return c
}

// signingMethodForKey returns the appropriate JWT signing method for a private key.
func signingMethodForKey(key crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return jwt.SigningMethodRS256, nil
	case *ecdsa.PrivateKey:
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported key type %T", key)
	}
}

// JWTSigner signs JWTs using a PrivateKeyring.
type JWTSigner struct {
	keyring PrivateKeyring
}

// NewJWTSigner creates a new JWTSigner with the given private keyring.
func NewJWTSigner(keyring PrivateKeyring) *JWTSigner {
	return &JWTSigner{keyring: keyring}
}

// Sign produces a signed JWT string from the given claims.
// If the claims do not include an issuer, the issuer from the keyring is used.
func (s *JWTSigner) Sign(ctx context.Context, claims JWTClaims) (string, error) {
	ik, err := s.keyring.Key(ctx, "sign")
	if err != nil {
		return "", fmt.Errorf("retrieving signing key: %w", err)
	}

	method, err := signingMethodForKey(ik.Key)
	if err != nil {
		return "", err
	}

	if ik.Issuer != "" && claims.Issuer == "" {
		claims.Issuer = ik.Issuer
	}

	mapClaims := jwtClaimsForSigning(claims)
	token := jwt.NewWithClaims(method, mapClaims)
	token.Header["kid"] = ik.KID

	signed, err := token.SignedString(ik.Key)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signed, nil
}

// JWTVerifierOption configures a JWTVerifier.
type JWTVerifierOption func(*JWTVerifier)

// WithVerifierLeeway sets the time leeway for validating exp, nbf, and iat claims.
// Default is DefaultLeeway (60s).
func WithVerifierLeeway(d time.Duration) JWTVerifierOption {
	return func(v *JWTVerifier) { v.leeway = d }
}

// JWTVerifier verifies JWT signatures and validates claims using an OAuthKeyring.
type JWTVerifier struct {
	keyring OAuthKeyring
	leeway  time.Duration
}

// NewJWTVerifier creates a new JWTVerifier with the given public keyring.
func NewJWTVerifier(keyring OAuthKeyring, opts ...JWTVerifierOption) *JWTVerifier {
	v := &JWTVerifier{keyring: keyring, leeway: DefaultLeeway}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Verify parses and verifies a JWT, returning the claims.
// Returns InvalidTokenError if the token is malformed or the signature is invalid.
func (v *JWTVerifier) Verify(ctx context.Context, tokenString string) (*JWTClaims, error) {
	// Parse without verification first to extract header claims
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("malformed JWT: %v", err)}
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &InvalidTokenError{Message: "invalid JWT claims"}
	}

	issuer, _ := mapClaims["iss"].(string)
	if issuer == "" {
		return nil, &InvalidTokenError{Message: "JWT missing issuer (iss) claim"}
	}

	kid, _ := token.Header["kid"].(string)

	publicKey, err := v.keyring.Key(ctx, issuer, kid)
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("failed to resolve key: %v", err)}
	}

	// Re-parse with signature verification and claims validation (exp, nbf, iat).
	verifiedToken, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithLeeway(v.leeway))
	if err != nil {
		return nil, &InvalidTokenError{Message: fmt.Sprintf("JWT verification failed: %v", err)}
	}

	verifiedClaims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, &InvalidTokenError{Message: "invalid JWT claims"}
	}

	return jwtClaimsFromMap(verifiedClaims), nil
}
