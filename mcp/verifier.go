package mcp

import (
	"context"

	"github.com/keycardai/credentials-go/oauth"
)

// AuthInfo contains information about an authenticated request.
type AuthInfo struct {
	Token     string
	ClientID  string
	Scopes    []string
	Resource  string
	ExpiresAt int64
}

// TokenVerifier verifies access tokens and returns auth information.
type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, token string) (*AuthInfo, error)
}

// JWTOAuthTokenVerifier implements TokenVerifier using JWT verification with JWKS.
type JWTOAuthTokenVerifier struct {
	verifier *oauth.JWTVerifier
}

// NewJWTOAuthTokenVerifier creates a new JWTOAuthTokenVerifier with the given keyring.
func NewJWTOAuthTokenVerifier(keyring oauth.OAuthKeyring) *JWTOAuthTokenVerifier {
	return &JWTOAuthTokenVerifier{
		verifier: oauth.NewJWTVerifier(keyring),
	}
}

// VerifyAccessToken verifies a JWT access token and returns auth information.
func (v *JWTOAuthTokenVerifier) VerifyAccessToken(ctx context.Context, token string) (*AuthInfo, error) {
	claims, err := v.verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	info := &AuthInfo{
		Token:    token,
		ClientID: claims.ClientID,
		Scopes:   parseScopes(claims.Scope),
	}

	if claims.Expiry != 0 {
		info.ExpiresAt = claims.Expiry
	}

	if sub, ok := claims.Extra["resource"].(string); ok {
		info.Resource = sub
	}

	if info.ClientID == "" {
		info.ClientID = claims.Subject
	}

	return info, nil
}

func parseScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	var scopes []string
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if i > start {
				scopes = append(scopes, scope[start:i])
			}
			start = i + 1
		}
	}
	return scopes
}
