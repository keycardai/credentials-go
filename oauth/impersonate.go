package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// SubstituteUserTokenType is the token type URN for Keycard impersonation subject tokens.
const SubstituteUserTokenType = "urn:keycard:params:oauth:token-type:substitute-user"

const substituteUserActorTokenType = "urn:ietf:params:oauth:token-type:access_token"

// substituteUserHeader is the fixed JWT header for substitute-user tokens.
type substituteUserHeader struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}

// substituteUserPayload is the JWT payload for substitute-user tokens.
type substituteUserPayload struct {
	Sub string `json:"sub"`
}

// ImpersonateRequest contains the inputs for an impersonation token exchange.
type ImpersonateRequest struct {
	// UserIdentifier is the target user; becomes sub in the issued token.
	UserIdentifier string
	// Resource is the target resource URI for the issued token. Optional.
	Resource string
	// Scopes are the scopes requested for the issued token. Optional.
	Scopes []string
}

// ImpersonateClientOption configures an ImpersonateClient.
type ImpersonateClientOption func(*impersonateConfig)

type impersonateConfig struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// WithImpersonateCredentials sets the client ID and secret for authenticating
// to the token endpoint.
func WithImpersonateCredentials(clientID, clientSecret string) ImpersonateClientOption {
	return func(cfg *impersonateConfig) {
		cfg.clientID = clientID
		cfg.clientSecret = clientSecret
	}
}

// WithImpersonateHTTPClient sets the HTTP client for all token requests.
func WithImpersonateHTTPClient(c *http.Client) ImpersonateClientOption {
	return func(cfg *impersonateConfig) {
		cfg.httpClient = c
	}
}

// ImpersonateClient performs Keycard impersonation token exchanges.
//
// It handles building the substitute-user subject token and obtaining the actor
// token from the configured application credential, so callers only need to
// supply the target user identifier, resource, and scopes.
type ImpersonateClient struct {
	cc *ClientCredentialsClient
	te *TokenExchangeClient
}

// NewImpersonateClient creates an ImpersonateClient for the given issuer.
func NewImpersonateClient(issuerURL string, opts ...ImpersonateClientOption) *ImpersonateClient {
	cfg := impersonateConfig{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	ccOpts := []ClientCredentialsClientOption{
		WithCCHTTPClient(cfg.httpClient),
	}
	teOpts := []TokenExchangeClientOption{
		WithTokenExchangeHTTPClient(cfg.httpClient),
	}
	if cfg.clientID != "" {
		ccOpts = append(ccOpts, WithCCBasicAuth(cfg.clientID, cfg.clientSecret))
		teOpts = append(teOpts, WithClientCredentials(cfg.clientID, cfg.clientSecret))
	}

	return &ImpersonateClient{
		cc: NewClientCredentialsClient(issuerURL, ccOpts...),
		te: NewTokenExchangeClient(issuerURL, teOpts...),
	}
}

// Impersonate exchanges the configured application credential for a token that
// acts on behalf of req.UserIdentifier. The actor identity comes from the
// credential configured at construction; callers do not pass it explicitly.
func (c *ImpersonateClient) Impersonate(ctx context.Context, req ImpersonateRequest) (*TokenResponse, error) {
	actorResp, err := c.cc.RequestToken(ctx, ClientCredentialsRequest{})
	if err != nil {
		return nil, err
	}

	return c.te.ExchangeToken(ctx, TokenExchangeRequest{
		SubjectToken:     buildSubstituteUserToken(req.UserIdentifier),
		SubjectTokenType: SubstituteUserTokenType,
		ActorToken:       actorResp.AccessToken,
		ActorTokenType:   substituteUserActorTokenType,
		Resource:         req.Resource,
		Scope:            strings.Join(req.Scopes, " "),
	})
}

// buildSubstituteUserToken constructs the unsigned JWT used as subject_token in
// Keycard impersonation exchanges. Format per the spec:
//
//	base64url({"typ":"vnd.kc.su+jwt","alg":"none"}).base64url({"sub":id}).
//
// The trailing dot is intentional — it marks the absent signature segment.
func buildSubstituteUserToken(userIdentifier string) string {
	header, _ := json.Marshal(substituteUserHeader{Typ: "vnd.kc.su+jwt", Alg: "none"})
	payload, _ := json.Marshal(substituteUserPayload{Sub: userIdentifier})
	return Base64URLEncode(header) + "." + Base64URLEncode(payload) + "."
}
