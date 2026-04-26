package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// ClientCredentialsRequest represents an RFC 6749 Section 4.4 client credentials request.
type ClientCredentialsRequest struct {
	Resource            string
	Scope               string
	ClientAssertion     string
	ClientAssertionType string
}

// ClientCredentialsClientOption configures a ClientCredentialsClient.
type ClientCredentialsClientOption func(*clientCredentialsConfig)

type clientCredentialsConfig struct {
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// WithCCBasicAuth sets the client ID and secret for HTTP basic auth.
func WithCCBasicAuth(clientID, clientSecret string) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) {
		cfg.clientID = clientID
		cfg.clientSecret = clientSecret
	}
}

// WithCCHTTPClient sets the HTTP client for client credentials requests.
func WithCCHTTPClient(c *http.Client) ClientCredentialsClientOption {
	return func(cfg *clientCredentialsConfig) {
		cfg.httpClient = c
	}
}

// ClientCredentialsClient performs RFC 6749 Section 4.4 client credentials grants
// against an OAuth authorization server. It lazily discovers the token endpoint
// via OAuth metadata.
type ClientCredentialsClient struct {
	issuerURL string
	cfg       clientCredentialsConfig

	once          sync.Once
	tokenEndpoint string
	discoverErr   error
}

// NewClientCredentialsClient creates a new ClientCredentialsClient for the given issuer.
func NewClientCredentialsClient(issuerURL string, opts ...ClientCredentialsClientOption) *ClientCredentialsClient {
	cfg := clientCredentialsConfig{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &ClientCredentialsClient{
		issuerURL: issuerURL,
		cfg:       cfg,
	}
}

// TokenEndpoint returns the discovered token endpoint URL.
// It triggers lazy metadata discovery if not already done.
func (c *ClientCredentialsClient) TokenEndpoint(ctx context.Context) (string, error) {
	return c.getTokenEndpoint(ctx)
}

// RequestToken performs a client credentials grant request.
func (c *ClientCredentialsClient) RequestToken(ctx context.Context, req ClientCredentialsRequest) (*TokenResponse, error) {
	tokenEndpoint, err := c.getTokenEndpoint(ctx)
	if err != nil {
		return nil, err
	}

	body := serializeClientCredentialsRequest(req)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating client credentials request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if c.cfg.clientID != "" && c.cfg.clientSecret != "" {
		httpReq.SetBasicAuth(c.cfg.clientID, c.cfg.clientSecret)
	}

	resp, err := c.cfg.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("client credentials request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errBody map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&errBody); err == nil {
			if errCode, ok := errBody["error"].(string); ok {
				oauthErr := &OAuthError{
					ErrorCode: errCode,
				}
				if desc, ok := errBody["error_description"].(string); ok {
					oauthErr.Message = desc
				} else {
					oauthErr.Message = errCode
				}
				if uri, ok := errBody["error_uri"].(string); ok {
					oauthErr.ErrorURI = uri
				}
				return nil, oauthErr
			}
		}
		return nil, fmt.Errorf("client credentials request failed (HTTP %d)", resp.StatusCode)
	}

	return deserializeTokenResponse(resp)
}

func (c *ClientCredentialsClient) getTokenEndpoint(ctx context.Context) (string, error) {
	c.once.Do(func() {
		metadata, err := FetchAuthorizationServerMetadata(ctx, c.issuerURL,
			WithDiscoveryHTTPClient(c.cfg.httpClient))
		if err != nil {
			c.discoverErr = fmt.Errorf("discovering token endpoint: %w", err)
			return
		}
		if metadata.TokenEndpoint == "" {
			c.discoverErr = fmt.Errorf("authorization server %q does not advertise a token_endpoint", c.issuerURL)
			return
		}
		c.tokenEndpoint = metadata.TokenEndpoint
	})

	return c.tokenEndpoint, c.discoverErr
}

func serializeClientCredentialsRequest(req ClientCredentialsRequest) url.Values {
	params := url.Values{}
	params.Set("grant_type", "client_credentials")

	if req.Resource != "" {
		params.Set("resource", req.Resource)
	}
	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}
	if req.ClientAssertion != "" {
		params.Set("client_assertion", req.ClientAssertion)
	}
	if req.ClientAssertionType != "" {
		params.Set("client_assertion_type", req.ClientAssertionType)
	}

	return params
}
