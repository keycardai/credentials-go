package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414).
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                     string   `json:"token_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// DiscoveryOption configures a metadata discovery request.
type DiscoveryOption func(*discoveryConfig)

type discoveryConfig struct {
	httpClient *http.Client
}

// WithDiscoveryHTTPClient sets the HTTP client used for discovery requests.
func WithDiscoveryHTTPClient(c *http.Client) DiscoveryOption {
	return func(cfg *discoveryConfig) {
		cfg.httpClient = c
	}
}

// FetchAuthorizationServerMetadata fetches OAuth authorization server metadata
// from the well-known endpoint for the given issuer (RFC 8414).
func FetchAuthorizationServerMetadata(ctx context.Context, issuer string, opts ...DiscoveryOption) (*AuthorizationServerMetadata, error) {
	cfg := &discoveryConfig{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	issuer = strings.TrimRight(issuer, "/")
	url := issuer + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching authorization server metadata from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Message: fmt.Sprintf("discovery endpoint returned HTTP %d for %s", resp.StatusCode, url),
			Status:  resp.StatusCode,
		}
	}

	var metadata AuthorizationServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding authorization server metadata: %w", err)
	}

	return &metadata, nil
}
