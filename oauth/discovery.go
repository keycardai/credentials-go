package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	// Extra holds any fields beyond the standard set, preserved for forward compatibility.
	Extra map[string]any `json:"-"`
}

// knownASMetadataFields are the JSON names mapped to typed fields above; anything else
// in a discovery response is preserved in AuthorizationServerMetadata.Extra.
var knownASMetadataFields = []string{
	"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri",
	"registration_endpoint", "scopes_supported", "response_types_supported",
	"grant_types_supported", "token_endpoint_auth_methods_supported",
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

	// Read the body once so we can decode the typed fields and also capture any
	// unknown ones for forward compatibility.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading authorization server metadata: %w", err)
	}

	var metadata AuthorizationServerMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("decoding authorization server metadata: %w", err)
	}

	// Validate the response issuer matches the requested issuer (RFC 8414 section 3.3),
	// ignoring a trailing slash.
	if strings.TrimRight(metadata.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, &IssuerMismatchError{
			Message: fmt.Sprintf("authorization server issuer %q does not match requested issuer %q", metadata.Issuer, issuer),
		}
	}

	// Preserve fields beyond the standard set.
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err == nil {
		for _, known := range knownASMetadataFields {
			delete(all, known)
		}
		if len(all) > 0 {
			metadata.Extra = make(map[string]any, len(all))
			for k, v := range all {
				var val any
				if err := json.Unmarshal(v, &val); err == nil {
					metadata.Extra[k] = val
				}
			}
		}
	}

	return &metadata, nil
}
