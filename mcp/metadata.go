package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ProtectedResourceMetadata represents OAuth Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	Resource              string   `json:"resource"`
	AuthorizationServers  []string `json:"authorization_servers,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
	ResourceName          string   `json:"resource_name,omitempty"`
	ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}

// MetadataOption configures auth metadata handlers.
type MetadataOption func(*metadataConfig)

type metadataConfig struct {
	issuer                string
	scopesSupported       []string
	resourceName          string
	resourceDocumentation string
	httpClient            *http.Client
}

// WithIssuer sets the authorization server issuer URL.
func WithIssuer(issuer string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.issuer = issuer }
}

// WithScopesSupported sets the scopes supported by the protected resource.
func WithScopesSupported(scopes []string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.scopesSupported = scopes }
}

// WithResourceName sets the human-readable name of the protected resource.
func WithResourceName(name string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.resourceName = name }
}

// WithServiceDocumentationURL sets the URL for the service documentation.
func WithServiceDocumentationURL(docURL string) MetadataOption {
	return func(cfg *metadataConfig) { cfg.resourceDocumentation = docURL }
}

// WithMetadataHTTPClient sets the HTTP client used to fetch upstream authorization server metadata.
func WithMetadataHTTPClient(c *http.Client) MetadataOption {
	return func(cfg *metadataConfig) { cfg.httpClient = c }
}

// AuthMetadataHandler returns an http.Handler that serves both
// /.well-known/oauth-protected-resource and /.well-known/oauth-authorization-server endpoints.
func AuthMetadataHandler(opts ...MetadataOption) http.Handler {
	cfg := metadataConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)

		scheme := requestScheme(r)
		baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

		path := r.URL.Path
		if path == "/.well-known/oauth-protected-resource" {
			path = ""
		}
		resource := baseURL + path

		metadata := ProtectedResourceMetadata{
			Resource:              resource,
			ScopesSupported:       cfg.scopesSupported,
			ResourceName:          cfg.resourceName,
			ResourceDocumentation: cfg.resourceDocumentation,
		}

		// Handle MCP protocol version for backward compatibility
		mcpVersion := r.Header.Get("MCP-Protocol-Version")
		if mcpVersion == "2025-03-26" {
			metadata.AuthorizationServers = []string{baseURL}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	})

	if cfg.issuer != "" {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
			setCORSHeaders(w)

			scheme := requestScheme(r)
			baseURL := fmt.Sprintf("%s://%s", scheme, r.Host)

			// Fetch upstream authorization server metadata
			issuerMetadataURL := cfg.issuer + "/.well-known/oauth-authorization-server"
			fetchReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, issuerMetadataURL, nil)
			if err != nil {
				http.Error(w, "failed to create metadata request", http.StatusInternalServerError)
				return
			}
			fetchReq.Header.Set("Accept", "application/json")

			resp, err := cfg.httpClient.Do(fetchReq)
			if err != nil {
				http.Error(w, "failed to fetch authorization server metadata", http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				http.Error(w, fmt.Sprintf("authorization server returned HTTP %d", resp.StatusCode), http.StatusBadGateway)
				return
			}

			var metadata map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
				http.Error(w, "failed to decode authorization server metadata", http.StatusBadGateway)
				return
			}

			// Rewrite authorization_endpoint to include resource parameter
			if authEndpoint, ok := metadata["authorization_endpoint"].(string); ok {
				authURL, err := url.Parse(authEndpoint)
				if err == nil {
					q := authURL.Query()
					q.Set("resource", baseURL)
					authURL.RawQuery = q.Encode()
					metadata["authorization_endpoint"] = authURL.String()
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(metadata)
		})
	}

	// Handle CORS preflight
	mux.HandleFunc("OPTIONS /.well-known/", func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w)
		w.WriteHeader(http.StatusNoContent)
	})

	return mux
}

func setCORSHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, MCP-Protocol-Version")
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		return fwd
	}
	return "http"
}
