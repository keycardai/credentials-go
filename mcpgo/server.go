package mcpgo

import (
	"log"
	"net/http"

	"github.com/keycardai/credentials-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Option configures the MCP server handler.
type Option func(*config)

type config struct {
	zoneURL      string
	resourceName string
	scopes       []string
	mcpPath      string

	// Delegated access
	clientID     string
	clientSecret string
	grants       []string
}

// WithZoneURL sets the Keycard zone URL (e.g., "https://my-zone.keycard.cloud").
func WithZoneURL(url string) Option {
	return func(c *config) { c.zoneURL = url }
}

// WithResourceName sets the human-readable name for this MCP server in OAuth metadata.
func WithResourceName(name string) Option {
	return func(c *config) { c.resourceName = name }
}

// WithScopes sets the OAuth scopes required to access this MCP server.
func WithScopes(scopes ...string) Option {
	return func(c *config) { c.scopes = scopes }
}

// WithMCPPath sets the path for the MCP endpoint. Default: "/mcp".
func WithMCPPath(path string) Option {
	return func(c *config) { c.mcpPath = path }
}

// WithClientCredentials sets the application credentials for delegated access (token exchange).
// Use together with WithGrant to enable calling external APIs on behalf of users.
func WithClientCredentials(clientID, clientSecret string) Option {
	return func(c *config) {
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// WithGrant adds resource URLs for delegated access via token exchange.
// Requires WithClientCredentials. The exchanged tokens are available in tool handlers
// via mcp.AccessContextFromContext(ctx).
func WithGrant(resources ...string) Option {
	return func(c *config) { c.grants = append(c.grants, resources...) }
}

// NewHandler creates an http.Handler that serves a complete MCP server with Keycard OAuth.
//
// The returned handler serves:
//   - /.well-known/* — OAuth metadata endpoints
//   - /mcp (or custom path) — MCP Streamable HTTP transport, protected by bearer auth
//
// The mcpServer should be created and configured with tools using the mcp-go library.
func NewHandler(mcpServer *server.MCPServer, opts ...Option) (http.Handler, error) {
	cfg := config{
		mcpPath: "/mcp",
		scopes:  []string{"mcp:tools"},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	mux := http.NewServeMux()

	// OAuth metadata endpoints
	var metadataOpts []mcp.MetadataOption
	if cfg.zoneURL != "" {
		metadataOpts = append(metadataOpts, mcp.WithIssuer(cfg.zoneURL))
	}
	if len(cfg.scopes) > 0 {
		metadataOpts = append(metadataOpts, mcp.WithScopesSupported(cfg.scopes))
	}
	if cfg.resourceName != "" {
		metadataOpts = append(metadataOpts, mcp.WithResourceName(cfg.resourceName))
	}
	mux.Handle("/.well-known/", mcp.AuthMetadataHandler(metadataOpts...))

	// MCP transport handler
	mcpHandler := server.NewStreamableHTTPServer(mcpServer)

	// Bearer auth middleware
	var bearerOpts []mcp.BearerAuthOption
	if len(cfg.scopes) > 0 {
		bearerOpts = append(bearerOpts, mcp.WithRequiredScopes(cfg.scopes...))
	}
	protectedHandler := mcp.RequireBearerAuth(bearerOpts...)(mcpHandler)

	// Optional delegated access middleware
	if cfg.clientID != "" && cfg.clientSecret != "" && len(cfg.grants) > 0 {
		authProvider, err := mcp.NewAuthProvider(
			mcp.WithZoneURL(cfg.zoneURL),
			mcp.WithApplicationCredential(
				mcp.NewClientSecret(cfg.clientID, cfg.clientSecret),
			),
		)
		if err != nil {
			return nil, err
		}
		protectedHandler = mcp.RequireBearerAuth(bearerOpts...)(
			authProvider.Grant(cfg.grants...)(mcpHandler),
		)
	}

	mux.Handle(cfg.mcpPath, protectedHandler)

	return mux, nil
}

// ListenAndServe starts an MCP server on the given address.
// This is a convenience wrapper around NewHandler and http.ListenAndServe.
func ListenAndServe(addr string, mcpServer *server.MCPServer, opts ...Option) error {
	handler, err := NewHandler(mcpServer, opts...)
	if err != nil {
		return err
	}
	log.Printf("MCP server listening on %s", addr)
	return http.ListenAndServe(addr, handler)
}
