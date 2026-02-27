// Package keycardai provides the Keycard Go SDK for OAuth 2.0 and MCP authentication.
//
// The SDK is organized into two sub-packages:
//
//   - [github.com/keycardai/credentials-go/oauth] — Pure OAuth 2.0 primitives: JWT signing/verification,
//     JWKS key discovery with caching, RFC 8693 token exchange, and OAuth server metadata discovery.
//
//   - [github.com/keycardai/credentials-go/mcp] — MCP-specific OAuth integration: bearer auth middleware,
//     token exchange orchestration (AuthProvider), application credentials, and well-known metadata endpoints.
//
// Import the sub-package you need:
//
//	import "github.com/keycardai/credentials-go/oauth"  // OAuth primitives only
//	import "github.com/keycardai/credentials-go/mcp"    // MCP integration (includes oauth)
package keycardai
