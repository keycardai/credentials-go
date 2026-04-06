// Package mcpserver provides a complete MCP server with Keycard OAuth authentication.
//
// It combines [github.com/mark3labs/mcp-go] for MCP protocol transport (Streamable HTTP)
// with [github.com/keycardai/credentials-go/mcp] for OAuth bearer authentication,
// metadata endpoints, and delegated access via token exchange.
//
// # Quick Start
//
//	import (
//	    "github.com/keycardai/credentials-go/mcpserver"
//	    mcpgo "github.com/mark3labs/mcp-go/mcp"
//	    "github.com/mark3labs/mcp-go/server"
//	)
//
//	s := server.NewMCPServer("My Server", "1.0.0")
//	s.AddTool(myTool, myHandler)
//
//	handler, err := mcpserver.NewHandler(s,
//	    mcpserver.WithZoneURL("https://my-zone.keycard.cloud"),
//	    mcpserver.WithResourceName("My Server"),
//	    mcpserver.WithScopes("mcp:tools"),
//	)
//
//	http.ListenAndServe(":8080", handler)
//
// The returned handler serves:
//   - GET /.well-known/oauth-protected-resource — OAuth resource metadata
//   - GET /.well-known/oauth-authorization-server — Authorization server metadata
//   - POST /mcp — MCP Streamable HTTP transport (protected by bearer auth)
//   - GET /mcp — MCP Streamable HTTP transport (protected by bearer auth)
//   - DELETE /mcp — MCP session cleanup
//
// # Delegated Access
//
// To call external APIs on behalf of authenticated users, provide application credentials:
//
//	handler, err := mcpserver.NewHandler(s,
//	    mcpserver.WithZoneURL(zoneURL),
//	    mcpserver.WithResourceName("GitHub Server"),
//	    mcpserver.WithScopes("mcp:tools"),
//	    mcpserver.WithClientCredentials(clientID, clientSecret),
//	    mcpserver.WithGrant("https://api.github.com"),
//	)
//
// Inside tool handlers, use [github.com/keycardai/credentials-go/mcp.AuthInfoFromContext]
// and [github.com/keycardai/credentials-go/mcp.AccessContextFromContext] to retrieve
// auth info and delegated tokens.
package mcpserver
