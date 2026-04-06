// Package mcpgo provides a complete MCP server with Keycard OAuth authentication,
// using [github.com/mark3labs/mcp-go] for MCP protocol transport (Streamable HTTP).
//
// This is one of two MCP server integrations provided by the Keycard Go SDK:
//   - mcpgo (this package) — uses the popular community [github.com/mark3labs/mcp-go] library
//   - [github.com/keycardai/credentials-go/mcpofficial] — uses the official [github.com/modelcontextprotocol/go-sdk]
//
// Both provide the same Keycard auth wiring. Choose based on your preferred MCP library.
//
// # Quick Start
//
//	import (
//	    "github.com/keycardai/credentials-go/mcpgo"
//	    mcpgotypes "github.com/mark3labs/mcp-go/mcp"
//	    "github.com/mark3labs/mcp-go/server"
//	)
//
//	s := server.NewMCPServer("My Server", "1.0.0")
//	s.AddTool(myTool, myHandler)
//
//	handler, err := mcpgo.NewHandler(s,
//	    mcpgo.WithZoneURL("https://my-zone.keycard.cloud"),
//	    mcpgo.WithResourceName("My Server"),
//	    mcpgo.WithScopes("mcp:tools"),
//	)
//
//	http.ListenAndServe(":8080", handler)
//
// Inside tool handlers, use [github.com/keycardai/credentials-go/mcp.AuthInfoFromContext]
// and [github.com/keycardai/credentials-go/mcp.AccessContextFromContext] to retrieve
// auth info and delegated tokens.
package mcpgo
