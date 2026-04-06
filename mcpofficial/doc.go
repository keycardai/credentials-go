// Package mcpofficial provides a complete MCP server with Keycard OAuth authentication,
// using the official [github.com/modelcontextprotocol/go-sdk] for MCP protocol transport.
//
// This is one of two MCP server integrations provided by the Keycard Go SDK:
//   - [github.com/keycardai/credentials-go/mcpgo] — uses the popular community [github.com/mark3labs/mcp-go] library
//   - mcpofficial (this package) — uses the official [github.com/modelcontextprotocol/go-sdk]
//
// Both provide the same Keycard auth wiring. Choose based on your preferred MCP library.
//
// # Quick Start
//
//	import (
//	    "github.com/keycardai/credentials-go/mcpofficial"
//	    "github.com/modelcontextprotocol/go-sdk/mcp"
//	)
//
//	s := mcp.NewServer(&mcp.Implementation{
//	    Name:    "My Server",
//	    Version: "1.0.0",
//	}, nil)
//	mcp.AddTool(s, myTool, myHandler)
//
//	handler, err := mcpofficial.NewHandler(s,
//	    mcpofficial.WithZoneURL("https://my-zone.keycard.cloud"),
//	    mcpofficial.WithResourceName("My Server"),
//	    mcpofficial.WithScopes("mcp:tools"),
//	)
//
//	http.ListenAndServe(":8080", handler)
//
// Inside tool handlers, use [github.com/keycardai/credentials-go/mcp.AuthInfoFromContext]
// and [github.com/keycardai/credentials-go/mcp.AccessContextFromContext] to retrieve
// auth info and delegated tokens.
package mcpofficial
