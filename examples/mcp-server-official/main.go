// Authenticated MCP server using the official modelcontextprotocol/go-sdk with Keycard OAuth.
//
// The credentials-go/mcp package provides composable HTTP middleware — you
// bring your own MCP library and mux, Keycard handles auth and metadata.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	keycardmcp "github.com/keycardai/credentials-go/mcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type HelloInput struct {
	Name string `json:"name" jsonschema:"the name to greet"`
}

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	// 1. Create your MCP server and register tools (pure official SDK, no Keycard involvement)
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "Hello World MCP Server",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(s, &mcp.Tool{
		Name:        "hello",
		Description: "Say hello to the authenticated user.",
	}, helloHandler)

	// 2. Get the MCP HTTP handler from the official SDK
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{},
	)

	// 3. Set up your own mux and mount Keycard auth + MCP transport
	httpMux := http.NewServeMux()

	// OAuth metadata — lets MCP clients discover how to authenticate
	httpMux.Handle("/.well-known/", keycardmcp.AuthMetadataHandler(
		keycardmcp.WithIssuer(zoneURL),
		keycardmcp.WithScopesSupported([]string{"mcp:tools"}),
		keycardmcp.WithResourceName("Hello World MCP Server"),
	))

	// Protect /mcp with bearer auth
	protected := keycardmcp.RequireBearerAuth(
		keycardmcp.WithRequiredScopes("mcp:tools"),
	)(mcpHandler)

	httpMux.Handle("/mcp", protected)

	// 4. Start
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("MCP server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpMux))
}

func helloHandler(ctx context.Context, req *mcp.CallToolRequest, input HelloInput) (*mcp.CallToolResult, any, error) {
	authInfo := keycardmcp.AuthInfoFromContext(ctx)

	var message string
	if authInfo != nil {
		message = fmt.Sprintf("Hello, %s! Authenticated as client: %s", input.Name, authInfo.ClientID)
	} else {
		message = fmt.Sprintf("Hello, %s!", input.Name)
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: message},
		},
	}, nil, nil
}
