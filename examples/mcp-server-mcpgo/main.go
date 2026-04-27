// Authenticated MCP server using mark3labs/mcp-go with Keycard OAuth.
//
// The credentials-go/mcp package provides composable HTTP middleware — you
// bring your own MCP library and mux, Keycard handles auth and metadata.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/keycardai/credentials-go/mcp"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func main() {
	zoneURL := os.Getenv("KEYCARD_ZONE_URL")
	if zoneURL == "" {
		log.Fatal("KEYCARD_ZONE_URL environment variable is required")
	}

	// 1. Create your MCP server and register tools (pure mcp-go, no Keycard involvement)
	s := server.NewMCPServer("Hello World MCP Server", "1.0.0")

	s.AddTool(
		mcpgo.NewTool("hello",
			mcpgo.WithDescription("Say hello to the authenticated user."),
			mcpgo.WithString("name", mcpgo.Required(), mcpgo.Description("Name to greet")),
		),
		helloHandler,
	)

	s.AddTool(
		mcpgo.NewTool("get_github_user",
			mcpgo.WithDescription("Get the authenticated user's GitHub profile via delegated access."),
		),
		githubUserHandler,
	)

	// 2. Get the MCP HTTP handler from mcp-go
	mcpHandler := server.NewStreamableHTTPServer(s)

	// 3. Set up your own mux and mount Keycard auth + MCP transport
	httpMux := http.NewServeMux()

	// OAuth metadata — lets MCP clients discover how to authenticate
	httpMux.Handle("/.well-known/", mcp.AuthMetadataHandler(
		mcp.WithIssuer(zoneURL),
		mcp.WithScopesSupported([]string{"mcp:tools"}),
		mcp.WithResourceName("Hello World MCP Server"),
	))

	// Protect /mcp with bearer auth
	protected := mcp.RequireBearerAuth(
		mcp.WithRequiredScopes("mcp:tools"),
	)(mcpHandler)

	// Optional: add delegated access for token exchange
	if clientID := os.Getenv("KEYCARD_CLIENT_ID"); clientID != "" {
		authProvider, err := mcp.NewAuthProvider(
			mcp.WithZoneURL(zoneURL),
			mcp.WithApplicationCredential(
				mcp.NewClientSecret(clientID, os.Getenv("KEYCARD_CLIENT_SECRET")),
			),
		)
		if err != nil {
			log.Fatal(err)
		}
		protected = mcp.RequireBearerAuth(
			mcp.WithRequiredScopes("mcp:tools"),
		)(authProvider.Grant("https://api.github.com")(mcpHandler))
	}

	httpMux.Handle("/mcp", protected)

	// 4. Start
	addr := ":8080"
	if port := os.Getenv("PORT"); port != "" {
		addr = ":" + port
	}
	log.Printf("MCP server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, httpMux))
}

func helloHandler(ctx context.Context, request mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	name, _ := request.GetArguments()["name"].(string)
	if name == "" {
		name = "World"
	}

	authInfo := mcp.AuthInfoFromContext(ctx)
	var message string
	if authInfo != nil {
		message = fmt.Sprintf("Hello, %s! Authenticated as client: %s", name, authInfo.ClientID)
	} else {
		message = fmt.Sprintf("Hello, %s!", name)
	}

	return mcpgo.NewToolResultText(message), nil
}

func githubUserHandler(ctx context.Context, request mcpgo.CallToolRequest) (*mcpgo.CallToolResult, error) {
	ac := mcp.AccessContextFromContext(ctx)
	if ac == nil {
		return mcpgo.NewToolResultError("Delegated access not configured. Set KEYCARD_CLIENT_ID and KEYCARD_CLIENT_SECRET."), nil
	}

	if ac.HasErrors() {
		_, globalErr := ac.GetErrors()
		if globalErr != nil {
			return mcpgo.NewToolResultError(fmt.Sprintf("Token exchange failed: %s", globalErr.Message)), nil
		}
		return mcpgo.NewToolResultError("Token exchange failed for GitHub"), nil
	}

	token, err := ac.Access("https://api.github.com")
	if err != nil {
		return mcpgo.NewToolResultError(fmt.Sprintf("GitHub token unavailable: %v", err)), nil
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return mcpgo.NewToolResultError(fmt.Sprintf("GitHub API error: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return mcpgo.NewToolResultError(fmt.Sprintf("GitHub API returned %d: %s", resp.StatusCode, string(body))), nil
	}

	var user map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return mcpgo.NewToolResultError(fmt.Sprintf("Failed to parse GitHub response: %v", err)), nil
	}

	result, _ := json.MarshalIndent(map[string]any{
		"login":        user["login"],
		"name":         user["name"],
		"public_repos": user["public_repos"],
	}, "", "  ")

	return mcpgo.NewToolResultText(string(result)), nil
}
