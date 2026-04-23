package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/keycardai/credentials-go/oauth"
)

const (
	defaultFlySocketPath = "/.fly/api"
	defaultFlyOIDCPath   = "http://localhost/v1/tokens/oidc"
)

// FlyWorkloadIdentityCredential implements ApplicationCredential using
// Fly.io OIDC tokens fetched from the local machine API Unix socket.
type FlyWorkloadIdentityCredential struct {
	socketPath string
	audience   string
}

// FlyWorkloadIdentityOption configures a FlyWorkloadIdentityCredential.
type FlyWorkloadIdentityOption func(*flyConfig)

type flyConfig struct {
	socketPath string
	audience   string
}

// WithFlySocketPath overrides the default Unix socket path (/.fly/api).
func WithFlySocketPath(path string) FlyWorkloadIdentityOption {
	return func(cfg *flyConfig) { cfg.socketPath = path }
}

// WithFlyAudience sets the audience claim for the OIDC token request.
// Typically the Keycard zone URL.
func WithFlyAudience(audience string) FlyWorkloadIdentityOption {
	return func(cfg *flyConfig) { cfg.audience = audience }
}

// NewFlyWorkloadIdentity creates a new FlyWorkloadIdentityCredential.
func NewFlyWorkloadIdentity(opts ...FlyWorkloadIdentityOption) *FlyWorkloadIdentityCredential {
	cfg := flyConfig{
		socketPath: defaultFlySocketPath,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &FlyWorkloadIdentityCredential{
		socketPath: cfg.socketPath,
		audience:   cfg.audience,
	}
}

// Auth returns nil (Fly uses assertion-based auth, not basic auth).
func (f *FlyWorkloadIdentityCredential) Auth() *ClientAuth {
	return nil
}

// PrepareTokenExchangeRequest builds a token exchange request with the
// Fly OIDC token as the client assertion.
func (f *FlyWorkloadIdentityCredential) PrepareTokenExchangeRequest(ctx context.Context, subjectToken, resource string, _ *PrepareOptions) (*oauth.TokenExchangeRequest, error) {
	flyToken, err := f.fetchOIDCToken(ctx)
	if err != nil {
		return nil, err
	}

	return &oauth.TokenExchangeRequest{
		SubjectToken:        subjectToken,
		Resource:            resource,
		SubjectTokenType:    "urn:ietf:params:oauth:token-type:access_token",
		ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
		ClientAssertion:     flyToken,
	}, nil
}

// fetchOIDCToken requests a short-lived OIDC JWT from the Fly.io machine API
// via the local Unix socket.
func (f *FlyWorkloadIdentityCredential) fetchOIDCToken(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", f.socketPath)
			},
		},
	}

	var body string
	if f.audience != "" {
		body = fmt.Sprintf(`{"aud":"%s"}`, f.audience)
	} else {
		body = `{}`
	}

	req, err := http.NewRequestWithContext(ctx, "POST", defaultFlyOIDCPath, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating Fly OIDC request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", &FlyWorkloadIdentityConfigurationError{
			Message: fmt.Sprintf("calling Fly OIDC endpoint at %s: %v (is this running on a Fly Machine?)", f.socketPath, err),
		}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading Fly OIDC response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Fly OIDC returned %d: %s", resp.StatusCode, string(raw))
	}

	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("Fly OIDC returned empty token")
	}

	return token, nil
}
