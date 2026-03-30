package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/keycardai/credentials-go/oauth"
)

// AccessContextStatus represents the status of token exchanges.
type AccessContextStatus string

const (
	StatusSuccess      AccessContextStatus = "success"
	StatusPartialError AccessContextStatus = "partial_error"
	StatusError        AccessContextStatus = "error"
)

// ErrorDetail describes an error during token exchange.
type ErrorDetail struct {
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
	RawError    string `json:"raw_error,omitempty"`
}

// AccessContext holds the results of token exchanges for multiple resources.
// It is a non-throwing result container: callers check status before accessing tokens.
type AccessContext struct {
	tokens         map[string]*oauth.TokenResponse
	resourceErrors map[string]ErrorDetail
	globalError    *ErrorDetail
}

// NewAccessContext creates a new empty AccessContext.
func NewAccessContext() *AccessContext {
	return &AccessContext{
		tokens:         make(map[string]*oauth.TokenResponse),
		resourceErrors: make(map[string]ErrorDetail),
	}
}

// SetToken sets a successful token for a resource (clears any error for that resource).
func (ac *AccessContext) SetToken(resource string, token *oauth.TokenResponse) {
	ac.tokens[resource] = token
	delete(ac.resourceErrors, resource)
}

// SetBulkTokens sets multiple tokens at once.
func (ac *AccessContext) SetBulkTokens(tokens map[string]*oauth.TokenResponse) {
	for resource, token := range tokens {
		ac.tokens[resource] = token
	}
}

// SetResourceError sets an error for a specific resource (clears any token for that resource).
func (ac *AccessContext) SetResourceError(resource string, detail ErrorDetail) {
	ac.resourceErrors[resource] = detail
	delete(ac.tokens, resource)
}

// SetError sets a global error.
func (ac *AccessContext) SetError(detail ErrorDetail) {
	ac.globalError = &detail
}

// Access returns the token for the given resource.
// Returns ResourceAccessError if the resource has an error or no token.
func (ac *AccessContext) Access(resource string) (*oauth.TokenResponse, error) {
	if ac.globalError != nil {
		return nil, &ResourceAccessError{Message: ac.globalError.Message}
	}
	if _, hasErr := ac.resourceErrors[resource]; hasErr {
		return nil, &ResourceAccessError{Message: ac.resourceErrors[resource].Message}
	}
	token, ok := ac.tokens[resource]
	if !ok {
		return nil, &ResourceAccessError{Message: fmt.Sprintf("no token for resource %q", resource)}
	}
	return token, nil
}

// Status returns the overall status of the context.
func (ac *AccessContext) Status() AccessContextStatus {
	if ac.globalError != nil {
		return StatusError
	}
	if len(ac.resourceErrors) > 0 {
		return StatusPartialError
	}
	return StatusSuccess
}

// HasErrors returns true if any errors occurred (global or per-resource).
func (ac *AccessContext) HasErrors() bool {
	return ac.globalError != nil || len(ac.resourceErrors) > 0
}

// HasError returns true if a global error is set.
func (ac *AccessContext) HasError() bool {
	return ac.globalError != nil
}

// HasResourceError returns true if the specific resource had an error.
func (ac *AccessContext) HasResourceError(resource string) bool {
	_, ok := ac.resourceErrors[resource]
	return ok
}

// GetError returns the global error, or nil.
func (ac *AccessContext) GetError() *ErrorDetail {
	return ac.globalError
}

// GetResourceError returns the error for a specific resource, or nil.
func (ac *AccessContext) GetResourceError(resource string) *ErrorDetail {
	if detail, ok := ac.resourceErrors[resource]; ok {
		return &detail
	}
	return nil
}

// GetErrors returns all errors (global + per-resource).
func (ac *AccessContext) GetErrors() (resources map[string]ErrorDetail, globalError *ErrorDetail) {
	result := make(map[string]ErrorDetail, len(ac.resourceErrors))
	for k, v := range ac.resourceErrors {
		result[k] = v
	}
	return result, ac.globalError
}

// SuccessfulResources returns the list of resources with successful token exchanges.
func (ac *AccessContext) SuccessfulResources() []string {
	resources := make([]string, 0, len(ac.tokens))
	for r := range ac.tokens {
		resources = append(resources, r)
	}
	return resources
}

// FailedResources returns the list of resources with failed token exchanges.
func (ac *AccessContext) FailedResources() []string {
	resources := make([]string, 0, len(ac.resourceErrors))
	for r := range ac.resourceErrors {
		resources = append(resources, r)
	}
	return resources
}

// AuthProviderOption configures an AuthProvider.
type AuthProviderOption func(*authProviderConfig)

type authProviderConfig struct {
	zoneURL               string
	zoneID                string
	baseURL               string
	applicationCredential ApplicationCredential
	httpClient            *http.Client
}

// WithZoneURL sets the Keycard zone URL directly.
func WithZoneURL(zoneURL string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.zoneURL = zoneURL }
}

// WithZoneID sets the Keycard zone ID (used with base URL to construct zone URL).
func WithZoneID(zoneID string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.zoneID = zoneID }
}

// WithBaseURL sets the base URL for zone URL construction. Default: "https://keycard.cloud".
func WithBaseURL(baseURL string) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.baseURL = baseURL }
}

// WithApplicationCredential sets the application credential for token exchange.
func WithApplicationCredential(cred ApplicationCredential) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.applicationCredential = cred }
}

// WithProviderHTTPClient sets the HTTP client used by the auth provider.
func WithProviderHTTPClient(c *http.Client) AuthProviderOption {
	return func(cfg *authProviderConfig) { cfg.httpClient = c }
}

// AuthProvider orchestrates token exchange for MCP servers.
type AuthProvider struct {
	zoneURL    string
	credential ApplicationCredential
	httpClient *http.Client

	clientOnce sync.Once
	client     *oauth.TokenExchangeClient
	clientErr  error
}

// NewAuthProvider creates a new AuthProvider with the given options.
func NewAuthProvider(opts ...AuthProviderOption) (*AuthProvider, error) {
	cfg := authProviderConfig{
		baseURL:    "https://keycard.cloud",
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	zoneURL := cfg.zoneURL
	if zoneURL == "" {
		zoneURL = buildZoneURL(cfg.zoneID, cfg.baseURL)
	}
	if zoneURL == "" {
		return nil, &AuthProviderConfigurationError{
			Message: "either zoneURL or zoneID must be provided",
		}
	}

	return &AuthProvider{
		zoneURL:    zoneURL,
		credential: cfg.applicationCredential,
		httpClient: cfg.httpClient,
	}, nil
}

// Grant returns middleware that performs token exchange for the specified resources.
// The AccessContext is stored in the request context (retrieve with AccessContextFromRequest).
func (p *AuthProvider) Grant(resources ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authInfo := AuthInfoFromRequest(r)

			if authInfo == nil || authInfo.Token == "" {
				ac := NewAccessContext()
				ac.SetError(ErrorDetail{
					Message: "No authentication token available. Ensure RequireBearerAuth() middleware runs before Grant().",
				})
				ctx := context.WithValue(r.Context(), accessContextKey, ac)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ac := p.ExchangeTokens(r.Context(), authInfo.Token, resources...)
			ctx := context.WithValue(r.Context(), accessContextKey, ac)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ExchangeTokens performs token exchange directly and returns an AccessContext.
func (p *AuthProvider) ExchangeTokens(ctx context.Context, subjectToken string, resources ...string) *AccessContext {
	ac := NewAccessContext()

	client, err := p.getOrCreateClient()
	if err != nil {
		ac.SetError(ErrorDetail{
			Message:  "Failed to initialize OAuth client. Server configuration issue.",
			RawError: err.Error(),
		})
		return ac
	}

	tokens := make(map[string]*oauth.TokenResponse)

	// Resolve the token endpoint for credential assertion audience.
	tokenEndpoint, _ := client.TokenEndpoint(ctx)

	for _, resource := range resources {
		var req *oauth.TokenExchangeRequest

		if p.credential != nil {
			opts := &PrepareOptions{TokenEndpoint: tokenEndpoint}
			req, err = p.credential.PrepareTokenExchangeRequest(ctx, subjectToken, resource, opts)
			if err != nil {
				ac.SetResourceError(resource, ErrorDetail{
					Message:  fmt.Sprintf("Token exchange failed for %s", resource),
					RawError: err.Error(),
				})
				continue
			}
		} else {
			req = &oauth.TokenExchangeRequest{
				SubjectToken:     subjectToken,
				Resource:         resource,
				SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
			}
		}

		resp, err := client.ExchangeToken(ctx, *req)
		if err != nil {
			detail := ErrorDetail{
				Message: fmt.Sprintf("Token exchange failed for %s", resource),
			}
			var oauthErr *oauth.OAuthError
			if errors.As(err, &oauthErr) {
				detail.Code = oauthErr.ErrorCode
				if oauthErr.Message != "" {
					detail.Description = oauthErr.Message
				}
			} else {
				detail.RawError = err.Error()
			}
			ac.SetResourceError(resource, detail)
			continue
		}

		tokens[resource] = resp
	}

	ac.SetBulkTokens(tokens)
	return ac
}

func (p *AuthProvider) getOrCreateClient() (*oauth.TokenExchangeClient, error) {
	p.clientOnce.Do(func() {
		var clientOpts []oauth.TokenExchangeClientOption

		if p.httpClient != nil {
			clientOpts = append(clientOpts, oauth.WithTokenExchangeHTTPClient(p.httpClient))
		}

		if p.credential != nil {
			if auth := p.credential.Auth(); auth != nil {
				clientOpts = append(clientOpts, oauth.WithClientCredentials(auth.ClientID, auth.ClientSecret))
			}
		}

		p.client = oauth.NewTokenExchangeClient(p.zoneURL, clientOpts...)
	})

	return p.client, p.clientErr
}

func buildZoneURL(zoneID, baseURL string) string {
	if zoneID == "" {
		return ""
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%s://%s.%s", u.Scheme, zoneID, u.Host)
}
