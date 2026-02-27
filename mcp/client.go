package mcp

// OAuthTokens holds an OAuth token set for client-side storage.
type OAuthTokens struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
}

// OAuthTokenStore stores and retrieves OAuth tokens for MCP client providers.
type OAuthTokenStore interface {
	Get() (*OAuthTokens, error)
	Save(tokens *OAuthTokens) error
}

// InMemoryTokenStore implements OAuthTokenStore using in-memory storage.
type InMemoryTokenStore struct {
	tokens *OAuthTokens
}

// NewInMemoryTokenStore creates a new in-memory token store.
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{}
}

// Get returns the stored tokens, or nil if none are stored.
func (s *InMemoryTokenStore) Get() (*OAuthTokens, error) {
	return s.tokens, nil
}

// Save stores the tokens.
func (s *InMemoryTokenStore) Save(tokens *OAuthTokens) error {
	s.tokens = tokens
	return nil
}
