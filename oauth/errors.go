package oauth

import "fmt"

// HTTPError represents an HTTP-related error with a status code.
type HTTPError struct {
	Message string
	Status  int
}

func (e *HTTPError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("HTTP %d: %s", e.Status, e.Message)
	}
	return e.Message
}

// OAuthError represents an OAuth protocol error with an error code.
type OAuthError struct {
	ErrorCode string
	Message   string
	ErrorURI  string
}

func (e *OAuthError) Error() string {
	if e.ErrorCode != "" {
		return fmt.Sprintf("oauth error %s: %s", e.ErrorCode, e.Message)
	}
	return e.Message
}

// InvalidTokenError indicates the token is invalid (expired, malformed, or bad signature).
type InvalidTokenError struct {
	Message  string
	ErrorURI string
}

func (e *InvalidTokenError) Error() string {
	return e.Message
}

// ErrorCode returns the OAuth error code for this error.
func (e *InvalidTokenError) ErrorCode() string {
	return "invalid_token"
}

// InsufficientScopeError indicates the token lacks required scopes.
type InsufficientScopeError struct {
	Message  string
	ErrorURI string
}

func (e *InsufficientScopeError) Error() string {
	return e.Message
}

// ErrorCode returns the OAuth error code for this error.
func (e *InsufficientScopeError) ErrorCode() string {
	return "insufficient_scope"
}
