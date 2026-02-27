package oauth

import (
	"errors"
	"testing"
)

func TestHTTPError(t *testing.T) {
	err := &HTTPError{Message: "not found", Status: 404}
	if err.Error() != "HTTP 404: not found" {
		t.Errorf("got %q", err.Error())
	}

	err2 := &HTTPError{Message: "something went wrong"}
	if err2.Error() != "something went wrong" {
		t.Errorf("got %q", err2.Error())
	}
}

func TestOAuthError(t *testing.T) {
	err := &OAuthError{ErrorCode: "invalid_grant", Message: "token expired"}
	if err.Error() != "oauth error invalid_grant: token expired" {
		t.Errorf("got %q", err.Error())
	}
}

func TestInvalidTokenError(t *testing.T) {
	err := &InvalidTokenError{Message: "bad signature"}
	if err.Error() != "bad signature" {
		t.Errorf("got %q", err.Error())
	}
	if err.ErrorCode() != "invalid_token" {
		t.Errorf("got %q", err.ErrorCode())
	}

	// Test errors.As
	var target *InvalidTokenError
	if !errors.As(err, &target) {
		t.Error("errors.As should match InvalidTokenError")
	}
}

func TestInsufficientScopeError(t *testing.T) {
	err := &InsufficientScopeError{Message: "need admin"}
	if err.Error() != "need admin" {
		t.Errorf("got %q", err.Error())
	}
	if err.ErrorCode() != "insufficient_scope" {
		t.Errorf("got %q", err.ErrorCode())
	}
}
