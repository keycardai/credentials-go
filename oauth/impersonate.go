package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
)

// SubstituteUserTokenType is the vendor URN used as subject_token_type in
// Keycard impersonation token exchanges. It signals to the authorization
// server that the subject_token is an unsigned substitute-user assertion.
const SubstituteUserTokenType = "urn:keycard:params:oauth:token-type:substitute-user"

// substituteUserActorTokenType is the IANA URN used as actor_token_type when
// the actor token is an OAuth 2.0 access token (RFC 8693 §3).
const substituteUserActorTokenType = "urn:ietf:params:oauth:token-type:access_token"

// ImpersonateRequest contains the inputs for an impersonation token exchange.
//
// The calling service's application credential supplies the actor identity;
// callers do not pass it explicitly. The configured TokenExchangeClient
// credential is used both to mint the actor token (via a client_credentials
// grant) and to authenticate the exchange request.
type ImpersonateRequest struct {
	// UserIdentifier is the target user. Becomes "sub" in the issued token. Required.
	UserIdentifier string
	// Resource is the target resource URI for the issued token. Required.
	Resource string
	// Scopes are the scopes requested for the issued token. Optional.
	Scopes []string
}

// Impersonate exchanges the client's application credential for a token that
// acts on behalf of req.UserIdentifier.
//
// It performs an RFC 8693 token exchange where:
//   - actor_token is minted via a client_credentials grant using the
//     credentials configured on this TokenExchangeClient
//   - subject_token is an unsigned substitute-user JWT carrying the user id
//   - subject_token_type is SubstituteUserTokenType
//
// Impersonation is a privileged operation gated by server-side policy and is
// forbidden by default. The authorization server returns "unauthorized_client"
// when the calling client is not permitted to impersonate.
func (c *TokenExchangeClient) Impersonate(ctx context.Context, req ImpersonateRequest) (*TokenResponse, error) {
	if req.UserIdentifier == "" {
		return nil, errors.New("oauth: ImpersonateRequest.UserIdentifier is required")
	}
	if req.Resource == "" {
		return nil, errors.New("oauth: ImpersonateRequest.Resource is required")
	}

	actor, err := c.clientCredentialsClient().RequestToken(ctx, ClientCredentialsRequest{})
	if err != nil {
		return nil, err
	}

	return c.ExchangeToken(ctx, TokenExchangeRequest{
		SubjectToken:     buildSubstituteUserToken(req.UserIdentifier),
		SubjectTokenType: SubstituteUserTokenType,
		ActorToken:       actor.AccessToken,
		ActorTokenType:   substituteUserActorTokenType,
		Resource:         req.Resource,
		Scope:            strings.Join(req.Scopes, " "),
	})
}

// buildSubstituteUserToken constructs the unsigned JWT used as subject_token
// in Keycard impersonation exchanges. The format is:
//
//	base64url({"typ":"vnd.kc.su+jwt","alg":"none"}).base64url({"sub":id}).
//
// The trailing dot is intentional: it marks the absent signature segment.
// The token is intentionally unsigned. Authority comes from the client's
// authentication to the token endpoint plus server-side impersonation policy,
// not from a signature on this assertion.
func buildSubstituteUserToken(userIdentifier string) string {
	header := []byte(`{"typ":"vnd.kc.su+jwt","alg":"none"}`)
	payload, _ := json.Marshal(struct {
		Sub string `json:"sub"`
	}{Sub: userIdentifier})
	return Base64URLEncode(header) + "." + Base64URLEncode(payload) + "."
}
