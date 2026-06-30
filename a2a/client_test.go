package a2a

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/keycardai/credentials-go/oauth"
)

// fakeZone is a fake Keycard authorization server: it advertises a token endpoint and
// performs (or rejects) the RFC 8693 exchange, recording the basic-auth client id it
// received so a test can assert the calling agent's credential was used.
type fakeZone struct {
	*httptest.Server
	mu           sync.Mutex
	exchanges    int
	lastClientID string
	reject       bool
}

func newFakeZone(t *testing.T) *fakeZone {
	t.Helper()
	z := &fakeZone{}
	mux := http.NewServeMux()
	z.Server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         z.URL,
			"token_endpoint": z.URL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, _, _ := r.BasicAuth()
		z.mu.Lock()
		z.exchanges++
		z.lastClientID = id
		reject := z.reject
		z.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if reject {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":             "invalid_grant",
				"error_description": "user token not accepted for target",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "exchanged-token",
			"token_type":   "bearer",
			"expires_in":   3600,
		})
	})
	t.Cleanup(z.Close)
	return z
}

func (z *fakeZone) exchangeCount() int {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.exchanges
}

func (z *fakeZone) clientID() string {
	z.mu.Lock()
	defer z.mu.Unlock()
	return z.lastClientID
}

// fakeAgent is a fake target agent: it serves its card and a JSON-RPC endpoint that
// records the bearer token it was invoked with and returns either a response message
// or a JSON-RPC error.
type fakeAgent struct {
	*httptest.Server
	mu          sync.Mutex
	invocations int
	lastBearer  string
	failCode    int
	failMessage string
}

func newFakeAgent(t *testing.T) *fakeAgent {
	t.Helper()
	a := &fakeAgent{}
	mux := http.NewServeMux()
	a.Server = httptest.NewServer(mux)
	mux.HandleFunc(agentCardPath, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "Target Agent",
			"url":  a.URL + "/a2a/jsonrpc",
		})
	})
	mux.HandleFunc("/a2a/jsonrpc", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.invocations++
		a.lastBearer = r.Header.Get("Authorization")
		failMessage := a.failMessage
		failCode := a.failCode
		a.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if failMessage != "" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"error":   map[string]any{"code": failCode, "message": failMessage},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"result": map[string]any{
				"message": map[string]any{
					"messageId": "resp-1",
					"role":      RoleAgent,
					"parts":     []map[string]any{{"kind": "text", "text": "handled"}},
				},
			},
		})
	})
	t.Cleanup(a.Close)
	return a
}

func (a *fakeAgent) invocationCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.invocations
}

func (a *fakeAgent) bearer() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastBearer
}

// Spec test 3: a valid user token is exchanged for a target-scoped token and the agent
// is invoked with it.
func TestDelegationClient_Invoke_ExchangesThenInvokes(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	res, err := client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if zone.exchangeCount() != 1 {
		t.Errorf("exchanges: got %d, want 1", zone.exchangeCount())
	}
	if zone.clientID() != "agent-client" {
		t.Errorf("exchange authenticated as %q, want agent-client", zone.clientID())
	}
	if agent.invocationCount() != 1 {
		t.Errorf("agent invocations: got %d, want 1", agent.invocationCount())
	}
	if got := agent.bearer(); got != "Bearer exchanged-token" {
		t.Errorf("agent bearer: got %q, want the exchanged token", got)
	}
	if len(res.Message.Parts) != 1 || res.Message.Parts[0].Text != "handled" {
		t.Errorf("response message: got %+v", res.Message)
	}
	if res.AgentCard.Name != "Target Agent" {
		t.Errorf("resolved card name: got %q", res.AgentCard.Name)
	}
}

// Spec test 4: the exchange is rejected by the zone; the token-exchange OAuth error
// surfaces and the agent is not invoked.
func TestDelegationClient_Invoke_ExchangeRejected(t *testing.T) {
	zone := newFakeZone(t)
	zone.reject = true
	agent := newFakeAgent(t)

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))

	var oauthErr *oauth.OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error: got %v, want oauth.OAuthError", err)
	}
	if oauthErr.ErrorCode != "invalid_grant" {
		t.Errorf("oauth error code: got %q, want invalid_grant", oauthErr.ErrorCode)
	}
	if agent.invocationCount() != 0 {
		t.Errorf("agent invocations: got %d, want 0 (must not invoke on exchange failure)", agent.invocationCount())
	}
}

// Spec test 5: the target returns a JSON-RPC error; an invocation error surfaces.
func TestDelegationClient_Invoke_JSONRPCError(t *testing.T) {
	zone := newFakeZone(t)
	agent := newFakeAgent(t)
	agent.failCode = -32000
	agent.failMessage = "task failed"

	client, err := NewDelegationClient(zone.URL, "agent-client", "agent-secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}

	_, err = client.Invoke(context.Background(), agent.URL, "user-token", NewTextMessage("do the thing"))

	var invErr *InvocationError
	if !errors.As(err, &invErr) {
		t.Fatalf("error: got %v, want InvocationError", err)
	}
	if invErr.Code != -32000 {
		t.Errorf("invocation error code: got %d, want -32000", invErr.Code)
	}
}

func TestNewDelegationClient_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name, issuer, clientID, clientSecret string
	}{
		{name: "empty issuer", issuer: "", clientID: "id", clientSecret: "secret"},
		{name: "empty client_id", issuer: "https://zone.example.com", clientID: "", clientSecret: "secret"},
		{name: "empty client_secret", issuer: "https://zone.example.com", clientID: "id", clientSecret: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDelegationClient(tc.issuer, tc.clientID, tc.clientSecret)
			var cfgErr *ConfigurationError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("error: got %v, want ConfigurationError", err)
			}
		})
	}
}

func TestDelegationClient_Invoke_RejectsEmptySubjectToken(t *testing.T) {
	client, err := NewDelegationClient("https://zone.example.com", "id", "secret")
	if err != nil {
		t.Fatalf("NewDelegationClient: %v", err)
	}
	_, err = client.Invoke(context.Background(), "https://agent.example.com", "", NewTextMessage("hi"))
	var cfgErr *ConfigurationError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("error: got %v, want ConfigurationError", err)
	}
}
