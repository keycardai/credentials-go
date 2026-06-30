package a2a

import (
	"crypto/rand"
	"fmt"
)

// Message roles, per the A2A protocol.
const (
	RoleUser  = "user"
	RoleAgent = "agent"
)

// Part is one piece of a Message. A text part carries Kind "text" and a Text body.
type Part struct {
	Kind string `json:"kind"`
	Text string `json:"text,omitempty"`
}

// Message is an A2A message exchanged with an agent: a role, an ordered list of
// content parts, and optional metadata.
type Message struct {
	MessageID string         `json:"messageId"`
	Role      string         `json:"role"`
	Parts     []Part         `json:"parts"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// AgentCard is the subset of an A2A agent card this package reads. The card carries
// many more fields; only name (required) and url (used to resolve the JSON-RPC
// endpoint) are consumed here.
type AgentCard struct {
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	URL             string `json:"url,omitempty"`
	Version         string `json:"version,omitempty"`
	ProtocolVersion string `json:"protocolVersion,omitempty"`
}

// Result is the outcome of a delegated invocation: the agent's response message and
// the agent card that was resolved for the call.
type Result struct {
	Message   Message
	AgentCard AgentCard
}

// NewTextMessage builds a user-role message carrying a single text part, with a
// freshly generated message ID.
func NewTextMessage(text string) Message {
	return Message{
		MessageID: newUUID(),
		Role:      RoleUser,
		Parts:     []Part{{Kind: "text", Text: text}},
	}
}

// newUUID returns a random RFC 4122 version 4 UUID string. crypto/rand.Read does not
// fail on any supported platform, so its error is not surfaced.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
