package oauth

import "testing"

func TestAccessContext_MergeTokensAndErrors(t *testing.T) {
	a := NewAccessContext()
	a.SetToken("res-a", &TokenResponse{AccessToken: "ta"})

	b := NewAccessContext()
	b.SetToken("res-b", &TokenResponse{AccessToken: "tb"})
	b.SetResourceError("res-c", ErrorDetail{Message: "failed"})

	a.Merge(b)

	if _, err := a.Access("res-a"); err != nil {
		t.Errorf("res-a: %v", err)
	}
	if _, err := a.Access("res-b"); err != nil {
		t.Errorf("res-b: %v", err)
	}
	if !a.HasResourceError("res-c") {
		t.Error("res-c error was not merged")
	}
}

// Merge is last-wins on the global error, matching the TypeScript convention.
func TestAccessContext_MergeGlobalErrorLastWins(t *testing.T) {
	a := NewAccessContext()
	a.SetError(ErrorDetail{Message: "first"})

	b := NewAccessContext()
	b.SetError(ErrorDetail{Message: "second"})

	a.Merge(b)

	if got := a.GetError(); got == nil || got.Message != "second" {
		t.Errorf("global error after merge: got %+v, want last-wins %q", got, "second")
	}
}
