package oauth

import "testing"

func TestBase64URLRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"hello", []byte("hello")},
		{"binary", []byte{0, 1, 2, 255, 254}},
		{"padding-1", []byte("a")},
		{"padding-2", []byte("ab")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := Base64URLEncode(tt.input)
			decoded, err := Base64URLDecode(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			if len(decoded) != len(tt.input) {
				t.Fatalf("length mismatch: got %d, want %d", len(decoded), len(tt.input))
			}
			for i := range decoded {
				if decoded[i] != tt.input[i] {
					t.Fatalf("byte %d mismatch: got %d, want %d", i, decoded[i], tt.input[i])
				}
			}
		})
	}
}

func TestBase64URLNoPadding(t *testing.T) {
	encoded := Base64URLEncode([]byte("test"))
	for _, c := range encoded {
		if c == '=' {
			t.Error("base64url output should not contain padding")
		}
	}
}
