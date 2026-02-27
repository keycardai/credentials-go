package oauth

import "encoding/base64"

// Base64URLEncode encodes data to base64url without padding (RFC 4648 §5).
func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Base64URLDecode decodes a base64url string without padding (RFC 4648 §5).
func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
