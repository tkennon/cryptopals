package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
)

// FromHex converts a hex-encoded string into raw bytes.
func FromHex(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

// ToBase64 converts raw bytes into a base64-encoded string.
func ToBase64(r []byte) string {
	return base64.StdEncoding.EncodeToString(r)
}

// HexToBase64 takes a hex-encoded string and returns a base-64 encoded string.
func HexToBase64(h string) (string, error) {
	r, err := FromHex(h)
	if err != nil {
		return "", err
	}
	return ToBase64(r), nil
}
