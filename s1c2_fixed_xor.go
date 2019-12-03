package cryptopals

import (
	"encoding/hex"
	"errors"
)

// ToHex converts raw bytes into a hex-encoded string.
func ToHex(r []byte) string {
	return hex.EncodeToString(r)
}

func fixedXOR(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range a {
		r[i] = a[i] ^ b[i]
	}
	return r
}

// FixedXOR takes two byte slices of identical length and XORs them. It returns
// an error if the slices are of different lengths.
func FixedXOR(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("buffers are different lengths")
	}
	return fixedXOR(a, b), nil
}

// FixedHexXOR takes two hex-encoded strings and XORs them. It returns an error
// if the strings are of different lengths.
func FixedHexXOR(a, b string) (string, error) {
	raw1, err := FromHex(a)
	if err != nil {
		return "", err
	}
	raw2, err := FromHex(b)
	if err != nil {
		return "", err
	}
	xor, err := FixedXOR(raw1, raw2)
	if err != nil {
		return "", err
	}
	return ToHex(xor), nil
}
