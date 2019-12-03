package cryptopals

import (
	"strings"
)

// countCommonChars returns the number of times the 12 most common characters in
// the English language appear in the string s.
func countCommonChars(s string) int {
	count := 0
	for _, c := range strings.ToLower(s) {
		switch c {
		case 'e', 't', 'a', 'o', 'i', 'n', 's', 'h', 'r', 'd', 'l', 'u':
			count++
		}
	}
	return count
}

// DetectSingleByteXOR takes as input a slice of hex-encoded strings, and
// determines which one of them has been encrypted with a single byte XOR. It
// returns the encrypted string, the decrypted string, the encryption key, and
// any error.
func DetectSingleByteXOR(hs []string) (encrypted, decrypted string, key byte, err error) {
	mostLetters := 0
	for _, h := range hs {
		d, k, err := DecodeSingleByteXOR(h)
		if err != nil {
			return "", "", 0, err
		}
		if letters := countCommonChars(d); letters > mostLetters {
			mostLetters = letters
			encrypted = h
			decrypted = d
			key = k
		}
	}
	return encrypted, decrypted, key, nil
}
