package cryptopals

import (
	"bytes"
	"unicode"
)

// ToString converts a raw byte slice into a string.
func ToString(r []byte) string {
	return string(r)
}

// DecodeSingleByteXOR takes a hex-encded string as input and attempts to
// decrypt it assuming it has been encrypted with a single character block
// cipher.
func DecodeSingleByteXOR(h string) (decrypted string, key byte, err error) {
	raw, err := FromHex(h)
	if err != nil {
		return "", 0, err
	}
	// For each one-byte value, XOR the raw bytes. Then check if the resulting
	// string looks like common English.
	mostChars := 0
	for i := 0; i < 256; i++ {
		b := []byte{byte(i)}
		xor := fixedXOR(raw, bytes.Repeat(b, len(raw)))
		xorStr := ToString(xor)
		chars := 0
		for _, c := range xorStr {
			if unicode.IsLetter(c) {
				chars++
			}
		}
		if chars > mostChars {
			mostChars = chars
			key = b[0]
			decrypted = xorStr
		}
	}
	return decrypted, key, nil
}
