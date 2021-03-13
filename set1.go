package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strings"
	"unicode"
)

//
// Challenge 1
//

// FromHex converts a hex-encoded string into raw bytes.
func FromHex(h string) ([]byte, error) {
	return hex.DecodeString(h)
}

// ToHex converts raw bytes into a hex-encoded string.
func ToHex(r []byte) string {
	return hex.EncodeToString(r)
}

// FromBase64 converts a base64-encoded string into raw bytes.
func FromBase64(b64 string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b64)
}

// ToBase64 converts raw bytes into a base64-encoded string.
func ToBase64(r []byte) string {
	return base64.StdEncoding.EncodeToString(r)
}

// HexToBase64 takes a hex-encoded string and returns it as a base-64 encoded string.
func HexToBase64(h string) (string, error) {
	r, err := FromHex(h)
	if err != nil {
		return "", err
	}
	return ToBase64(r), nil
}

// Base64ToHex takes a base64-encoded string and returns it as a hex-encoded string.
func Base64ToHex(b64 string) (string, error) {
	r, err := FromBase64(b64)
	if err != nil {
		return "", err
	}
	return ToHex(r), nil
}

//
// Challenge 2
//

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

//
// Challenge 3
//

// ToString converts a raw byte slice into a string.
func ToString(r []byte) string {
	return string(r)
}

// DecodeSingleByteXOR takes a hex-encoded string as input and attempts to
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

//
// Challenge 4
//

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

//
// Challenge 5
//

// EncryptRepeatingKeyXOR encrypts the input using the provided key using
// repeated XOR encryption. If no key is given, then the input is returned
// unchanged.
func EncryptRepeatingKeyXOR(key, input []byte) []byte {
	if len(key) == 0 {
		return input
	}

	var output []byte
	for i, b := range input {
		output = append(output, key[i%len(key)]^b)
	}
	return output
}

//
// Challenge 6
//

// HammingDistance returns the Hamming distance between two equal length
// strings.
func HammingDistance(a, b []byte) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("inputs are of different lengths")
	}
	hd := 0
	for _, byt := range fixedXOR(a, b) {
		hd += bits.OnesCount8(byt)
	}
	return hd, nil
}

func BreakRepeatingKeyXOR(ciphertext []byte, maxKeysize int) ([]byte, error) {
	if len(ciphertext) == 0 {
		// Empty data data be encrypted.
		return nil, nil
	}

	// For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
	// KEYSIZE worth of bytes, and find the edit distance between them.
	// Normalize this result by dividing by KEYSIZE.
	//
	// The KEYSIZE with the smallest normalized edit distance is probably the
	// key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or
	// take 4 KEYSIZE blocks instead of 2 and average the distances.
	nhdToKeysizes := make(map[int]float64)
	if len(ciphertext)/2 < maxKeysize {
		maxKeysize = len(ciphertext) / 2
	}
	for keysize := 1; keysize <= maxKeysize; keysize++ {
		first := ciphertext[:keysize]
		second := ciphertext[keysize : 2*keysize]
		hd, err := HammingDistance(first, second)
		if err != nil {
			return nil, fmt.Errorf("could not compute Hamming Distance for keysize %d: %w", keysize, err)
		}
		nhdToKeysizes[keysize] = float64(hd) / float64(keysize)
	}
	var nhds []float64
	for _, nhd := range nhdToKeysizes {
		nhds = append(nhds, nhd)
	}
	fmt.Println(nhdToKeysizes)
	sort.Float64s(nhds)
	mostLikelyKeysize := 0
	for ks, nhd := range nhdToKeysizes {
		if nhds[0] == nhd {
			mostLikelyKeysize = ks
			fmt.Println("XXXTK: keysize used", mostLikelyKeysize)
			fmt.Println("XXXTK: normalised HD", nhd)
			break
		}
	}

	// Now that you probably know the KEYSIZE: break the ciphertext into blocks
	// of KEYSIZE length.
	var blocks [][]byte
	ct := make([]byte, len(ciphertext))
	copy(ct, ciphertext)
	for len(ct) > 0 {
		size := mostLikelyKeysize
		if size > len(ct) {
			size = len(ct)
		}
		blocks = append(blocks, ct[:size])
		ct = ct[size:]
	}

	// Now transpose the blocks: make a block that is the first byte of every
	// block, and a block that is the second byte of every block, and so on.
	transposed := make([][]byte, len(blocks[0]))
	for _, block := range blocks {
		for i, b := range block {
			transposed[i] = append(transposed[i], b)
		}
	}

	// Solve each block as if it was single-character XOR. You already have code
	// to do this.
	var repeatingXORKey []byte
	for _, t := range transposed {
		hex := ToHex(t)
		_, key, err := DecodeSingleByteXOR(hex)
		if err != nil {
			return nil, fmt.Errorf("unable to decode single byte XOR: %w", err)
		}

		// For each block, the single-byte XOR key that produces the best
		// looking histogram is the repeating-key XOR key byte for that block.
		// Put them together and you have the key.
		repeatingXORKey = append(repeatingXORKey, key)
	}
	fmt.Println(ToString(repeatingXORKey))
	fmt.Println(len(repeatingXORKey))
	fmt.Println(len(ciphertext))

	var decrypted []byte
	l := len(repeatingXORKey)
	for len(ciphertext) > 0 {
		size := l
		if len(ciphertext) < l {
			size = len(ciphertext)
		}
		d, err := FixedXOR(repeatingXORKey[:size], ciphertext[:size])
		if err != nil {
			return nil, err
		}
		ciphertext = ciphertext[size:]
		decrypted = append(decrypted, d...)

	}
	return decrypted, nil
}
