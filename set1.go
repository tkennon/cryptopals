package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/bits"
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

// HexToBase64 takes a hex-encoded string and returns it as a base-64 encoded
// string.
func HexToBase64(h string) (string, error) {
	r, err := FromHex(h)
	if err != nil {
		return "", err
	}
	return ToBase64(r), nil
}

// Base64ToHex takes a base64-encoded string and returns it as a hex-encoded
// string.
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

// DecodeSingleByteXOR takes a hex-encoded string as input and attempts to
// decrypt it assuming it has been encrypted with a single character block
// cipher.
func DecodeSingleByteXOR(h string) (plaintext string, key byte, err error) {
	raw, err := FromHex(h)
	if err != nil {
		return "", 0, err
	}

	rawPlaintext, key := decodeSingleByteXOR(raw)

	return string(rawPlaintext), key, nil
}

func decodeSingleByteXOR(ciphertext []byte) (plaintext []byte, key byte) {
	// For each one-byte value, XOR the raw bytes. Then check if the resulting
	// string looks like common English.
	mostChars := 0
	for i := 0; i < 256; i++ {
		b := []byte{byte(i)}
		xor := fixedXOR(ciphertext, bytes.Repeat(b, len(ciphertext)))
		chars := 0
		for _, c := range string(xor) {
			if unicode.IsLetter(c) || unicode.IsSpace(c) || unicode.IsNumber(c) {
				chars++
			}
		}
		if chars > mostChars {
			mostChars = chars
			key = byte(i)
			plaintext = xor
		}
	}

	return plaintext, key
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

// DetectSingleByteXOR takes as input a slice of hex-encoded ciphertexts, and
// determines which one of them has been encrypted with a single byte XOR. It
// returns the siphertext, the plaintext, the encryption key, and
// any error.
func DetectSingleByteXOR(hs []string) (ciphertext, plaintext string, key byte, err error) {
	mostLetters := 0
	for _, h := range hs {
		d, k, err := DecodeSingleByteXOR(h)
		if err != nil {
			return "", "", 0, err
		}
		if letters := countCommonChars(d); letters > mostLetters {
			mostLetters = letters
			ciphertext = h
			plaintext = d
			key = k
		}
	}
	return ciphertext, plaintext, key, nil
}

//
// Challenge 5
//

// EncryptRepeatingKeyXOR encrypts the input plaintext using the provided key
// using repeated XOR encryption. If no kqey is given, then the input is
// returned unchanged.
func EncryptRepeatingKeyXOR(key, plaintext []byte) []byte {
	keylen := len(key)
	if keylen == 0 {
		return plaintext
	}

	var ciphertext []byte
	for i, b := range plaintext {
		ciphertext = append(ciphertext, key[i%keylen]^b)
	}
	return ciphertext
}

// DecryptRepeatingKeyXOR decrypts the input ciphertext using the provided key
// using repeated XOR decryption. If not key is given then the input is return
// unchanged.
func DecryptRepeatingKeyXOR(key, ciphertext []byte) []byte {
	// Symmetry!
	return EncryptRepeatingKeyXOR(key, ciphertext)
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
	hammingDistance := 0
	for _, byt := range fixedXOR(a, b) {
		hammingDistance += bits.OnesCount8(byt)
	}
	return hammingDistance, nil
}

func NormalisedHammingDistance(input []byte, blockSize int) float64 {
	numBlocks := len(input) / blockSize
	cumulativeHD := 0
	numHDs := 0
	for i := 0; i < numBlocks; i++ {
		for j := 0; j < numBlocks; j++ {
			if i == j {
				continue
			}
			block1 := input[i*blockSize : (i+1)*blockSize]
			block2 := input[j*blockSize : (j+1)*blockSize]
			hd, err := HammingDistance(block1, block2)
			if err != nil {
				panic(err)
			}
			cumulativeHD += hd
			numHDs++
		}
	}

	return float64(cumulativeHD) / float64(numHDs*8*blockSize)
}

func BreakRepeatingKeyXOR(ciphertext []byte, maxKeysize int) ([]byte, error) {
	if len(ciphertext) == 0 {
		// Empty data can't be encrypted, so is trivially decrypted!
		return nil, nil
	}

	// For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
	// KEYSIZE worth of bytes, and find the edit distance between them.
	// Normalize this result by dividing by KEYSIZE.
	//
	// The KEYSIZE with the smallest normalized edit distance is probably the
	// key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or
	// take 4 KEYSIZE blocks instead of 2 and average the distances.
	if len(ciphertext)/2 < maxKeysize {
		maxKeysize = len(ciphertext) / 2
	}

	var (
		mostLikelyKeysize = 1
		smallestNHD       = 1.0
	)
	for keysize := 1; keysize <= maxKeysize; keysize++ {
		nhd := NormalisedHammingDistance(ciphertext, keysize)
		if nhd < smallestNHD {
			smallestNHD = nhd
			mostLikelyKeysize = keysize
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
	for i := 0; i < len(blocks[0]); i++ {
		for _, block := range blocks {
			if i < len(block) {
				transposed[i] = append(transposed[i], block[i])
			}
		}
	}

	// Solve each block as if it was single-character XOR. You already have code
	// to do this. For each block, the single-byte XOR key that produces the
	// best looking histogram is the repeating-key XOR key byte for that block.
	// Put them together and you have the key.
	var repeatingXORKey []byte
	for _, block := range transposed {
		_, key := decodeSingleByteXOR(block)
		repeatingXORKey = append(repeatingXORKey, key)
	}

	return DecryptRepeatingKeyXOR(repeatingXORKey, ciphertext), nil
}

// DecryptAES128ECB decrypts a ciphertext that has been encrypted using the
// given key, and a block size of 128 bits in the ECB mode.
func DecryptAES128ECB(key, ciphertext []byte) (plaintext []byte, err error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := 16 // 128 bits.
	for len(ciphertext) > 0 {
		block := ciphertext[:blockSize]
		dst := make([]byte, blockSize)
		cipherBlock.Decrypt(dst, block)
		plaintext = append(plaintext, dst...)
		ciphertext = ciphertext[blockSize:]
	}

	return plaintext, nil
}

func IsAES128ECB(ciphertext []byte) bool {
	chunks := make(map[string]uint)
	blockSize := 16 // 128 bits.
	for len(ciphertext) > 0 {
		block := ciphertext[:blockSize]
		chunks[string(block)] = chunks[string(block)] + 1
		ciphertext = ciphertext[blockSize:]
	}

	// There are 2^128 different possible values for a 16-byte block. For a
	// random input the chance of two different 16-byte blocks having the same
	// value are (2^-128 * len(input)/16) which is tiny for any input that could
	// reasonably be saved on disk. Therefore if we do find two blocks that are
	// same we can safely assume that the input is not random, and therefore the
	// block encoding is likely ECB.
	for _, frequency := range chunks {
		if frequency > 2 {
			return true
		}
	}
	return false
}
