package cryptopals

import (
	"bytes"
	"crypto/aes"
)

func PadPKCS7(input []byte, blockSize uint8) []byte {
	if blockSize == 0 {
		// Definitely a mistake, but we will do as told: append bytes with value
		// zero so that len(input) is a multiple of 0. This is trivially true,
		// so return the input unchanged.
		return input
	}

	remainder := len(input) % int(blockSize)
	toPad := blockSize - uint8(remainder)
	padding := bytes.Repeat([]byte{toPad}, int(toPad))
	return append(input, padding...)
}

// EncryptXORCBC takes plaintext, encrypts it by XORing it with the key, and
// appends blocks in CBC mode. The block size is assumed to be the keysize. The
// initialisation vector must have the same length (blocksize) as the key.
func EncryptXORCBC(iv, key, plaintext []byte) []byte
func DecryptAES128ECB(key, ciphertext []byte) (plaintext []byte, err error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := 16 // 128 bits.
	for len(ciphertext) > 0 {
		block := ciphertext[:blockSize]
		dst := make([]byte, blockSize)
		cipherBlock.Encrypt(dst, block)
		plaintext = append(plaintext, dst...)
		ciphertext = ciphertext[blockSize:]
	}

	return plaintext, nil
}
