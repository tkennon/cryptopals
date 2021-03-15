package cryptopals_test

import (
	"io/ioutil"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tkennon/cryptopals"
)

func getTestInput(t *testing.T) []byte {
	input, err := ioutil.ReadFile(filepath.Join("testdata", t.Name()+".input"))
	require.NoError(t, err)
	return input
}

func getTestExpectedOutput(t *testing.T) []byte {
	output, err := ioutil.ReadFile(filepath.Join("testdata", t.Name()+".output"))
	require.NoError(t, err)
	return output
}

func TestSet1Challenge1(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	wanted := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	// In steps.
	raw, err := cryptopals.FromHex(input)
	require.NoError(t, err)
	assert.Equal(t, wanted, cryptopals.ToBase64(raw))

	// As one.
	b64, err := cryptopals.HexToBase64(input)
	require.NoError(t, err)
	assert.Equal(t, wanted, b64)

	// And back again.
	hex, err := cryptopals.Base64ToHex(b64)
	require.NoError(t, err)
	assert.Equal(t, input, hex)

}

func TestSet1Challenge2(t *testing.T) {
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	wanted := "746865206b696420646f6e277420706c6179"

	// In steps.
	raw1, err := cryptopals.FromHex(input1)
	require.NoError(t, err)
	raw2, err := cryptopals.FromHex(input2)
	require.NoError(t, err)
	xor, err := cryptopals.FixedXOR(raw1, raw2)
	require.NoError(t, err)
	assert.Equal(t, wanted, cryptopals.ToHex(xor))

	// As one.
	xorStr, err := cryptopals.FixedHexXOR(input1, input2)
	require.NoError(t, err)
	assert.Equal(t, wanted, xorStr)

	// Check byte slices with mismatching lengths are rejected.
	_, err = cryptopals.FixedXOR([]byte("crypto"), []byte("pals"))
	assert.Error(t, err)
}

func TestSet1Challenge3(t *testing.T) {
	encrypted := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	decrypted, key, err := cryptopals.DecodeSingleByteXOR(encrypted)
	require.NoError(t, err)
	assert.Equal(t, byte(88), key)
	assert.Equal(t, "Cooking MC's like a pound of bacon", decrypted)
}

func TestSet1Challenge4(t *testing.T) {
	input := getTestInput(t)
	ciphertexts := strings.Split(string(input), "\n")

	ciphertext, plaintext, key, err := cryptopals.DetectSingleByteXOR(ciphertexts)
	require.NoError(t, err)
	assert.Equal(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f", ciphertext)
	assert.Equal(t, byte(0x35), key)
	assert.Equal(t, "Now that the party is jumping\n", plaintext)
}

func TestSet1Challenge5(t *testing.T) {
	plaintext := []byte(`Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`)

	// Check empty key.
	assert.Equal(t, plaintext, cryptopals.EncryptRepeatingKeyXOR(nil, plaintext))

	// Now check a non-empty key.
	key := []byte("ICE")
	wanted := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := cryptopals.EncryptRepeatingKeyXOR(key, plaintext)
	assert.Equal(t, wanted, cryptopals.ToHex(encrypted))
}

func TestHammingDistance(t *testing.T) {
	hd, err := cryptopals.HammingDistance([]byte("this is a test"), []byte("wokka wokka!!!"))
	require.NoError(t, err)
	assert.Equal(t, 37, hd)
}
func TestSet1Challenge6(t *testing.T) {
	input := getTestInput(t)
	expectedPlaintext := getTestExpectedOutput(t)

	ciphertext := strings.ReplaceAll(string(input), "\n", "")
	rawCiphertext, err := cryptopals.FromBase64(ciphertext)
	require.NoError(t, err)
	plaintext, err := cryptopals.BreakRepeatingKeyXOR(rawCiphertext, 40)
	require.NoError(t, err)
	assert.Equal(t, expectedPlaintext, plaintext)
}

func TestSet1Challenge7(t *testing.T) {
	input := getTestInput(t)
	ciphertext, err := cryptopals.FromBase64(string(input))
	require.NoError(t, err)
	expectedPlaintext := getTestExpectedOutput(t)

	key := []byte("YELLOW SUBMARINE")
	plaintext, err := cryptopals.DecryptAES128ECB(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, expectedPlaintext, plaintext)
}

func TestSet1Challenge8(t *testing.T) {
	input := getTestInput(t)
	lines := strings.Split(string(input), "\n")
	var found []string
	for _, line := range lines {
		if cryptopals.IsAES128ECB([]byte(line)) {
			found = append(found, line)
		}
	}

	assert.Equal(t, 1, len(found))
	assert.Equal(t, "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a", found[0])
}
