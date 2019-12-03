package cryptopals_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"me/cryptopals"
)

func TestS1C3(t *testing.T) {
	encrypted := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	decrypted, key, err := cryptopals.DecodeSingleByteXOR(encrypted)
	require.NoError(t, err)
	assert.Equal(t, byte(88), key)
	assert.Equal(t, "Cooking MC's like a pound of bacon", decrypted)
}
