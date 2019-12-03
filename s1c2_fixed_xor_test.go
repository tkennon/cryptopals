package cryptopals_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"me/cryptopals"
)

func TestS1C2(t *testing.T) {
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
}
