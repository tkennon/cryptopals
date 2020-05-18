package cryptopals_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tkennon/cryptopals"
)

func TestS1C1(t *testing.T) {
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
}
