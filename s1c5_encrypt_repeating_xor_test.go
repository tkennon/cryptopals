package cryptopals_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tkennon/cryptopals"
)

func TestS1C5(t *testing.T) {
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := []byte("ICE")
	wanted := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	encrypted := cryptopals.EncryptRepeatingKeyXOR(key, []byte(input))
	assert.Equal(t, wanted, cryptopals.ToHex(encrypted))
}
