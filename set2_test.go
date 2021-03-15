package cryptopals_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tkennon/cryptopals"
)

func TestSet2Challenge9(t *testing.T) {
	input := "YELLOW SUBMARINE"
	blockSize := uint8(20)
	expectedOutput := "YELLOW SUBMARINE\x04\x04\x04\x04"

	assert.Equal(t, []byte(expectedOutput), cryptopals.PadPKCS7([]byte(input), blockSize))
}
