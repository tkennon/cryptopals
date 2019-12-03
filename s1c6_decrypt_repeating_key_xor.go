package cryptopals

import (
	"errors"
	"math/bits"
)

// HammingDistance returns the Hamming distance between two equal length
// strings.
func HammingDistance(a, b string) (int, error) {
	if len(a) != len(b) {
		return 0, errors.New("strings are of different lengths")
	}
	hd := 0
	for _, byt := range fixedXOR([]byte(a), []byte(b)) {
		hd += bits.OnesCount8(byt)
	}
	return hd, nil
}
