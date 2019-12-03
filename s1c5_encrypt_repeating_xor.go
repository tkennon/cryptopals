package cryptopals

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
