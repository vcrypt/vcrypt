package cryptex

import (
	"crypto/rand"
	"errors"
	"io"
)

// NewXOR constructs a new XOR for the input parts.
func NewXOR(comment string) *XOR {
	return &XOR{
		comment: comment,
	}
}

// Comment string
func (c *XOR) Comment() string {
	return c.comment
}

// Close seals the secret to the xor of all the generated inputs.
func (c *XOR) Close(inputs, secrets [][]byte) error {
	if len(secrets) != 1 {
		return errors.New("XOR supports only a single secret")
	}
	secret := secrets[0]

	slen := len(secret)
	buf := make([]byte, slen)
	copy(buf, secret)

	for i := range inputs[1:] {
		idx := i + 1
		input := make([]byte, slen)
		if _, err := io.ReadFull(rand.Reader, input); err != nil {
			return err
		}
		inputs[idx] = input

		for j := range input {
			buf[j] = buf[j] ^ input[j]
		}
	}

	inputs[0] = buf
	return nil
}

// Open unseals the secret by xor'ing all inputs data.
func (c *XOR) Open(secrets, inputs [][]byte) error {
	if nonNilLen(inputs) != len(inputs) {
		return errors.New("XOR requires inputs to be non-nil")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	buf := make([]byte, len(inputs[0]))
	copy(buf, inputs[0])

	for _, input := range inputs[1:] {
		for i := range input {
			buf[i] = buf[i] ^ input[i]
		}
	}

	secrets[0] = buf
	return nil
}
