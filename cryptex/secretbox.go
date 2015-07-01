package cryptex

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
)

// NewSecretBox constructs a new SecretBox for a single input.
func NewSecretBox(comment string) *SecretBox {
	return &SecretBox{
		comment: comment,
	}
}

// Comment string
func (c *SecretBox) Comment() string {
	return c.comment
}

// Close seals the secret to the input key. The input key is generated if not
// present in the inputs data.
func (c *SecretBox) Close(inputs, secrets [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("SecretBox supports exactly 2 inputs")
	}
	if len(secrets) != 1 {
		return errors.New("SecretBox supports only a single secret")
	}

	secret := secrets[0]
	nonce := [24]byte{}

	if _, err := rand.Reader.Read(nonce[:]); err != nil {
		return err
	}

	pass := inputs[0]
	if len(pass) == 0 {
		pass = make([]byte, 32)
		if _, err := rand.Reader.Read(pass); err != nil {
			return err
		}
	}
	key := sha256.Sum256(pass)

	out := make([]byte, 24+len(secret)+secretbox.Overhead)
	copy(out[:24], nonce[:])

	secretbox.Seal(out[24:24], secret, &nonce, &key)
	inputs[0] = pass
	inputs[1] = out
	return nil
}

// Open unseals a secret from the key in input data.
func (c *SecretBox) Open(secrets, inputs [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("len(inputs) must be 2")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	key := sha256.Sum256(inputs[0])
	nbox := inputs[1]

	if len(nbox) < 24+secretbox.Overhead {
		return errors.New("invalid box")
	}
	nonce := [24]byte{}
	copy(nonce[:], nbox[:24])
	box := nbox[24:]

	secret, ok := secretbox.Open(nil, box, &nonce, &key)
	if !ok {
		return errors.New("decryption failure")
	}

	secrets[0] = secret
	return nil
}
