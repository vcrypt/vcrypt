package cryptex

import (
	"bytes"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// NewBox constructs a new Box for the PublicKey keypair.
func NewBox(publicKey []byte, comment string) *Box {
	return &Box{
		PublicKey: publicKey,
		comment:   comment,
	}
}

// Comment string
func (c *Box) Comment() string {
	return c.comment
}

// Close seals the secret using PublicKey. The ciphertext is stored in the
// input data.
func (c *Box) Close(inputs, secrets [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) != 2 {
		return errors.New("SecretBox requires 2 input")
	}
	if len(secrets) != 1 {
		return errors.New("SecretBox supports 1 secret")
	}
	secret := secrets[0]

	pkey, skey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	nonce, peerkey := [24]byte{}, [32]byte{}
	copy(peerkey[:], c.PublicKey)

	if _, err := rand.Reader.Read(nonce[:]); err != nil {
		return err
	}

	out := make([]byte, 56+len(secret)+box.Overhead)
	copy(out[:32], pkey[:])
	copy(out[32:56], nonce[:])

	box.Seal(out[56:56], secret, &nonce, &peerkey, skey)

	inputs[0] = out
	inputs[1] = nil
	return nil
}

// Open unseals a secret from the ciphertext & private key portions of the
// input data.
func (c *Box) Open(secrets, inputs [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) != 2 {
		return errors.New("len(inputs) must be 2")
	}

	keySlice := inputs[1]
	if len(keySlice) != 32 {
		return errors.New("invalid private key")
	}
	pkey, skey := [32]byte{}, [32]byte{}
	copy(skey[:], keySlice)

	curve25519.ScalarBaseMult(&pkey, &skey)
	if !bytes.Equal(pkey[:], c.PublicKey) {
		return errors.New("wrong private key for public key")
	}

	nbox := inputs[0]

	if len(nbox) < 24+box.Overhead {
		return errors.New("invalid box")
	}
	peerkey, nonce := [32]byte{}, [24]byte{}
	copy(peerkey[:], nbox[:32])
	copy(nonce[:], nbox[32:56])
	ctext := nbox[56:]

	secret, ok := box.Open(nil, ctext, &nonce, &peerkey, &skey)
	if !ok {
		return errors.New("decryption failure")
	}

	secrets[0] = secret
	return nil
}

func (c *Box) validate() error {
	if len(c.PublicKey) == 0 {
		return errors.New("PublicKey missing")
	}
	if len(c.PublicKey) != 32 {
		return errors.New("PublicKey must be 32 bytes")
	}
	return nil
}
