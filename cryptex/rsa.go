package cryptex

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
)

// NewRSA constructs a new RSA for the RSA PublicKey pair.
func NewRSA(publicKey []byte, comment string) *RSA {
	return &RSA{
		PublicKey: publicKey,
		comment:   comment,
	}
}

// Comment string
func (c *RSA) Comment() string {
	return c.comment
}

// Close seals the secret using OAEP encryption with the PublicKey. The
// ciphertext is stored in the input data.
func (c *RSA) Close(inputs, secrets [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("RSA supports exactly 2 inputs")
	}
	if len(secrets) != 1 {
		return errors.New("RSA supports only a single secret")
	}
	secret := secrets[0]

	pubKey, err := c.publicKey()
	if err != nil {
		return err
	}
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, secret, nil)
	if err != nil {
		return err
	}

	inputs[0] = ct
	inputs[1] = nil
	return nil
}

// Open unseals a secret using OAEP decryption from the ciphertext & RSA
// private key portions of the input data.
func (c *RSA) Open(secrets, inputs [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("len(inputs) must be 2")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	ct := inputs[0]
	privKey, err := x509.ParsePKCS1PrivateKey(inputs[1])
	if err != nil {
		return err
	}

	secret, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, ct, nil)
	if err != nil {
		return err
	}

	secrets[0] = secret
	return nil
}

func (c *RSA) publicKey() (*rsa.PublicKey, error) {
	pubKey, err := x509.ParsePKIXPublicKey(c.PublicKey)
	if err != nil {
		return nil, err
	}
	if pubKey, ok := pubKey.(*rsa.PublicKey); ok {
		return pubKey, nil
	}
	return nil, errors.New("invalid RSA public key")
}
