package payload

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/secretbox"
)

// NewAttached constructs an Attached.
func NewAttached() (*Attached, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Attached{
		Nonce: nonce,
	}, nil
}

// Lock encrypts the data from r using the secretbox encryption scheme from
// NaCl and returns the secret key.
func (p *Attached) Lock(r io.Reader) ([]byte, error) {
	nonce, key := [24]byte{}, [32]byte{}
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, err
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	p.Data = make([]byte, 24+len(data)+secretbox.Overhead)
	copy(p.Data[:24], nonce[:])

	secretbox.Seal(p.Data[24:24], data, &nonce, &key)

	return key[:], nil
}

// Unlock decrypts ciphertext the from the attached data with the secret key
// and writes the cleartext to w.
func (p *Attached) Unlock(w io.Writer, ks []byte) error {
	nonce, key := [24]byte{}, [32]byte{}
	copy(nonce[:], p.Data[:24])
	copy(key[:], ks[:])

	data, ok := secretbox.Open(nil, p.Data[24:], &nonce, &key)
	if !ok {
		return errors.New("decryption failure")
	}

	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

// Digest is a unique series of bytes that identify the payload.
func (p *Attached) Digest() ([]byte, error) {
	// HMAC(Nonce, Block.Data)
	hash := hmac.New(sha256.New, p.Nonce)

	if _, err := hash.Write(p.Data); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
