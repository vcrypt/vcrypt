package payload

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"io/ioutil"

	"github.com/vcrypt/vcrypt/material"
	"golang.org/x/crypto/nacl/secretbox"
)

// NewDetached constructs an Detached.
func NewDetached() (*Detached, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Detached{
		Nonce: nonce,
	}, nil
}

// Lock encrypts the data from r using the secretbox encryption scheme from
// NaCl. The nonce & ciphertext are stored in the DB and the secret key is
// returned.
func (p *Detached) Lock(r io.Reader, db material.DB) ([]byte, error) {
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

	out := make([]byte, 24+len(data)+secretbox.Overhead)
	copy(out[:24], nonce[:])

	secretbox.Seal(out[24:24], data, &nonce, &key)

	hash := hmac.New(sha256.New, p.Nonce)

	if _, err := io.Copy(hash, r); err != nil {
		return nil, err
	}
	p.digest = hash.Sum(nil)

	mtrl, err := material.New(p.digest, [][]byte{out})
	if err != nil {
		return nil, err
	}

	if err := db.StoreMaterial(mtrl); err != nil {
		return nil, err
	}

	return key[:], nil
}

// Unlock decrypts the ciphertext retrieved from the DB using the secret key
// and writes the cleartext to w.
func (p *Detached) Unlock(w io.Writer, ks []byte, db material.DB) error {
	mtrl, err := db.LoadMaterial(p.digest)
	if err != nil {
		return err
	}
	if mtrl == nil {
		return errors.New("missing material for detached payload")
	}
	data := mtrl.Data[0]

	nonce, key := [24]byte{}, [32]byte{}
	copy(nonce[:], data[:24])
	copy(key[:], ks[:])

	data, ok := secretbox.Open(nil, data[24:], &nonce, &key)
	if !ok {
		return errors.New("decryption failure")
	}

	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

// Digest is a unique series of bytes that identify the payload.
func (p *Detached) Digest() ([]byte, error) {
	return p.digest, nil
}
