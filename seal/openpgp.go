package seal

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// NewOpenPGP constructs an OpenPGP seal from an OpenPGP entity and signing data.
// The entity must contain a signing private key.
func NewOpenPGP(signer *openpgp.Entity, data []byte) (*OpenPGP, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	var sb, eb bytes.Buffer
	if err := openpgp.DetachSign(&sb, signer, bytes.NewBuffer(data), nil); err != nil {
		return nil, err
	}

	if err := signer.Serialize(&eb); err != nil {
		return nil, err
	}

	return &OpenPGP{
		Nonce:     nonce,
		Entity:    eb.Bytes(),
		Signature: sb.Bytes(),
	}, nil
}

// Check verifies the OpenPGP signature for the data using the signing public
// key in the entity.
func (s *OpenPGP) Check(data []byte) error {
	r := packet.NewReader(bytes.NewBuffer(s.Entity))
	e, err := openpgp.ReadEntity(r)
	if err != nil {
		return err
	}

	_, err = openpgp.CheckDetachedSignature(openpgp.EntityList([]*openpgp.Entity{e}), bytes.NewBuffer(data), bytes.NewBuffer(s.Signature))
	return err
}

// Digest returns an HMAC of the entity and signature data.
func (s *OpenPGP) Digest() ([]byte, error) {
	// HMAC(Nonce,Entity|Signature)
	hash := hmac.New(sha256.New, s.Nonce)

	if _, err := hash.Write(s.Entity); err != nil {
		return nil, err
	}

	if _, err := hash.Write(s.Signature); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
