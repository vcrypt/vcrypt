package vcrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/benburkert/vcrypt/payload"
	"github.com/benburkert/vcrypt/seal"
)

// NewVault constructs a Vault from a Plan.
func NewVault(plan *Plan, comment string) (*Vault, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Vault{
		comment: comment,
		Plan:    plan,
		Nonce:   nonce,
	}, nil
}

// Comment string
func (v *Vault) Comment() string {
	return v.comment
}

// Digest is a unique series of bytes that identify the Vault.
func (v *Vault) Digest() ([]byte, error) {
	if v.payload == nil {
		return nil, errors.New("unlocked vault has no digest")
	}

	// HMAC(Nonce,Plan.Digest|Materials[*].Digest|Seals[*].Digest|Payload.Digest)
	hash := hmac.New(sha256.New, v.Nonce)

	fp, err := v.Plan.Digest()
	if err != nil {
		return nil, err
	}
	if _, err := hash.Write(fp); err != nil {
		return nil, err
	}

	for _, m := range v.Materials {
		if fp, err = m.Digest(); err != nil {
			return nil, err
		}
		if _, err := hash.Write(fp); err != nil {
			return nil, err
		}
	}

	seals, err := v.Seals()
	if err != nil {
		return nil, err
	}
	for _, s := range seals {
		if fp, err = s.Digest(); err != nil {
			return nil, err
		}
		if _, err := hash.Write(fp); err != nil {
			return nil, err
		}
	}

	pld, err := v.Payload()
	if err != nil {
		return nil, err
	}

	if fp, err = pld.Digest(); err != nil {
		return nil, err
	}
	if _, err := hash.Write(fp); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// Seals are the verifiable seals of the vault.
func (v *Vault) Seals() ([]seal.Seal, error) {
	seals := make([]seal.Seal, 0, len(v.seals))
	for _, env := range v.seals {
		seal, err := env.Seal()
		if err != nil {
			return nil, err
		}
		seals = append(seals, seal)
	}
	return seals, nil
}

// Payload holds the encrypted data protected by the vault.
func (v *Vault) Payload() (payload.Payload, error) {
	return v.payload.Payload()
}
