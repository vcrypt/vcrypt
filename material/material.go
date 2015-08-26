package material

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

// New constructs a new Material for an id & data.
func New(id []byte, data [][]byte) (*Material, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Material{
		Data:  data,
		ID:    id,
		Nonce: nonce,
	}, nil
}

// Comment string
func (m *Material) Comment() string { return m.comment }

// Digest returns a unique series of bytes that identify the Material.
func (m *Material) Digest() ([]byte, error) {
	// SHA256(Nonce,ID|Data[*])
	hash := hmac.New(sha256.New, m.Nonce)

	if _, err := hash.Write(m.ID); err != nil {
		return nil, err
	}

	for _, chunk := range m.Data {
		if _, err := hash.Write(chunk); err != nil {
			return nil, err
		}
	}

	return hash.Sum(nil), nil
}
