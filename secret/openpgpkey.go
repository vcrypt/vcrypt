package secret

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
)

// NewOpenPGPKey constructs a OpenPGPKey secret for one or more encryption key
// ids.
func NewOpenPGPKey(keyIDs []uint64, comment string) *OpenPGPKey {
	return &OpenPGPKey{
		KeyIDs:  keyIDs,
		comment: comment,
	}
}

// Comment string
func (s *OpenPGPKey) Comment() string {
	return s.comment
}

// Phase is Unlock
func (s *OpenPGPKey) Phase() Phase { return Unlock }

// Load reads the input data and returns one or more serialized OpenPGP
// encryption keys for the key ids.
func (s *OpenPGPKey) Load(r io.Reader) ([][]byte, error) {
	el, err := openpgp.ReadKeyRing(r)
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(nil)
	for _, id := range s.KeyIDs {

		keys := el.KeysById(id)
		if len(keys) > 0 {
			keys[0].Entity.SerializePrivate(w, nil)
		}
	}

	if w.Len() == 0 {
		return nil, errors.New("missing openpgp key(s)")
	}

	return [][]byte{w.Bytes()}, nil
}
