package payload

import (
	"errors"
	"io"

	"github.com/vcrypt/vcrypt/material"
)

// Payload encrypts and stores the data for a vault.
type Payload interface {
	// Digest is a unique series of bytes that identify the Payload.
	Digest() ([]byte, error)

	// Lock encrypts the data from the Reader and returns ciphertext.
	Lock(io.Reader, material.DB) ([]byte, error)

	// Unlock decrypts the ciphertext and writes the data to the Writer.
	Unlock(io.Writer, []byte, material.DB) error

	// Marshal returns the binary representation of the Payload.
	Marshal() ([]byte, error)

	// Unmarshal parses the Payload encoded in data.
	Unmarshal([]byte) error
}

// Wrap returns an intermediate form of the Payload for marshalling.
func Wrap(p Payload) (*Envelope, error) {
	env := &Envelope{}
	if !env.SetValue(p) {
		return nil, errors.New("unknown Payload type")
	}
	return env, nil
}

// Payload returns the concrete type from the intermediate form.
func (e *Envelope) Payload() (Payload, error) {
	v := e.GetValue()
	if v == nil {
		return nil, errors.New("invalid Payload data")
	}
	return v.(Payload), nil
}

// Marshal returns the proto3 encoding of p.
func Marshal(p Payload) ([]byte, error) {
	env, err := Wrap(p)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Unmarshal parses the proto3 encoded payload.
func Unmarshal(data []byte) (Payload, error) {
	env := &Envelope{}
	if err := env.Unmarshal(data); err != nil {
		return nil, err
	}

	return env.Payload()
}
