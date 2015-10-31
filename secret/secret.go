package secret

import (
	"errors"
	"io"
)

// Phase marks the time at which a Secret input is expected.
type Phase int

const (
	// Unlock denotes a secret input for unlocking a vault.
	Unlock Phase = iota

	// Dual denotes a secret input for both locking & unlocking a vault.
	Dual
)

// Secret represents an input secret of a certain medium e.g. an RSA private
// key or a password.
type Secret interface {
	// Optional description of the secret usage.
	Comment() string

	// Marker for the point at which the secret input is required.
	Phase() Phase

	// Load the secret data from the Reader and return the internal form.
	Load(r io.Reader) ([][]byte, error)

	// Marshal returns the binary representation of the Secret.
	Marshal() (data []byte, err error)

	// Unmarshal parses the Secret encoded in data.
	Unmarshal(data []byte) error
}

// Wrap returns an intermediate form of the secret for marshalling.
func Wrap(sec Secret) (*Envelope, error) {
	env := &Envelope{}
	if !env.SetValue(sec) {
		return nil, errors.New("unknown Secret type")
	}
	return env, nil
}

// Secret returns the concrete type from the intermediate form.
func (e *Envelope) Secret() (Secret, error) {
	v := e.GetValue()
	if v == nil {
		return nil, errors.New("invalid Secret data")
	}
	return v.(Secret), nil
}

// Marshal returns the proto3 encoding of sec.
func Marshal(sec Secret) ([]byte, error) {
	env, err := Wrap(sec)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Unmarshal parses the proto3 encoded secret.
func Unmarshal(data []byte) (Secret, error) {
	env := &Envelope{}
	if err := env.Unmarshal(data); err != nil {
		return nil, err
	}

	return env.Secret()
}
