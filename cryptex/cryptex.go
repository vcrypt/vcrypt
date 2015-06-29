package cryptex

import "errors"

// Cryptex lock intermediate secrets.
type Cryptex interface {
	// Optional description of the cryptex usage.
	Comment() string

	// Close encloses the inputs into the secret.
	Close(inputs, secrets [][]byte) error

	// Open unwraps the secrets contained in the inputs.
	Open(secrets, inputs [][]byte) error

	// Marshal returns the binary representation of the Cryptex.
	Marshal() (data []byte, err error)

	// Unmarshal parses the Cryptex encoded in data.
	Unmarshal(data []byte) error
}

// Wrap returns an intermediate form of the cryptex for marshalling.
func Wrap(cptx Cryptex) (*Envelope, error) {
	env := &Envelope{}
	if !env.SetValue(cptx) {
		return nil, errors.New("unknown Cryptex type")
	}
	return env, nil
}

// Cryptex returns the concrete type from the intermediate form.
func (e *Envelope) Cryptex() (Cryptex, error) {
	v := e.GetValue()
	if v == nil {
		return nil, errors.New("invalid Cryptex data")
	}
	return v.(Cryptex), nil
}

// Marshal returns the proto3 encoding of cptx.
func Marshal(cptx Cryptex) ([]byte, error) {
	env, err := Wrap(cptx)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Unmarshal parses the proto3 encoded cryptex.
func Unmarshal(data []byte) (Cryptex, error) {
	env := &Envelope{}
	if err := env.Unmarshal(data); err != nil {
		return nil, err
	}

	return env.Cryptex()
}
