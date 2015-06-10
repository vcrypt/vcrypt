package seal

import "errors"

// Seal holds a verifiable signature.
type Seal interface {
	// Check verifies the seal for the data.
	Check(data []byte) error

	// Digest returns a unique series of bytes that identify the Seal.
	Digest() ([]byte, error)

	// Marshal returns the binary representation of the Seal.
	Marshal() (data []byte, err error)

	// Unmarshal parses the Seal encoded in data.
	Unmarshal(data []byte) error
}

// Wrap returns an intermediate form of the Seal for marshalling.
func Wrap(s Seal) (*Envelope, error) {
	env := &Envelope{}
	if !env.SetValue(s) {
		return nil, errors.New("unknown Seal type")
	}
	return env, nil
}

// Seal returns the concrete type from the intermediate form.
func (e *Envelope) Seal() (Seal, error) {
	v := e.GetValue()
	if v == nil {
		return nil, errors.New("invalid Seal data")
	}
	return v.(Seal), nil
}

// Marshal returns the proto3 encoding of s.
func Marshal(s Seal) ([]byte, error) {
	env, err := Wrap(s)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Unmarshal parses the proto3 encoded seal.
func Unmarshal(data []byte) (Seal, error) {
	env := &Envelope{}
	if err := env.Unmarshal(data); err != nil {
		return nil, err
	}

	return env.Seal()
}
