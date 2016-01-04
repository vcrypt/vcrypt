package vcrypt

import (
	"errors"
	"io"

	"github.com/vcrypt/vcrypt/material"
	"github.com/vcrypt/vcrypt/payload"
	"github.com/vcrypt/vcrypt/seal"
	"github.com/vcrypt/vcrypt/secret"
)

//go:generate -command protoc protoc --proto_path=$GOPATH/src:$GOPATH/src/github.com/gogo/protobuf/protobuf:. --gogo_out=.
//go:generate protoc cryptex/cryptex.proto cryptex/sss.proto cryptex/xor.proto cryptex/secretbox.proto cryptex/box.proto cryptex/rsa.proto cryptex/openpgp.proto cryptex/mux.proto cryptex/demux.proto
//go:generate protoc material/material.proto
//go:generate protoc payload/payload.proto payload/attached.proto payload/detached.proto
//go:generate protoc seal/seal.proto seal/openpgp.proto
//go:generate protoc secret/secret.proto secret/password.proto secret/openpgpkey.proto secret/sshkey.proto
//go:generate protoc vcrypt.proto marker.proto node.proto plan.proto vault.proto

// Driver is an interface for an interactive vault processor.
type Driver interface {
	material.DB

	// LockPayload encrypts the Reader data and returns the payload and decryption key.
	LockPayload(io.Reader) (payload.Payload, []byte, error)

	// LoadSecret returns the secret data for a Secret.
	LoadSecret(secret.Secret) (data [][]byte, skip bool, err error)
}

// Sealer is an interface for the Seal method.
type Sealer interface {
	// Seal constructs a new seal for the data.
	Seal([]byte) (seal.Seal, error)
}

// Message is a top-level data structure for exporting & importing.
type Message interface {
	// Marshal returns the binary representation of the Message.
	Marshal() (data []byte, err error)

	// Unmarshal parses the Message encoded in data.
	Unmarshal(data []byte) error

	Comment() string
	Digest() ([]byte, error)
}

// Wrap returns an intermediate form of the message for marshalling.
func Wrap(msg Message) (*Envelope, error) {
	env := &Envelope{}
	if !env.SetValue(msg) {
		return nil, errors.New("unknown Message type")
	}
	return env, nil
}

// Message returns the concrete type from the intermediate form.
func (e *Envelope) Message() (Message, error) {
	v := e.GetValue()
	if v == nil {
		return nil, errors.New("invalid Message data")
	}
	return v.(Message), nil
}

// Marshal returns the proto3 encoding of msg.
func Marshal(msg Message) ([]byte, error) {
	env, err := Wrap(msg)
	if err != nil {
		return nil, err
	}
	return env.Marshal()
}

// Unmarshal parses the proto3 encoded message.
func Unmarshal(data []byte) (Message, error) {
	env := &Envelope{}
	if err := env.Unmarshal(data); err != nil {
		return nil, err
	}

	return env.Message()
}

func (e *Envelope) pemType() (string, error) {
	switch {
	case e.Plan != nil:
		return "VCRYPT PLAN", nil
	case e.Material != nil:
		return "VCRYPT MATERIAL", nil
	case e.Vault != nil:
		return "VCRYPT VAULT", nil
	}
	return "", errors.New("unknown Message type")
}
