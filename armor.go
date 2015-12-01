package vcrypt

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// Armor returns the PEM encoded msg data.
func Armor(msg Message) ([]byte, error) {
	env, err := Wrap(msg)
	if err != nil {
		return nil, err
	}

	data, err := env.Marshal()
	if err != nil {
		return nil, err
	}

	fp, err := msg.Digest()
	if err != nil {
		return nil, err
	}

	pemType, err := env.pemType()
	if err != nil {
		return nil, err
	}

	p := &pem.Block{
		Type:  pemType,
		Bytes: data,
		Headers: map[string]string{
			"Digest": base64.StdEncoding.EncodeToString(fp),
		},
	}

	if cmnt := msg.Comment(); cmnt != "" {
		p.Headers["Comment"] = cmnt
	}

	return pem.EncodeToMemory(p), nil
}

// Unarmor constructs a Message from the PEM encoded data.
func Unarmor(data []byte) (Message, []byte, error) {
	p, rest := pem.Decode(data)
	if p == nil {
		return nil, rest, errors.New("invalid armored Message")
	}

	msg, err := Unmarshal(p.Bytes)
	if err != nil {
		return nil, rest, err
	}
	return msg, rest, nil
}
