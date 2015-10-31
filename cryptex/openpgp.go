package cryptex

import (
	"bytes"
	"errors"
	"io/ioutil"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// NewOpenPGP constructs a new OpenPGP for one or more entities containing a
// public key for encryption.
func NewOpenPGP(entities []*openpgp.Entity, comment string) (*OpenPGP, error) {
	entBytes := [][]byte{}
	for _, entity := range entities {
		buf := bytes.NewBuffer(nil)
		if err := entity.Serialize(buf); err != nil {
			return nil, err
		}
		entBytes = append(entBytes, buf.Bytes())
	}

	return &OpenPGP{
		Entities: entBytes,
		comment:  comment,
	}, nil
}

// Comment string
func (c *OpenPGP) Comment() string {
	return c.comment
}

// Close seals a single secret by encrypting with the public keys from the
// entities.
func (c *OpenPGP) Close(inputs, secrets [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("OpenPGP supports exactly 2 inputs")
	}
	if len(secrets) != 1 {
		return errors.New("OpenPGPsupports only a single secret")
	}
	secret := secrets[0]

	ctBuf := bytes.NewBuffer(nil)
	entities, err := c.entities()
	if err != nil {
		return err
	}

	pt, err := openpgp.Encrypt(ctBuf, entities, nil, nil, nil)
	if err != nil {
		return err
	}

	if _, err := pt.Write(secret); err != nil {
		return err
	}
	if err := pt.Close(); err != nil {
		return err
	}

	inputs[0] = ctBuf.Bytes()
	inputs[1] = nil
	return nil
}

// Open unseals a single secret with a private key input matching a public key
// from the entities.
func (c *OpenPGP) Open(secrets, inputs [][]byte) error {
	if len(inputs) != 2 {
		return errors.New("len(inputs) must be 2")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(inputs[1]))
	if err != nil {
		return err
	}

	ct := bytes.NewReader(inputs[0])
	md, err := openpgp.ReadMessage(ct, keyring, nil, nil)
	if err != nil {
		return err
	}

	secret, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return err
	}

	secrets[0] = secret
	return nil
}

func (c *OpenPGP) entities() ([]*openpgp.Entity, error) {
	entities := []*openpgp.Entity{}
	for _, data := range c.Entities {
		rdr := packet.NewReader(bytes.NewBuffer(data))
		ent, err := openpgp.ReadEntity(rdr)
		if err != nil {
			return nil, err
		}
		entities = append(entities, ent)
	}
	return entities, nil
}
