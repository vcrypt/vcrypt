package test

import (
	"bytes"
	"io"

	"github.com/vcrypt/vcrypt/material"
	"github.com/vcrypt/vcrypt/payload"
	"github.com/vcrypt/vcrypt/secret"
)

// Driver is a test implementation of a driver for encryption & decryption.
type Driver map[string][]byte

// LoadMaterial retrieves Material data stored in d.
func (d Driver) LoadMaterial(id []byte) (*material.Material, error) {
	data, ok := d[string(id)]
	if !ok {
		return nil, nil
	}

	mtrl := &material.Material{}
	if err := mtrl.Unmarshal(data); err != nil {
		return nil, err
	}

	return mtrl, nil
}

// StoreMaterial saves Material data to d.
func (d Driver) StoreMaterial(mtrl *material.Material) error {
	data, err := mtrl.Marshal()
	if err != nil {
		return err
	}

	d[string(mtrl.ID)] = data
	return nil
}

// LockPayload encrypts the Reader data in an Attached payload.
func (d Driver) LockPayload(r io.Reader) (payload.Payload, []byte, error) {
	pld, err := payload.NewAttached()
	if err != nil {
		return nil, nil, err
	}

	key, err := pld.Lock(r, d)
	if err != nil {
		return nil, nil, err
	}
	return pld, key, nil
}

// LoadSecret returns the data for a Secret stored in d.
func (d Driver) LoadSecret(sec secret.Secret) ([][]byte, bool, error) {
	data, ok := d[sec.Comment()]
	if !ok {
		return nil, true, nil
	}

	datas, err := sec.Load(bytes.NewBuffer(data))
	return datas, false, err
}
