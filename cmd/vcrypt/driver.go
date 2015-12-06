package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bgentry/speakeasy"
	"github.com/vcrypt/vcrypt/payload"
	"github.com/vcrypt/vcrypt/secret"
)

// Driver is an implementation of a vcrypt.Driver for use in a terminal.
type Driver struct {
	*DB
	*OpenPGPKeyRing

	pw io.WriteCloser
}

// LockPayload constructs a Payload from the Reader data. Attached & Detached
// payloads are supported.
func (d *Driver) LockPayload(r io.Reader) (payload.Payload, []byte, error) {
	var (
		pld payload.Payload
		err error
	)

	if d.pw != nil {
		pld, err = payload.NewDetached()
	} else {
		pld, err = payload.NewAttached()
	}
	if err != nil {
		return nil, nil, err
	}

	key, err := pld.Lock(r, d)
	if err != nil {
		return nil, nil, err
	}
	return pld, key, nil
}

// LoadSecret returns the secret data for a given secret. Password & OpenPGPKey
// secrets are supported.
func (d *Driver) LoadSecret(sec secret.Secret) ([][]byte, bool, error) {
	switch sec := sec.(type) {
	case *secret.Password:
		passwd, err := speakeasy.FAsk(os.Stderr, fmt.Sprintf("password for '%s': ", sec.Comment()))
		if err != nil {
			return nil, false, err
		}
		if len(passwd) == 0 {
			return [][]byte{[]byte{}}, true, nil
		}

		return [][]byte{[]byte(passwd)}, false, nil
	case *secret.OpenPGPKey:
		data, err := d.OpenPGPKeyRing.SerializePrivateKeys(sec.KeyIDs)
		if err != nil {
			return nil, false, err
		}
		if len(data) == 0 {
			return [][]byte{[]byte{}}, true, nil
		}

		return [][]byte{data}, false, nil
	default:
		return nil, false, fmt.Errorf("unknown secret %#v\n", sec)
	}
}
