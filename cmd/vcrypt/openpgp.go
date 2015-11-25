package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/bgentry/speakeasy"
	"golang.org/x/crypto/openpgp"
)

// OpenPGPKeyRing is a OpenPGP keyring located on the local filesystem.
type OpenPGPKeyRing struct {
	homedir string

	secring openpgp.EntityList
}

// SerializePrivateKeys writes the private key data of the keyring keys
// identified by ids. Encrypted keys are first decrypted with a passphrase and
// the decrypted data is returned.
func (r *OpenPGPKeyRing) SerializePrivateKeys(ids []uint64) ([]byte, error) {
	ents := make(openpgp.EntityList, 0)
	for _, id := range ids {
		ks, err := r.privateKey(id)
		if err != nil {
			return nil, err
		}

		for _, key := range ks {
			ents = append(ents, key.Entity)
		}
	}

	for _, key := range ents.DecryptionKeys() {
		if key.PrivateKey.Encrypted {
			for user := range key.Entity.Identities {
				fmt.Fprintf(os.Stderr, "user: %q\n", user)
			}

			prompt := fmt.Sprintf("passphrase for OpenPGP key %q: ", key.PublicKey.KeyIdString())
			pass, err := speakeasy.FAsk(os.Stderr, prompt)
			if err != nil {
				return nil, err
			}

			if err := key.PrivateKey.Decrypt([]byte(pass)); err != nil {
				return nil, err
			}
		}

		for _, subkey := range key.Entity.Subkeys {
			if subkey.PrivateKey.Encrypted {
				prompt := fmt.Sprintf("passphrase for OpenPGP key %q: ", subkey.PublicKey.KeyIdString())
				pass, err := speakeasy.FAsk(os.Stderr, prompt)
				if err != nil {
					return nil, err
				}

				if err := subkey.PrivateKey.Decrypt([]byte(pass)); err != nil {
					return nil, err
				}
			}
		}
	}

	buf := bytes.NewBuffer(nil)
	for _, ent := range ents {
		if err := ent.SerializePrivate(buf, nil); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (r *OpenPGPKeyRing) privateKey(id uint64) ([]openpgp.Key, error) {
	if r.secring == nil {
		path, err := expandPath(r.homedir, "secring.gpg")
		if err != nil {
			return nil, err
		}

		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}

		r.secring, err = openpgp.ReadKeyRing(f)
		if err != nil {
			return nil, err
		}
	}

	return r.secring.KeysById(id), nil
}
