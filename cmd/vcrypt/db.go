package main

import (
	"encoding/hex"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/vcrypt/vcrypt"
	"github.com/vcrypt/vcrypt/material"
)

// DB is a store for Material data. It stores each Material as an individual
// file by id inside a single directory structure.
type DB struct {
	vault   *vcrypt.Vault
	baseDir string

	shadow map[string][]byte
}

// LoadMaterial retrieves a Material from the local filesystem by reading from
// the base directory.
func (d *DB) LoadMaterial(id []byte) (*material.Material, error) {
	if d.shadow == nil {
		d.shadow = make(map[string][]byte)
	}

	hid := hex.EncodeToString(id)
	if data, ok := d.shadow[hid]; ok {
		return unmarshal(data)
	}

	dir, err := d.dir()
	if err != nil {
		return nil, err
	}

	fpath, err := expandPath(dir, hid)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(fpath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}

		return nil, err
	}

	return unmarshal(data)
}

// StoreMaterial saves a Material from the local filesystem by writing to the
// base directory.
func (d *DB) StoreMaterial(mtrl *material.Material) error {
	if d.shadow == nil {
		d.shadow = make(map[string][]byte)
	}

	data, err := mtrl.Marshal()
	if err != nil {
		return err
	}
	d.shadow[hex.EncodeToString(mtrl.ID)] = data

	return nil
}

func (d *DB) commit() error {
	dir, err := d.dir()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	for id, data := range d.shadow {
		fpath, err := expandPath(dir, id)
		if err != nil {
			return err
		}

		if err := ioutil.WriteFile(fpath, data, 0600); err != nil {
			return err
		}
	}

	return nil
}

func (d *DB) dir() (string, error) {
	id, err := d.vault.Digest()
	if err != nil {
		return "", err
	}

	return expandPath(d.baseDir, hex.EncodeToString(id))
}

func (d *DB) rollback() error {
	dir, err := d.dir()
	if err != nil {
		return err
	}

	for id := range d.shadow {
		fpath, err := expandPath(dir, id)
		if err != nil {
			return err
		}

		if err := os.RemoveAll(fpath); err != nil {
			return err
		}
	}
	return nil
}

func unmarshal(data []byte) (*material.Material, error) {
	mtrl := &material.Material{}
	if err := mtrl.Unmarshal(data); err != nil {
		return nil, err
	}
	return mtrl, nil
}

func expandPath(elem ...string) (string, error) {
	if elem[0][:2] == "~/" {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}

		elem[0] = strings.Replace(elem[0], "~", usr.HomeDir, 1)
	}

	return filepath.Join(elem...), nil
}
