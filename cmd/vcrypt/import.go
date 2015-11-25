package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/benburkert/vcrypt"
	"github.com/benburkert/vcrypt/material"
)

var (
	importFS = flag.NewFlagSet("import", flag.ExitOnError)

	importVars = struct {
		in, vault *string

		dbDir *string
	}{
		in:    importFS.String("in", "", "material file - default stdin"),
		vault: importFS.String("vault", "", "vault file"),

		dbDir: importFS.String("db.dir", "~/.vcrypt/db", "vcrypt database directory"),
	}
)

func importM(args []string) {
	importFS.Parse(args)

	var (
		err error
		r   io.Reader

		in    = *importVars.in
		vfile = *importVars.vault
	)

	if vfile == "" {
		fmt.Fprintln(os.Stderr, "missing required argument: -vault")
		os.Exit(1)
	}

	if in == "" {
		r = os.Stdin
	} else {
		if r, err = os.Open(in); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	msg, _, err := vcrypt.Unarmor(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mtrl, ok := msg.(*material.Material)
	if !ok {
		fmt.Fprintln(os.Stderr, "could not load material")
		os.Exit(1)
	}

	vr, err := os.Open(vfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if data, err = ioutil.ReadAll(vr); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	if msg, _, err = vcrypt.Unarmor(data); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	vault, ok := msg.(*vcrypt.Vault)
	if !ok {
		fmt.Fprintln(os.Stderr, "could not load vault file")
		os.Exit(1)
	}

	found := false
	err = vault.Plan.BFS(func(node *vcrypt.Node) error {
		if found {
			return nil
		}

		id, err := node.Digest()
		if err != nil {
			return err
		}

		if bytes.Equal(mtrl.ID, id) {
			found = true
		}

		return nil
	})
	if !found {
		fmt.Fprintf(os.Stderr, "missing node '%x' for vault\n", mtrl.ID[:8])
		os.Exit(1)
	}

	db := &DB{
		vault:   vault,
		baseDir: *importVars.dbDir,
	}

	if err := db.StoreMaterial(mtrl); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := db.commit(); err != nil {
		if err := db.rollback(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}

		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
