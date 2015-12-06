package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/vcrypt/vcrypt"
)

var (
	exportFS = flag.NewFlagSet("export", flag.ExitOnError)

	exportVars = struct {
		in, out, id *string

		dbDir *string
	}{
		in:  exportFS.String("in", "", "vault file - default stdin"),
		out: exportFS.String("out", "", "output material file - default stdout"),
		id:  exportFS.String("id", "", "node id"),

		dbDir: exportFS.String("db.dir", "~/.vcrypt/db", "vcrypt database directory"),
	}
)

func export(args []string) {
	exportFS.Parse(args)

	var (
		err    error
		r      io.Reader
		w      io.WriteCloser
		fullID []byte

		in      = *exportVars.in
		out     = *exportVars.out
		shortID = *exportVars.id
	)

	prefix, err := hex.DecodeString(shortID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
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

	if out == "" {
		w = os.Stdout
	} else {
		if w, err = os.Create(out); err != nil {
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

	vault, ok := msg.(*vcrypt.Vault)
	if !ok {
		fmt.Fprintln(os.Stderr, "could not load vault file")
		os.Exit(1)
	}

	err = vault.Plan.BFS(func(node *vcrypt.Node) error {
		if len(fullID) > 0 {
			return nil
		}

		id, err := node.Digest()
		if err != nil {
			return err
		}

		if bytes.Equal(prefix, id[:len(prefix)]) {
			fullID = id
		}

		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	db := &DB{
		vault:   vault,
		baseDir: *exportVars.dbDir,
	}

	mtrl, err := db.LoadMaterial(fullID)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if data, err = vcrypt.Armor(mtrl); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if _, err := w.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
