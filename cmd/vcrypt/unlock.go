package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/vcrypt/vcrypt"
)

var (
	unlockFS = flag.NewFlagSet("unlock", flag.ExitOnError)

	unlockVars = struct {
		in, out *string

		dbDir, pgpDir *string
	}{
		in:  unlockFS.String("in", "", "vault file - default stdin"),
		out: unlockFS.String("out", "", "output file - default stdout"),

		dbDir:  unlockFS.String("db.dir", "~/.vcrypt/db", "vcrypt database directory"),
		pgpDir: unlockFS.String("openpgp.dir", "~/.gnupg", "OpenPGP keyring directory"),
	}
)

func unlock(args []string) {
	unlockFS.Parse(args)

	var (
		err error
		vr  io.Reader
		w   io.WriteCloser

		in  = *unlockVars.in
		out = *unlockVars.out

		dbDir  = *unlockVars.dbDir
		pgpDir = *unlockVars.pgpDir
	)

	if in == "" {
		vr = os.Stdin
	} else {
		if vr, err = os.Open(in); err != nil {
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

	data, err := ioutil.ReadAll(vr)
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

	drv := &Driver{
		DB: &DB{
			vault:   vault,
			baseDir: dbDir,
		},
		OpenPGPKeyRing: &OpenPGPKeyRing{
			homedir: pgpDir,
		},
	}

	unlocked, err := vault.Unlock(w, drv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := drv.commit(); err != nil {
		if err := drv.rollback(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}

		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if !unlocked {
		os.Exit(1)
	}
}
