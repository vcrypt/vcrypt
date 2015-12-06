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
	lockFS = flag.NewFlagSet("lock", flag.ExitOnError)

	lockVars = struct {
		in, out, plan, comment, detach *string

		dbDir *string
	}{
		in:      lockFS.String("in", "", "input file - default stdin"),
		out:     lockFS.String("out", "", "output file - default stdout"),
		plan:    lockFS.String("plan", "", "plan file"),
		comment: lockFS.String("comment", "", "vault comment"),
		detach:  lockFS.String("detach", "", "detached payload file"),

		dbDir: lockFS.String("db.dir", "~/.vcrypt/db", "vcrypt database directory"),
	}
)

func lock(args []string) {
	lockFS.Parse(args)

	var (
		err error
		r   io.Reader
		w   io.WriteCloser

		in    = *lockVars.in
		out   = *lockVars.out
		pfile = *lockVars.plan
		cmnt  = *lockVars.comment
		dfile = *lockVars.detach

		dbDir = *lockVars.dbDir
	)

	if pfile == "" {
		fmt.Fprintln(os.Stderr, "missing required argument: -plan")
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

	pr, err := os.Open(pfile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	data, err := ioutil.ReadAll(pr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	msg, _, err := vcrypt.Unarmor(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	plan, ok := msg.(*vcrypt.Plan)
	if !ok {
		fmt.Fprintln(os.Stderr, "could not load plan file")
		os.Exit(1)
	}

	vault, err := vcrypt.NewVault(plan, cmnt)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	drv := &Driver{
		DB: &DB{
			vault:   vault,
			baseDir: dbDir,
		},
	}

	if dfile != "" {
		if drv.pw, err = os.Create(dfile); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
	}

	if err := vault.Lock(r, drv); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if data, err = vcrypt.Armor(vault); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if err := drv.commit(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if _, err := w.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())

		if err := drv.rollback(); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
		}

		os.Exit(1)
	}
}
