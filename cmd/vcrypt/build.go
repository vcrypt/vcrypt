package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/vcrypt/vcrypt"
)

var (
	buildFS = flag.NewFlagSet("build", flag.ExitOnError)

	buildVars = struct {
		in, out *string
	}{
		in:  buildFS.String("in", "", "input file - default stdin"),
		out: buildFS.String("out", "", "output file - default stdout"),
	}
)

func build(args []string) {
	buildFS.Parse(args)

	var (
		err error
		r   io.Reader
		w   io.WriteCloser

		in  = *buildVars.in
		out = *buildVars.out
	)

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

	plan, err := vcrypt.BuildPlan(r)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	data, err := vcrypt.Armor(plan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if _, err := w.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
