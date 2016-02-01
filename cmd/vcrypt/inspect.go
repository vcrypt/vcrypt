package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/vcrypt/vcrypt"
	"github.com/vcrypt/vcrypt/cli"
	"github.com/vcrypt/vcrypt/material"
)

var (
	inspectFS = flag.NewFlagSet("inspect", flag.ExitOnError)

	inspectVars = struct {
		in *string

		dbDir *string
	}{
		in: inspectFS.String("in", "", "vcrypt data file - default stdin"),

		dbDir: inspectFS.String("db.dir", "~/.vcrypt/db", "vcrypt database directory"),
	}
)

func inspect(args []string) {
	inspectFS.Parse(args)

	var (
		err error
		r   io.Reader

		in = *inspectVars.in
	)

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

	switch msg := msg.(type) {
	case *material.Material:
		inspectMaterial(msg)
	case *vcrypt.Plan:
		inspectPlan(msg)
	case *vcrypt.Vault:
		inspectVault(msg)
	}
}

func inspectMaterial(mtrl *material.Material) {
	fmt.Printf("material %x\n", mtrl.ID)
	fmt.Println()

	if cmnt := mtrl.Comment(); len(cmnt) > 0 {
		fmt.Printf("\t%s\n", strings.Replace(cmnt, "\n", "\t\n", 0))
		fmt.Println()
	}
}

func inspectPlan(plan *vcrypt.Plan) {
	id, err := plan.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Printf("plan %x\n", id)
	fmt.Println()

	if cmnt := plan.Comment(); len(cmnt) > 0 {
		fmt.Printf("\t%s\n", strings.Replace(cmnt, "\n", "\t\n", 0))
		fmt.Println()
	}

	graphLines, err := cli.PlanGraph(plan)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	for _, line := range graphLines {
		fmt.Println(line)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func inspectVault(vault *vcrypt.Vault) {
	vid, err := vault.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Printf("vault %x\n", vid)

	if cmnt := vault.Comment(); len(cmnt) > 0 {
		fmt.Println()
		fmt.Printf("\t%s\n", strings.Replace(cmnt, "\n", "\t\n", 0))
		fmt.Println()
	}

	fid, err := vault.Plan.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Printf("plan %x\n", fid)

	if cmnt := vault.Plan.Comment(); len(cmnt) > 0 {
		fmt.Println()
		fmt.Printf("\t%s\n", strings.Replace(cmnt, "\n", "\t\n", 0))
		fmt.Println()
	}

	db := &DB{
		vault:   vault,
		baseDir: *inspectVars.dbDir,
	}

	graphLines, err := cli.VaultGraph(vault, db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	for _, line := range graphLines {
		fmt.Println(line)
	}
}
