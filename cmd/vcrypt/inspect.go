package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/benburkert/vcrypt"
	"github.com/benburkert/vcrypt/cryptex"
	"github.com/benburkert/vcrypt/material"
	"github.com/benburkert/vcrypt/secret"
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

	err = plan.BFS(func(node *vcrypt.Node) error {
		id, err := node.Digest()
		if err != nil {
			return err
		}

		cmnt, err := node.Comment()
		if err != nil {
			return err
		}
		cmnt = strings.Replace(cmnt, "\n", "\t\t\n", 0)

		typ, err := nodeTypeName(node)
		if err != nil {
			return err
		}
		typ = "[" + typ + "]"

		fmt.Printf("%x %-12s %s\n", id[:8], typ, cmnt)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func inspectVault(vault *vcrypt.Vault) {
	id, err := vault.Digest()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	fmt.Printf("vault %x\n", id)
	fmt.Println()

	if cmnt := vault.Comment(); len(cmnt) > 0 {
		fmt.Printf("\t%s\n", strings.Replace(cmnt, "\n", "\t\n", 0))
		fmt.Println()
	}

	db := &DB{
		vault:   vault,
		baseDir: *inspectVars.dbDir,
	}

	err = vault.Plan.BFS(func(node *vcrypt.Node) error {
		id, err := node.Digest()
		if err != nil {
			return err
		}

		stat := ""
		mtrl, err := db.LoadMaterial(id)
		if err != nil {
			return err
		}
		if mtrl != nil {
			stat = "S"
		}

		cmnt, err := node.Comment()
		if err != nil {
			return err
		}
		cmnt = strings.Replace(cmnt, "\n", "\t\t\n", 0)

		typ, err := nodeTypeName(node)
		if err != nil {
			return err
		}
		typ = "[" + typ + "]"

		fmt.Printf("%1s %x %-12s %s\n", stat, id[:8], typ, cmnt)
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func nodeTypeName(node *vcrypt.Node) (string, error) {
	switch node.Type() {
	case vcrypt.MarkerNode:
		return "material", nil
	case vcrypt.SecretNode:
		sec, err := node.Secret()
		if err != nil {
			return "", err
		}

		switch sec.(type) {
		case *secret.OpenPGPKey:
			return "openpgpkey", nil
		case *secret.Password:
			return "password", nil
		default:
			return "secret", nil
		}
	case vcrypt.CryptexNode:
		cptx, err := node.Cryptex()
		if err != nil {
			return "", err
		}

		switch cptx.(type) {
		case *cryptex.Box:
			return "box", nil
		case *cryptex.Demux:
			return "demux", nil
		case *cryptex.Mux:
			return "mux", nil
		case *cryptex.OpenPGP:
			return "openpgp", nil
		case *cryptex.RSA:
			return "rsa", nil
		case *cryptex.SecretBox:
			return "secretbox", nil
		case *cryptex.SSS:
			return "sss", nil
		case *cryptex.XOR:
			return "xor", nil
		default:
			return "cryptex", nil
		}
	default:
		return "unknown", nil
	}
}
