package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		help()
		os.Exit(1)
	}

	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "build":
		build(args)
	case "export":
		export(args)
	case "import":
		importM(args)
	case "inspect":
		inspect(args)
	case "lock":
		lock(args)
	case "unlock":
		unlock(args)
	default:
		help()
		os.Exit(1)
	}
}

func help() {
	help := []string{
		"usage: vcrypt <command> [<args>]",
		"",
		"The vcrypt commands are:",
		"	build	Build plan file from plan config",
		"	export  Export material data",
		"	import  Import material data",
		"	inspect Show vault, plan, & material info",
		"	lock	Encrypt data to a vault",
		"	unlock	Decrypt data from a vault",
	}

	fmt.Println(strings.Join(help, "\n"))
}
