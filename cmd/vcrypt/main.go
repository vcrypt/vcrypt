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
	}

	fmt.Println(strings.Join(help, "\n"))
}
