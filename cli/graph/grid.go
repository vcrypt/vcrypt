package graph

import (
	"fmt"
	"strings"

	"github.com/vcrypt/vcrypt"
	"github.com/vcrypt/vcrypt/cryptex"
	"github.com/vcrypt/vcrypt/secret"
)

type table []row

func (t table) lines() ([]string, error) {
	max := 0
	for _, r := range t {
		if l := len(r); l > max {
			max = l
		}
	}

	for i := range t {
		for j := len(t[i]); j < max; j++ {
			t[i] = append(t[i], spacer)
		}
	}

	lines := make([]string, 0, len(t))
	for _, r := range t {
		lines = append(lines, r.String())
	}
	return lines, nil // TODO
}

type row []cell

func (r row) String() string {
	line := ""

	var target *nodeCell
	for _, c := range r {
		line += c.String()

		if n, ok := c.(*nodeCell); ok {
			target = n
		}
	}

	if target != nil {
		s, _ := target.detail()
		line += s
	}
	return line
}

var (
	spacer = runeCell(' ')

	conEdge    = runeCell('/')
	cornerEdge = runeCell('.')
	expEdge    = runeCell('\\')
	horizEdge  = runeCell('-')
	latEdge    = runeCell('_')
	vertEdge   = runeCell('|')
)

type cell interface {
	String() string
}

type runeCell rune

func (r runeCell) String() string {
	return string(r)
}

type nodeCell struct {
	node   *vcrypt.Node
	marker rune
}

func (n *nodeCell) String() string {
	return string(n.marker)
}

func (n *nodeCell) detail() (string, error) {
	cmnt, err := n.node.Comment()
	if err != nil {
		return "", err
	}
	cmnt = strings.Replace(cmnt, "\n", "\t\t\n", 0)

	typ, err := n.name()
	if err != nil {
		return "", err
	}
	typ = "[" + typ + "]"

	id, err := n.node.Digest()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x %-12s %s", id[:8], typ, cmnt), nil
}

func (n *nodeCell) name() (string, error) {
	switch n.node.Type() {
	case vcrypt.MarkerNode:
		return "material", nil
	case vcrypt.SecretNode:
		sec, err := n.node.Secret()
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
		cptx, err := n.node.Cryptex()
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
