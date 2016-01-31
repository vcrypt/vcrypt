package cli

import (
	"fmt"
	"strings"

	"github.com/vcrypt/vcrypt"
	"github.com/vcrypt/vcrypt/cli/graph"
	"github.com/vcrypt/vcrypt/cryptex"
	"github.com/vcrypt/vcrypt/material"
	"github.com/vcrypt/vcrypt/secret"
)

// PlanGraph returns the textual representation of a Plan. Nodes are displayed
// as the '*' character.
func PlanGraph(plan *vcrypt.Plan) ([]string, error) {
	nodes := []*graph.Node{}
	walker := func(vnode *vcrypt.Node) error {
		id, err := vnode.Digest()
		if err != nil {
			return err
		}

		detail, err := nodeDetail(vnode)
		if err != nil {
			return err
		}

		nodes = append(nodes, &graph.Node{
			ID:     id,
			Edges:  vnode.Inputs,
			Marker: '*',
			Detail: detail,
		})

		return nil
	}

	if err := plan.BFS(walker); err != nil {
		return nil, err
	}

	return graph.Lines(nodes)
}

// VaultGraph returns the textual representation of a Vault. Nodes are
// displayed as 'S' if solved or '*' otherwise.
func VaultGraph(vault *vcrypt.Vault, db material.DB) ([]string, error) {
	nodes := []*graph.Node{}
	walker := func(vnode *vcrypt.Node) error {
		id, err := vnode.Digest()
		if err != nil {
			return err
		}

		detail, err := nodeDetail(vnode)
		if err != nil {
			return err
		}

		mtrl, err := db.LoadMaterial(id)
		if err != nil {
			return err
		}

		marker := '*'
		if mtrl != nil {
			marker = 'S'
		}

		nodes = append(nodes, &graph.Node{
			ID:     id,
			Edges:  vnode.Inputs,
			Marker: marker,
			Detail: detail,
		})

		return nil
	}

	if err := vault.Plan.BFS(walker); err != nil {
		return nil, err
	}

	return graph.Lines(nodes)
}

func nodeDetail(node *vcrypt.Node) (string, error) {
	cmnt, err := node.Comment()
	if err != nil {
		return "", err
	}
	cmnt = strings.Replace(cmnt, "\n", "\t\t\t\n", 0)

	typ, err := nodeTypeName(node)
	if err != nil {
		return "", err
	}
	typ = "[" + typ + "]"

	id, err := node.Digest()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x %-12s %s", id[:8], typ, cmnt), nil
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
