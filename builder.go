package vcrypt

import (
	"fmt"

	"github.com/benburkert/vcrypt/config"
	"github.com/benburkert/vcrypt/cryptex"
	"github.com/benburkert/vcrypt/graph"
	"github.com/benburkert/vcrypt/secret"
)

type builder struct {
	plan config.Plan

	verts map[string]*graph.Vertex
}

func build(plan config.Plan) (*Graph, error) {
	root, ok := plan.CryptexNode(plan.Root)
	if !ok {
		return nil, fmt.Errorf("missing root cryptex %q", plan.Root)
	}

	bldr := builder{
		plan:  plan,
		verts: make(map[string]*graph.Vertex),
	}

	g, err := bldr.buildGraph(root)
	if err != nil {
		return nil, err
	}

	g.Nodes() // load digests & nonces maps
	return g, nil
}

func (b builder) buildGraph(root config.CryptexNode) (*Graph, error) {
	cptx, err := root.Cryptex()
	if err != nil {
		return nil, err
	}

	g, err := NewGraph(cptx)
	if err != nil {
		return nil, err
	}

	for _, edge := range root.Edges() {
		if err := b.buildEdge(g, edge, g.Root); err != nil {
			return nil, err
		}
	}

	return g, nil
}

func (b builder) buildEdge(g *Graph, name string, from *graph.Vertex) error {
	if to, ok := b.verts[name]; ok {
		return g.AddEdge(to, from)
	}

	return b.buildVertex(g, name, from)
}

func (b builder) buildVertex(g *Graph, name string, from *graph.Vertex) error {
	if node, ok := b.plan.CryptexNode(name); ok {
		cptx, err := node.Cryptex()
		if err != nil {
			return err
		}

		env, err := cryptex.Wrap(cptx)
		if err != nil {
			return err
		}

		to, err := g.Add(env, from)
		if err != nil {
			return err
		}
		b.verts[name] = to

		for _, edge := range node.Edges() {
			if err := b.buildEdge(g, edge, to); err != nil {
				return err
			}
		}
		return nil
	}
	if node, ok := b.plan.SecretNode(name); ok {
		sec, err := node.Secret()
		if err != nil {
			return err
		}

		env, err := secret.Wrap(sec)
		if err != nil {
			return err
		}

		_, err = g.Add(env, from)
		return err
	}
	if mrkr, ok := b.plan.Materials[name]; ok {
		_, err := g.Add(&Marker{Comment: mrkr.Comment}, from)
		return err
	}

	return fmt.Errorf("missing node for edge %q", name)
}
