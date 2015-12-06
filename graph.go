package vcrypt

import (
	"bytes"
	"crypto/rand"
	"errors"

	"github.com/vcrypt/vcrypt/cryptex"
	"github.com/vcrypt/vcrypt/graph"
	"github.com/vcrypt/vcrypt/secret"
)

// Graph encodes an encryption plan into discrete steps represented as Nodes.
type Graph struct {
	*graph.DAG

	digests, nonces map[*graph.Vertex][]byte
}

// NewGraph constructs a graph with a root Node for cptx.
func NewGraph(cptx cryptex.Cryptex) (*Graph, error) {
	env, err := cryptex.Wrap(cptx)
	if err != nil {
		return nil, err
	}

	return &Graph{
		DAG:     graph.NewDAG(env),
		digests: make(map[*graph.Vertex][]byte),
		nonces:  make(map[*graph.Vertex][]byte),
	}, nil
}

// BuildGraph constructs a graph from a slice of Nodes.
func BuildGraph(nodes []*Node) (*Graph, error) {
	cptx, err := nodes[0].Cryptex()
	if err != nil {
		return nil, err
	}
	if cptx == nil {
		return nil, errors.New("root node is non cryptex")
	}

	g, err := NewGraph(cptx)
	if err != nil {
		return nil, err
	}

	fp, err := nodes[0].Digest()
	if err != nil {
		return nil, err
	}

	g.digests[g.Root] = fp
	g.nonces[g.Root] = nodes[0].Nonce

	vertMap := map[string]*graph.Vertex{
		string(fp): g.Root,
	}

	// insert verts
	for _, node := range nodes[1:] {
		var val interface{}
		switch node.Type() {
		case CryptexNode:
			cptx, err := node.Cryptex()
			if err != nil {
				return nil, err
			}
			if val, err = cryptex.Wrap(cptx); err != nil {
				return nil, err
			}
		case SecretNode:
			sec, err := node.Secret()
			if err != nil {
				return nil, err
			}
			if val, err = secret.Wrap(sec); err != nil {
				return nil, err
			}
		case MarkerNode:
			val = node.Marker
		default:
			panic("unreachable")
		}

		v := g.DAG.Add(val)
		fp, err := node.Digest()
		if err != nil {
			return nil, err
		}

		g.digests[v] = fp
		g.nonces[v] = node.Nonce
		vertMap[string(fp)] = v
	}

	// add edges
	for _, node := range nodes {
		fromfp, err := node.Digest()
		if err != nil {
			return nil, err
		}

		for _, tofp := range node.Inputs {
			to, from := vertMap[string(tofp)], vertMap[string(fromfp)]
			if err := g.AddEdge(to, from); err != nil {
				return nil, err
			}
		}
	}

	return g, nil
}

// Add inserts a new Node into the graph with a parent edge from the vertex.
func (g *Graph) Add(val interface{}, from *graph.Vertex) (*graph.Vertex, error) {
	to := g.DAG.Add(val)
	return to, g.AddEdge(to, from)
}

// Nodes converts the graph vertecies into Nodes in consistent reverse
// depth-first order.
func (g *Graph) Nodes() ([]*Node, error) {
	nodes := make([]*Node, 0, len(g.Adjacency))

	walker := func(v *graph.Vertex) error {
		node, err := g.node(v)
		if err != nil {
			return err
		}

		fp, err := node.Digest()
		if err != nil {
			return err
		}

		nodes = append([]*Node{node}, nodes...) // push front so Root is first
		g.digests[v] = fp
		g.nonces[v] = node.Nonce

		return nil
	}

	if err := g.DAG.ReverseDFS(walker); err != nil {
		return nil, err
	}
	return nodes, nil
}

func (g *Graph) node(v *graph.Vertex) (*Node, error) {
	edgeList, ok := g.Adjacency[v]
	if !ok {
		return nil, errors.New("vertex missing in DAG")
	}

	nonce := g.nonces[v]
	if nonce == nil {
		nonce = g.genNonce()
	}

	inputs := make([][]byte, 0, edgeList.Len())
	for e := edgeList.Front(); e != nil; e = e.Next() {
		v := e.Value.(*graph.Vertex)
		fp, ok := g.digests[v]
		if !ok {
			return nil, errors.New("reached parent vertex before child")
		}

		inputs = append(inputs, fp)
	}

	switch v := v.Value.(type) {
	case *cryptex.Envelope:
		return &Node{
			Nonce:   nonce,
			Inputs:  inputs,
			cryptex: v,
		}, nil
	case *secret.Envelope:
		return &Node{
			Nonce:  nonce,
			Inputs: inputs,
			secret: v,
		}, nil
	case *Marker:
		return &Node{
			Nonce:  nonce,
			Inputs: inputs,
			Marker: v,
		}, nil
	default:
		return nil, errors.New("invalid graph Vertex value")
	}
}

func (g *Graph) genNonce() []byte {
	for {
		nonce := make([]byte, 8)
		if _, err := rand.Read(nonce); err != nil {
			panic(err)
		}

		collision := false
		for _, n := range g.nonces {
			if bytes.Equal(nonce, n) {
				collision = true
			}
		}

		if !collision {
			return nonce
		}
	}
}
