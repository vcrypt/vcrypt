package vcrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"github.com/benburkert/vcrypt/config"
	"github.com/benburkert/vcrypt/seal"
)

// NewPlan constructs a Plan from an pre-built Graph.
func NewPlan(g *Graph, comment string) (*Plan, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	nodes, err := g.Nodes()
	if err != nil {
		return nil, err
	}

	return &Plan{
		comment: comment,
		Nonce:   nonce,
		Nodes:   nodes,
	}, nil
}

// BuildPlan constructs a Plan from the config data in r.
func BuildPlan(r io.Reader) (*Plan, error) {
	cp := config.Plan{}
	if err := config.NewDecoder(r).Decode(&cp); err != nil {
		return nil, err
	}

	g, err := build(cp)
	if err != nil {
		return nil, err
	}

	return NewPlan(g, cp.Comment)
}

// Comment string
func (p *Plan) Comment() string {
	return p.comment
}

// AddSeal adds a Seal for the Plan from the nonce, root node, and comment
// data.
func (p *Plan) AddSeal(slr Sealer) (seal.Seal, error) {
	data, err := p.sealData()
	if err != nil {
		return nil, err
	}

	s, err := slr.Seal(data)
	if err != nil {
		return nil, err
	}

	env, err := seal.Wrap(s)
	if err != nil {
		return nil, err
	}

	p.seals = append(p.seals, env)
	return s, nil
}

// Digest is a unique series of bytes that identify the Plan.
func (p *Plan) Digest() ([]byte, error) {
	// HMAC(Nonce,Nodes[0].Digest|Comment|Seal[*].Digest)
	hash := hmac.New(sha256.New, p.Nonce)

	fp, err := p.Nodes[0].Digest()
	if err != nil {
		return nil, err
	}

	if _, err := hash.Write(fp); err != nil {
		return nil, err
	}

	if _, err := hash.Write([]byte(p.comment)); err != nil {
		return nil, err
	}

	seals, err := p.Seals()
	if err != nil {
		return nil, err
	}

	for _, s := range seals {
		fp, err = s.Digest()
		if err != nil {
			return nil, err
		}

		if _, err := hash.Write(fp); err != nil {
			return nil, err
		}
	}

	return hash.Sum(nil), nil
}

// Graph returns a new Graph built from the plan nodes.
func (p *Plan) Graph() (*Graph, error) {
	return BuildGraph(p.Nodes)
}

// Seals return a Seal slice for the Plan.
func (p *Plan) Seals() ([]seal.Seal, error) {
	seals := make([]seal.Seal, 0, len(p.seals))
	for _, env := range p.seals {
		seal, err := env.Seal()
		if err != nil {
			return nil, err
		}
		seals = append(seals, seal)
	}
	return seals, nil
}

func (p *Plan) sealData() ([]byte, error) {
	// Nonce|Nodes[0].Digest|Comment
	nfp, err := p.Nodes[0].Digest()
	if err != nil {
		return nil, err
	}

	data := make([]byte, 0, len(p.Nonce)+len(nfp)+len(p.comment))
	copy(data, p.Nonce)
	data = append(data, nfp...)
	data = append(data, []byte(p.comment)...)

	return data, nil
}
