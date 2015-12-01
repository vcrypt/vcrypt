package vcrypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/benburkert/vcrypt/cryptex"
	"github.com/benburkert/vcrypt/graph"
	"github.com/benburkert/vcrypt/material"
	"github.com/benburkert/vcrypt/payload"
	"github.com/benburkert/vcrypt/seal"
	"github.com/benburkert/vcrypt/secret"
)

// NewVault constructs a Vault from a Plan.
func NewVault(plan *Plan, comment string) (*Vault, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Vault{
		comment: comment,
		Plan:    plan,
		Nonce:   nonce,
	}, nil
}

// Lock encrypts a vault by building an encrypted Payload from r. It then
// secures the decryption key in a multi-step encryption scheme described in
// the Plan.
func (v *Vault) Lock(r io.Reader, drv Driver) error {
	if v.payload != nil {
		return errors.New("Vault already locked")
	}

	pld, rootKey, err := drv.LockPayload(r)
	if err != nil {
		return err
	}

	g, err := v.Plan.Graph()
	if err != nil {
		return err
	}

	walker := &vaultWalker{
		graph:   g,
		drv:     drv,
		outputs: map[*graph.Vertex][][]byte{g.Root: [][]byte{rootKey}},
	}

	if err := g.BFS(walker.lock); err != nil {
		return err
	}

	env, err := payload.Wrap(pld)
	if err != nil {
		return err
	}

	v.payload = env
	v.Materials = walker.materials
	return nil
}

// Unlock retrieves the Payload decryption key by solving the Plan and
// writes the decrypted Payload data to w.
func (v *Vault) Unlock(w io.Writer, drv Driver) (unlocked bool, err error) {
	if v.payload == nil {
		return false, errors.New("Vault is not locked")
	}

	g, err := v.Plan.Graph()
	if err != nil {
		return false, err
	}

	walker := &vaultWalker{
		graph:     g,
		drv:       drv,
		materials: v.Materials,
		outputs:   map[*graph.Vertex][][]byte{g.Root: [][]byte{nil}},
		skipped:   map[*graph.Vertex]bool{},
	}

	if err := g.BFS(walker.shapeOutputs); err != nil {
		return false, err
	}

	if err := g.ReverseDFS(walker.unlock); err != nil {
		return false, err
	}
	if walker.skipped[g.Root] {
		return false, nil
	}
	rootKey := walker.outputs[g.Root][0]

	pld, err := v.Payload()
	if err != nil {
		return false, err
	}

	if err := pld.Unlock(w, rootKey, drv); err != nil {
		return false, err
	}

	return true, nil
}

// Comment string
func (v *Vault) Comment() string {
	return v.comment
}

// Digest is a unique series of bytes that identify the Vault.
func (v *Vault) Digest() ([]byte, error) {
	if v.payload == nil {
		return nil, errors.New("unlocked vault has no digest")
	}

	// HMAC(Nonce,Plan.Digest|Materials[*].Digest|Seals[*].Digest|Payload.Digest)
	hash := hmac.New(sha256.New, v.Nonce)

	fp, err := v.Plan.Digest()
	if err != nil {
		return nil, err
	}
	if _, err := hash.Write(fp); err != nil {
		return nil, err
	}

	for _, m := range v.Materials {
		if fp, err = m.Digest(); err != nil {
			return nil, err
		}
		if _, err := hash.Write(fp); err != nil {
			return nil, err
		}
	}

	seals, err := v.Seals()
	if err != nil {
		return nil, err
	}
	for _, s := range seals {
		if fp, err = s.Digest(); err != nil {
			return nil, err
		}
		if _, err := hash.Write(fp); err != nil {
			return nil, err
		}
	}

	pld, err := v.Payload()
	if err != nil {
		return nil, err
	}

	if fp, err = pld.Digest(); err != nil {
		return nil, err
	}
	if _, err := hash.Write(fp); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// Seals are the verifiable seals of the vault.
func (v *Vault) Seals() ([]seal.Seal, error) {
	seals := make([]seal.Seal, 0, len(v.seals))
	for _, env := range v.seals {
		seal, err := env.Seal()
		if err != nil {
			return nil, err
		}
		seals = append(seals, seal)
	}
	return seals, nil
}

// Payload holds the encrypted data protected by the vault.
func (v *Vault) Payload() (payload.Payload, error) {
	return v.payload.Payload()
}

type vaultWalker struct {
	graph *Graph
	drv   Driver

	materials []*material.Material

	outputs map[*graph.Vertex][][]byte
	skipped map[*graph.Vertex]bool
}

func (w *vaultWalker) lock(vrt *graph.Vertex) error {
	node, err := w.graph.node(vrt)
	if err != nil {
		return err
	}

	id, err := node.Digest()
	if err != nil {
		return err
	}

	var mtrl *material.Material
	switch node.Type() {
	case CryptexNode:
		cptx, err := node.Cryptex()
		if err != nil {
			return err
		}

		mtrl, err = w.lockCryptex(cptx, vrt)
		if err != nil {
			return err
		}

		return w.drv.StoreMaterial(mtrl)
	case SecretNode:
		if _, ok := w.outputs[vrt]; !ok {
			panic("reached unprocessed non-cryptex node")
		}

		return nil
	case MarkerNode:
		data, ok := w.outputs[vrt]
		if !ok {
			panic("reached unprocessed non-cryptex node")
		}

		mtrl, err = material.New(id, data)
		if err != nil {
			return err
		}

		w.materials = append(w.materials, mtrl)
		return nil
	default:
		return errors.New("unknown Node type")
	}
}

func (w *vaultWalker) lockCryptex(cptx cryptex.Cryptex, vrt *graph.Vertex) (*material.Material, error) {
	edges := w.graph.Edges(vrt)
	inputs := make([][]byte, 0, w.graph.Adjacency[vrt].Len())

	for _, vrt := range edges {
		node, err := w.graph.node(vrt)
		if err != nil {
			return nil, err
		}

		switch node.Type() {
		case CryptexNode, MarkerNode:
			inputs = append(inputs, nil)
		case SecretNode:
			sec, err := node.Secret()
			if err != nil {
				return nil, err
			}

			data, skip := [][]byte{[]byte{}}, false
			if sec.Phase() == secret.Dual {
				if data, skip, err = w.drv.LoadSecret(sec); err != nil {
					return nil, err
				}
			}
			if skip {
				w.skipped[vrt] = true
			}

			inputs = append(inputs, data...)
		default:
			return nil, errors.New("unknown Node type")
		}

	}

	if err := cptx.Close(inputs, w.outputs[vrt]); err != nil {
		return nil, err
	}

	for i, vrt := range edges {
		w.outputs[vrt] = append(w.outputs[vrt], inputs[i])
	}

	node, err := w.graph.node(vrt)
	if err != nil {
		return nil, err
	}

	id, err := node.Digest()
	if err != nil {
		return nil, err
	}

	return material.New(id, w.outputs[vrt])
}

func (w *vaultWalker) shapeOutputs(vrt *graph.Vertex) error {
	for _, v := range w.graph.Edges(vrt) {
		w.outputs[v] = append(w.outputs[v], nil)
	}
	return nil
}

func (w *vaultWalker) unlock(vrt *graph.Vertex) error {
	node, err := w.graph.node(vrt)
	if err != nil {
		return err
	}

	id, err := node.Digest()
	if err != nil {
		return err
	}

	mtrl, err := w.drv.LoadMaterial(id)
	if err != nil {
		return err
	}
	if mtrl != nil {
		w.outputs[vrt] = mtrl.Data
		return nil
	}

	switch node.Type() {
	case CryptexNode:
		cptx, err := node.Cryptex()
		if err != nil {
			return err
		}
		if mtrl, err = w.unlockCryptex(cptx, vrt); err != nil {
			return err
		}

		if mtrl != nil {
			return w.drv.StoreMaterial(mtrl)
		}
	case SecretNode:
		sec, err := node.Secret()
		if err != nil {
			return err
		}

		output, skip, err := w.drv.LoadSecret(sec)
		if err != nil {
			return err
		}
		if skip {
			w.skipped[vrt] = true
		}
		w.outputs[vrt] = output
	case MarkerNode:
		nfp, err := node.Digest()
		if err != nil {
			return err
		}

		mtrl, err := w.material(nfp)
		if err != nil {
			return err
		}
		w.outputs[vrt] = mtrl.Data
	default:
		return errors.New("unknown Node type")
	}

	return nil
}

func (w *vaultWalker) unlockCryptex(cptx cryptex.Cryptex, vrt *graph.Vertex) (*material.Material, error) {
	edges := w.graph.Edges(vrt)
	inputs := make([][]byte, 0, w.graph.Adjacency[vrt].Len())

	skippable := false
	for _, vrt := range edges {
		inputs = append(inputs, w.outputs[vrt][0])
		if len(w.outputs[vrt]) > 1 {
			w.outputs[vrt] = w.outputs[vrt][1:]
		} else {
			w.outputs[vrt] = [][]byte{}
		}

		if w.skipped[vrt] {
			skippable = true
		}
	}
	if err := cptx.Open(w.outputs[vrt], inputs); err != nil {
		if skippable {
			w.skipped[vrt] = true
			// TODO w.drv.Warn(err)
			return nil, nil
		}
		return nil, err
	}

	node, err := w.graph.node(vrt)
	if err != nil {
		return nil, err
	}

	id, err := node.Digest()
	if err != nil {
		return nil, err
	}

	return material.New(id, w.outputs[vrt])
}

func (w *vaultWalker) material(id []byte) (*material.Material, error) {
	for _, mtrl := range w.materials {
		if bytes.Equal(id, mtrl.ID) {
			return mtrl, nil
		}
	}
	return nil, errors.New("no Material for Node")
}
