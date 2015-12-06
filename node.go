package vcrypt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/vcrypt/vcrypt/cryptex"
	"github.com/vcrypt/vcrypt/secret"
)

// NodeType marks the type of data held by a Node.
type NodeType int

const (
	// CryptexNode contains a marshaled cryptex.
	CryptexNode NodeType = iota + 1

	// SecretNode holds a marshaled secret.
	SecretNode

	// MarkerNode marks material data.
	MarkerNode
)

// NewCryptexNode constructs a node with the marshaled cryptex data.
func NewCryptexNode(cptx cryptex.Cryptex, inputs [][]byte) (*Node, error) {
	env, err := cryptex.Wrap(cptx)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Node{
		Nonce:   nonce,
		Inputs:  inputs,
		cryptex: env,
	}, nil
}

// NewSecretNode constructs a node with the marshaled secret data.
func NewSecretNode(sec secret.Secret) (*Node, error) {
	env, err := secret.Wrap(sec)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Node{
		Nonce:  nonce,
		secret: env,
	}, nil
}

// NewMarkerNode constructs a node with a marker for material data.
func NewMarkerNode(mrkr *Marker) (*Node, error) {
	nonce := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return &Node{
		Nonce:  nonce,
		Marker: mrkr,
	}, nil
}

// Cryptex returns the unmarshaled cryptex held by the node.
func (n *Node) Cryptex() (cryptex.Cryptex, error) {
	if n.cryptex == nil {
		return nil, nil
	}
	return n.cryptex.Cryptex()
}

// Secret returns the unmarshaled secret held by the node.
func (n *Node) Secret() (secret.Secret, error) {
	if n.secret == nil {
		return nil, nil
	}
	return n.secret.Secret()
}

// Comment string
func (n *Node) Comment() (string, error) {
	switch {
	case n.cryptex != nil:
		cptx, err := n.cryptex.Cryptex()
		if err != nil {
			return "", err
		}
		return cptx.Comment(), nil
	case n.secret != nil:
		sec, err := n.secret.Secret()
		if err != nil {
			return "", err
		}
		return sec.Comment(), nil
	case n.Marker != nil:
		return n.Marker.Comment, nil
	default:
		return "", errors.New("invalid Node, nil members")
	}
}

// Digest returns a unique series of bytes that identify the node.
func (n *Node) Digest() ([]byte, error) {
	// HMAC(Nonce,Inputs[*]|(Cryptex||Secret||Marker))
	hash := hmac.New(sha256.New, n.Nonce)

	for _, input := range n.Inputs {
		if _, err := hash.Write(input); err != nil {
			return nil, err
		}
	}

	var (
		data []byte
		err  error
	)

	switch {
	case n.cryptex != nil:
		data, err = n.cryptex.Marshal()
	case n.secret != nil:
		data, err = n.secret.Marshal()
	case n.Marker != nil:
		data, err = n.Marker.Marshal()
	}

	if err != nil {
		return nil, err
	}

	if _, err := hash.Write(data); err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}

// Type of Node
func (n *Node) Type() NodeType {
	switch {
	case n.cryptex != nil:
		return CryptexNode
	case n.secret != nil:
		return SecretNode
	case n.Marker != nil:
		return MarkerNode
	default:
		panic("unrecognizable Node type")
	}
}
