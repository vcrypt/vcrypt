package config

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
	"strings"

	"github.com/vcrypt/vcrypt/cryptex"
	"github.com/vcrypt/vcrypt/secret"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh"
)

// Plan config
type Plan struct {
	// Top level config
	Comment string `vcrypt:"comment,optional"`
	Root    string `vcrypt:"root"`

	// Cryptex config
	SSSs        map[string]SSS       `vcrypt:"sss,section"`
	XORs        map[string]XOR       `vcrypt:"xor,section"`
	SecretBoxes map[string]SecretBox `vcrypt:"secretbox,section"`
	Boxes       map[string]Box       `vcrypt:"box,section"`
	RSAs        map[string]RSA       `vcrypt:"rsa,section"`
	OpenPGPs    map[string]OpenPGP   `vcrypt:"openpgp,section"`
	Muxes       map[string]Mux       `vcrypt:"mux,section"`
	Demuxes     map[string]Demux     `vcrypt:"demux,section"`
	MSPs        map[string]MSP       `vcrypt:"msp,section"`

	// Secret config
	Passwords   map[string]Password   `vcrypt:"password,section"`
	OpenPGPKeys map[string]OpenPGPKey `vcrypt:"openpgp-key,section"`
	SSHKeys     map[string]SSHKey     `vcrypt:"ssh-key,section"`

	// Material config
	Materials map[string]Marker `vcrypt:"material,section"`
}

// CryptexNode config
type CryptexNode interface {
	Cryptex() (cryptex.Cryptex, error)
	Edges() []string
}

// SecretNode config
type SecretNode interface {
	Secret() (secret.Secret, error)
}

// Marker config
type Marker struct {
	Comment string `vcrypt:"comment,optional"`
}

// CryptexNode returns the CryptexNode for the name.
func (p Plan) CryptexNode(name string) (CryptexNode, bool) {
	if n, ok := p.SSSs[name]; ok {
		return n, true
	}
	if n, ok := p.XORs[name]; ok {
		return n, true
	}
	if n, ok := p.SecretBoxes[name]; ok {
		return n, true
	}
	if n, ok := p.Boxes[name]; ok {
		return n, true
	}
	if n, ok := p.RSAs[name]; ok {
		return n, true
	}
	if n, ok := p.OpenPGPs[name]; ok {
		return n, true
	}
	if n, ok := p.Muxes[name]; ok {
		return n, true
	}
	if n, ok := p.Demuxes[name]; ok {
		return n, true
	}
	if n, ok := p.MSPs[name]; ok {
		return n, true
	}

	return nil, false
}

// SecretNode returns the SecretNode for the name.
func (p Plan) SecretNode(name string) (SecretNode, bool) {
	if n, ok := p.Passwords[name]; ok {
		return n, true
	}
	if n, ok := p.OpenPGPKeys[name]; ok {
		return n, true
	}
	if n, ok := p.SSHKeys[name]; ok {
		return n, true
	}

	return nil, false
}

// SSS config
type SSS struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`

	N int `vcrypt:"max-shares"`
	K int `vcrypt:"required-shares"`
}

// Cryptex for SSS
func (n SSS) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewSSS(uint32(n.N), uint32(n.K), n.Comment), nil
}

// Edges for SSS
func (n SSS) Edges() []string { return n.EdgeSlice }

// XOR config
type XOR struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`
}

// Cryptex for XOR
func (n XOR) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewXOR(n.Comment), nil
}

// Edges for XOR
func (n XOR) Edges() []string { return n.EdgeSlice }

// SecretBox config
type SecretBox struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`
}

// Cryptex for SecretBox
func (n SecretBox) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewSecretBox(n.Comment), nil
}

// Edges for SecretBox
func (n SecretBox) Edges() []string { return n.EdgeSlice }

// Box config
type Box struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`

	PublicKey string `vcrypt:"publickey"`
}

// Cryptex for Box
func (n Box) Cryptex() (cryptex.Cryptex, error) {
	pk, err := base64.StdEncoding.DecodeString(n.PublicKey)
	if err != nil {
		return nil, err
	}

	return cryptex.NewBox(pk, n.Comment), nil
}

// Edges for Box
func (n Box) Edges() []string { return n.EdgeSlice }

// RSA config
type RSA struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`

	PKIXKey string `vcrypt:"pkix-key,optional"`
	SSHKey  string `vcrypt:"ssh-key,optional"`
}

// Cryptex for RSA
func (n RSA) Cryptex() (cryptex.Cryptex, error) {
	var (
		pk      crypto.PublicKey
		comment string
		err     error
	)

	switch {
	case n.PKIXKey != "":
		p, _ := pem.Decode([]byte(n.PKIXKey))
		if p == nil {
			return nil, errors.New("invalid PKIX RSA key, must be PEM encoded")
		}

		if pk, err = x509.ParsePKIXPublicKey(p.Bytes); err != nil {
			return nil, err
		}
	case n.SSHKey != "":
		if pk, comment, err = parseAuthorizedKey(n.SSHKey); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("rsa cryptex requires either pkix-key or ssh-key")
	}

	b, err := x509.MarshalPKIXPublicKey(pk.(*rsa.PublicKey))
	if err != nil {
		return nil, err
	}

	if n.Comment != "" {
		comment = n.Comment
	}

	return cryptex.NewRSA(b, comment), nil
}

// Edges for RSA
func (n RSA) Edges() []string { return n.EdgeSlice }

// OpenPGP config
type OpenPGP struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`

	PublicKeys []string `vcrypt:"publickey"`
}

// Cryptex for OpenPGP
func (n OpenPGP) Cryptex() (cryptex.Cryptex, error) {
	es := make([]*openpgp.Entity, 0, len(n.PublicKeys))
	for _, pubkey := range n.PublicKeys {
		el, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(pubkey))
		if err != nil {
			return nil, err
		}
		es = append(es, el...)
	}

	return cryptex.NewOpenPGP(es, n.Comment)
}

// Edges for OpenPGP
func (n OpenPGP) Edges() []string { return n.EdgeSlice }

// Mux config
type Mux struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`
}

// Cryptex for Mux
func (n Mux) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewMux(n.Comment)
}

// Edges for Mux
func (n Mux) Edges() []string { return n.EdgeSlice }

// Demux config
type Demux struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`
}

// Cryptex for Demux
func (n Demux) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewDemux(n.Comment)
}

// Edges for Demux
func (n Demux) Edges() []string { return n.EdgeSlice }

// MSP config
type MSP struct {
	Comment   string   `vcrypt:"comment,optional"`
	EdgeSlice []string `vcrypt:"edge,optional"`

	Predicate string `vcrypt:"predicate"`
}

func (n MSP) Cryptex() (cryptex.Cryptex, error) {
	return cryptex.NewMSP(n.Predicate, n.Edges(), n.Comment)
}

func (n MSP) Edges() []string { return n.EdgeSlice }

// Password config
type Password struct {
	Comment string `vcrypt:"comment,optional"`
}

// Secret for Password
func (n Password) Secret() (secret.Secret, error) {
	return secret.NewPassword(n.Comment), nil
}

// OpenPGPKey config
type OpenPGPKey struct {
	Comment string `vcrypt:"comment,optional"`

	KeyIDs []string `vcrypt:"keyid,optional"`
}

// Secret for OpenPGPKey
func (n OpenPGPKey) Secret() (secret.Secret, error) {
	keyIDs := make([]uint64, 0, len(n.KeyIDs))
	for _, strID := range n.KeyIDs {
		id, err := strconv.ParseUint(strID, 16, 64)
		if err != nil {
			return nil, err
		}
		keyIDs = append(keyIDs, uint64(id))
	}

	return secret.NewOpenPGPKey(keyIDs, n.Comment), nil
}

// SSKey config
type SSHKey struct {
	Comment string `vcrypt:"comment,optional"`

	AuthorizedKey string `vcrypt:"authorized-key,optional"`
	Fingerprint   string `vcrypt:"fingerprint,optional"`
}

// Secret for SSHKey
func (n SSHKey) Secret() (secret.Secret, error) {
	if n.Fingerprint != "" {
		return secret.NewSSHKey(n.Fingerprint, n.Comment)
	}

	if n.AuthorizedKey == "" {
		return nil, errors.New("ssh secret requires either authorized-key or fingerprint")
	}

	pk, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(n.AuthorizedKey))
	if err != nil {
		return nil, err
	}

	if n.Comment != "" {
		comment = n.Comment
	}

	sum := sha256.Sum256(pk.Marshal())
	digest := base64.StdEncoding.EncodeToString(sum[:])
	fingerprint := "SHA256:" + strings.TrimRight(digest, "=")

	return secret.NewSSHKey(fingerprint, comment)
}
