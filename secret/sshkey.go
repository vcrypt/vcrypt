package secret

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/ssh"
)

func NewSSHKey(fingerprint, comment string) (*SSHKey, error) {
	if _, _, err := parseFingerprint(fingerprint); err != nil {
		return nil, err
	}

	return &SSHKey{
		fingerprint: fingerprint,
		comment:     comment,
	}, nil
}

// Comment string
func (s *SSHKey) Comment() string {
	return s.comment
}

// Phase is Unlock
func (s *SSHKey) Phase() Phase { return Unlock }

func (s *SSHKey) Load(r io.Reader) ([][]byte, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if err := s.verify(data); err != nil {
		return nil, err
	}

	return [][]byte{data}, nil
}

func (s *SSHKey) verify(keyData []byte) error {
	rawKey, err := ssh.ParseRawPrivateKey(keyData)
	if err != nil {
		return err
	}

	privKey, ok := rawKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("invalid ssh key, must be ssh-rsa")
	}

	signer, err := ssh.NewSignerFromSigner(privKey)
	if err != nil {
		return err
	}

	hash, fp, err := parseFingerprint(s.fingerprint)
	if err != nil {
		return err
	}
	if _, err := hash.Write(signer.PublicKey().Marshal()); err != nil {
		return err
	}
	if !bytes.Equal(fp, hash.Sum(nil)) {
		return errors.New("ssh key fingerprint mismatch")
	}

	return nil
}

func parseFingerprint(fingerprint string) (hash.Hash, []byte, error) {
	parts := strings.Split(fingerprint, ":")

	if len(parts) != 2 {
		return nil, nil, errors.New("invalid ssh key fingerprint")
	}

	algo, digest := parts[0], parts[1]
	if strings.ToUpper(algo) != "SHA256" {
		return nil, nil, fmt.Errorf("unsupported hash algorithm %q", algo)
	}

	// TODO(benburkert): switch to base64.RawStdEncoding for go1.6
	digest += "="

	fp, err := base64.StdEncoding.DecodeString(digest)
	return sha256.New(), fp, err
}
