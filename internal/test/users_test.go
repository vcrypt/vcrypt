package test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ssh"
)

func TestUsers(t *testing.T) {
	for _, data := range Users {
		testOpenPGPKey(t, data.OpenPGPKey)
		testSSHKey(t, data.SSHKey)
	}
}

func testOpenPGPKey(t *testing.T, openPGPKey OpenPGPKey) {
	buf := bytes.NewBufferString(openPGPKey.Private)
	el, err := openpgp.ReadArmoredKeyRing(buf)
	if err != nil {
		t.Fatal(err)
	}

	if len(el) != 1 {
		t.Errorf("want 1 key in openpgp keyring, got %d", len(el))
	}
	ent := el[0]

	keyID, err := strconv.ParseUint(openPGPKey.KeyID, 16, 64)
	if err != nil {
		t.Fatal(err)
	}

	if keyID != ent.PrimaryKey.KeyId {
		t.Errorf("want openpgp keyid = %x, got %x", keyID, ent.PrimaryKey.KeyId)
	}
}

func testSSHKey(t *testing.T, sshKey SSHKey) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(sshKey.Public))
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(pk.Marshal())
	digest := strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
	fp := "SHA256:" + digest

	if sshKey.Fingerprint != fp {
		t.Errorf("want sshkey fingerprint %q, got %q", sshKey.Fingerprint, fp)
	}
}
