package vcrypt

import (
	"reflect"
	"testing"

	"github.com/benburkert/vcrypt/cryptex"
	"github.com/benburkert/vcrypt/secret"
)

func TestNodeDigest(t *testing.T) {
	node, err := NewCryptexNode(cryptex.NewSecretBox("cryptex node test"), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = node.Digest(); err != nil {
		t.Fatal(err)
	}

	node, err = NewSecretNode(secret.NewPassword("secret node test"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = node.Digest(); err != nil {
		t.Fatal(err)
	}

	node, err = NewMarkerNode(&Marker{Comment: "marker node test"})
	if err != nil {
		t.Fatal(err)
	}

	if _, err = node.Digest(); err != nil {
		t.Fatal(err)
	}
}

func TestRoundTripNode(t *testing.T) {
	want, err := NewCryptexNode(cryptex.NewSecretBox("roundtrip node test"), [][]byte{})
	if err != nil {
		t.Fatal(err)
	}

	want.Inputs = [][]byte{
		[]byte("A"),
		[]byte("B"),
		[]byte("C"),
	}

	wfp, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}

	data, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got := &Node{}
	if err := got.Unmarshal(data); err != nil {
		t.Fatal(err)
	}

	gfp, err := got.Digest()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(wfp, gfp) {
		t.Errorf("want Node digest %x, got %x", wfp, gfp)
	}

	if !reflect.DeepEqual(*want, *got) {
		t.Errorf("want Node %v, got %v", want, got)
	}
}
