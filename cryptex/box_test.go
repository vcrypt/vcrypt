package cryptex

import (
	"crypto/rand"
	"reflect"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestBox(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cptx := NewBox(pk[:], "Box cryptex")

	inputs := make([][]byte, 2)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if inputs[1] != nil {
		t.Errorf("want inputs[1] to be nil, got %v", inputs[1])
	}
	inputs[1] = sk[:]

	got := make([][]byte, len(want))
	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	inputs[0][0] = inputs[0][0] ^ 1
	if err := cptx.Open(got, inputs); err == nil {
		t.Errorf("box cryptex opened with bad nonce")
	}
}

func TestRoundTripBox(t *testing.T) {
	pk, _, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	want := NewBox(pk[:], "Box cryptex")

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got.(*Box)) {
		t.Errorf("want Box cryptex %v, got %v", want, got)
	}
}
