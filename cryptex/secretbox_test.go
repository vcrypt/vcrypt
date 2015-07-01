package cryptex

import (
	"reflect"
	"testing"
)

func TestSecretBox(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	cptx := NewSecretBox("SecretBox cryptex")

	inputs := make([][]byte, 2)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Errorf("want sss len(inputs) = 2, got %d", len(inputs))
	}

	got := make([][]byte, len(want))
	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	inputs[0][0] = inputs[0][0] ^ 1
	if err := cptx.Open(got, inputs); err == nil {
		t.Errorf("SecretBox cryptex unsealed with bad nonce")
	}

	pass := []byte("secretbox pass")
	inputs[0] = pass
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if err := cptx.Open(got, [][]byte{pass, inputs[1]}); err != nil {
		t.Errorf("SecretBox input password ignored")
	}
}

func TestRoundTripSecretBox(t *testing.T) {
	want := NewSecretBox("SecretBox cryptex")

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if *want != *got.(*SecretBox) {
		t.Errorf("want SecretBox cryptex %v, got %v", want, got)
	}
}
