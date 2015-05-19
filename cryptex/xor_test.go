package cryptex

import (
	"reflect"
	"testing"
)

func TestXOR(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	cptx := NewXOR("XOR cryptex")

	inputs := make([][]byte, 7)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}

	got := make([][]byte, len(want))
	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	inputs[0] = nil
	if err := cptx.Open(got, inputs); err == nil {
		t.Errorf("xor cryptex opened with nil input")
	}
}

func TestRoundTripXOR(t *testing.T) {
	want := NewXOR("XOR cryptex")

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if *want != *got.(*XOR) {
		t.Errorf("want XOR cryptex %v, got %v", want, got)
	}
}
