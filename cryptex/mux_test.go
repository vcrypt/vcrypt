package cryptex

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestMux(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	cptx, err := NewMux("Mux cryptex")
	if err != nil {
		t.Fatal(err)
	}

	inputs := make([][]byte, 17)
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

	if err := cptx.Open(got, inputs[:7]); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	if err := cptx.Open(got, make([][]byte, 17)); err == nil {
		t.Errorf("mux cryptex opened without non-nil input")
	}

	singleInputs := make([][]byte, len(inputs))
	for i, input := range inputs {
		singleInputs[i] = input

		if err := cptx.Open(got, singleInputs); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("want secret %q, got %q", want, got)
		}

		singleInputs[i] = nil
	}
}

func TestRoundTripMux(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		t.Fatal(err)
	}

	want, err := NewMux("Mux cryptex")
	if err != nil {
		t.Fatal(err)
	}

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got.(*Mux)) {
		t.Errorf("want Mux cryptex %v, got %v", want, got)
	}
}
