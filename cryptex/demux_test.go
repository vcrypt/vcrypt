package cryptex

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

func TestDemux(t *testing.T) {
	want := [][]byte{
		[]byte("first super secret password"),
		[]byte("second super secret password"),
		[]byte("third super secret password"),
	}
	cptx, err := NewDemux("Demux cryptex")
	if err != nil {
		t.Fatal(err)
	}

	inputs := make([][]byte, 1)
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

	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	inputs[0][0] = inputs[0][0] ^ 1
	if err := cptx.Open(got, inputs); err == nil {
		t.Errorf("demux cryptex opened with corrupt bytestream")
	}

	if err := cptx.Open(got, make([][]byte, 17)); err == nil {
		t.Errorf("demux cryptex opened without non-nil input")
	}
}

func TestRoundTripDemux(t *testing.T) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		t.Fatal(err)
	}

	want, err := NewDemux("Demux cryptex")
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

	if !reflect.DeepEqual(want, got.(*Demux)) {
		t.Errorf("want Demux cryptex %v, got %v", want, got)
	}
}
