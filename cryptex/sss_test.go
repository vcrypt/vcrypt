package cryptex

import (
	"reflect"
	"testing"
)

func TestSSS(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	cptx := NewSSS(11, 7, "SSS cryptex")

	inputs := make([][]byte, 11)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if int(cptx.N) != len(inputs) {
		t.Errorf("want sss len(inputs) = %d, got %d", cptx.N, len(inputs))
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

	if err := cptx.Open(got, inputs[:6]); err == nil {
		t.Errorf("sss cryptex opened with too few inputs")
	}
}

func TestRoundTripSSS(t *testing.T) {
	want := NewSSS(7, 5, "SSS cryptex")

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if *want != *got.(*SSS) {
		t.Errorf("want SSS cryptex %v, got %v", want, got)
	}
}
