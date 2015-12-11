package cryptex

import (
	"errors"
	"reflect"
	"testing"
)

func TestMSP(t *testing.T) {
	want := [][]byte{[]byte("this is 16 bytes")}
	table := []string{"Alice", "Bob", "Carl"}

	cptx, err := NewMSP("(Alice | Bob) & Carl", table, "MSP cryptex")
	if err != nil {
		t.Fatal(err)
	}

	inputs := make([][]byte, 3)
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

	tests := []struct {
		shares [][]byte

		want [][]byte
		err  error
	}{
		// Alice & Bob
		{
			shares: [][]byte{inputs[0], inputs[1], nil},
			err:    errors.New("Not enough shares to recover."),
		},
		// Alice & Carl
		{
			shares: [][]byte{inputs[0], nil, inputs[2]},
			want:   want,
		},
		// Bob & Carl
		{
			shares: [][]byte{nil, inputs[1], inputs[2]},
			want:   want,
		},
	}

	for _, test := range tests {
		got := make([][]byte, len(want))
		if err := cptx.Open(got, test.shares); err != nil {
			if test.err == nil {
				t.Error(test.err)
				continue
			}
			if err.Error() != test.err.Error() {
				t.Errorf("want error %q, got %q", test.err, err)
			}
			continue
		}

		if test.want != nil {
			if !reflect.DeepEqual(test.want, got) {
				t.Errorf("want secret %q, got %q", test.want, got)
			}
		}
	}
}

func TestRoundTripMSP(t *testing.T) {
	want, err := NewMSP("(a | b) & c", []string{"a", "b", "c"}, "MSP cryptex")
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

	if gotMSP := *got.(*MSP); want.Predicate != gotMSP.Predicate {
		t.Errorf("want MSP cryptex %v, got %v", want, got)
	}
}
