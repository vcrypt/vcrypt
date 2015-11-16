package payload

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/benburkert/vcrypt/material"
)

func TestRoundTripDetached(t *testing.T) {
	d := &db{}

	want, err := NewDetached()
	if err != nil {
		t.Fatal(err)
	}

	wstr := "test data"
	key, err := want.Lock(bytes.NewBufferString(wstr), d)
	if err != nil {
		t.Fatal(err)
	}

	data, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got := &Detached{}
	if err := got.Unmarshal(data); err != nil {
		t.Fatal(err)
	}

	gbuf := new(bytes.Buffer)
	if err := got.Unlock(gbuf, key, d); err != nil {
		t.Fatal(err)
	}

	gstr := gbuf.String()
	if wstr != gstr {
		t.Errorf("want Blob %q, got %q", wstr, gstr)
	}
}

type db []*material.Material

func (d *db) LoadMaterial(id []byte) (*material.Material, error) {
	for _, mtrl := range *d {
		if reflect.DeepEqual(id, mtrl.ID) {
			return mtrl, nil
		}
	}
	return nil, nil
}

func (d *db) StoreMaterial(mtrl *material.Material) error {
	*d = append(*d, mtrl)
	return nil
}
