package payload

import (
	"bytes"
	"testing"
)

func TestRoundTripAttached(t *testing.T) {
	want, err := NewAttached()
	if err != nil {
		t.Fatal(err)
	}

	wstr := "test data"
	key, err := want.Lock(bytes.NewBufferString(wstr))
	if err != nil {
		t.Fatal(err)
	}

	data, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	got := &Attached{}
	if err := got.Unmarshal(data); err != nil {
		t.Fatal(err)
	}

	gbuf := new(bytes.Buffer)
	if err := got.Unlock(gbuf, key); err != nil {
		t.Fatal(err)
	}

	gstr := gbuf.String()
	if wstr != gstr {
		t.Errorf("want Blob %q, got %q", wstr, gstr)
	}
}
