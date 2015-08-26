package material

import (
	"reflect"
	"testing"
)

func TestMaterialRoundTrip(t *testing.T) {
	id, want := []byte(`test id`), [][]byte{[]byte(`test value`)}
	mtrl, err := New(id, want)
	if err != nil {
		t.Fatal(err)
	}

	data, err := mtrl.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	mtrl = &Material{}
	if err := mtrl.Unmarshal(data); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(id, mtrl.ID) {
		t.Errorf("want id %+v, got %+v", id, mtrl.ID)
	}
	if !reflect.DeepEqual(want, mtrl.Data) {
		t.Errorf("want data %+v, got %+v", want, mtrl.Data)
	}
}
