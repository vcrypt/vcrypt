package test

import "testing"

func TestSealer(t *testing.T) {
	message := []byte("a message to seal")

	seal, err := Sealer.Seal(message)
	if err != nil {
		t.Fatal(err)
	}

	if err := seal.Check(message); err != nil {
		t.Error(err)
	}
}
