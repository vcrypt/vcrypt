package cryptex

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"reflect"
	"testing"
)

func TestRSA(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(priv.Public().(*rsa.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	cptx := NewRSA(pubKey, "RSA cryptex")

	inputs := make([][]byte, 2)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Errorf("want rsa len(inputs) = 2, got %d", len(inputs))
	}
	inputs[1] = x509.MarshalPKCS1PrivateKey(priv)

	got := make([][]byte, len(want))
	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}
}

func TestRoundTripRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := x509.MarshalPKIXPublicKey(priv.Public().(*rsa.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	want := NewRSA(pubKey, "RSA cryptex")

	data, err := Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got.(*RSA)) {
		t.Errorf("want RSA cryptex %v, got %v", want, got)
	}
}
