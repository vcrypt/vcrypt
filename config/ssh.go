package config

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"reflect"

	"golang.org/x/crypto/ssh"
)

func parseAuthorizedKey(in string) (key crypto.PublicKey, comment string, err error) {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(in))
	if err != nil {
		return nil, comment, err
	}

	val := reflect.ValueOf(pub).Elem()
	n := val.FieldByName("N").Interface().(*big.Int)
	e := val.FieldByName("E").Interface().(int)

	key = &rsa.PublicKey{
		N: n,
		E: e,
	}

	return
}
