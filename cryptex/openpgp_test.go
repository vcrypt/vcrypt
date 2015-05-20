package cryptex

import (
	"bytes"
	"reflect"
	"testing"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/ripemd160"
)

var _ = ripemd160.Size // force import

func TestOpenPGP(t *testing.T) {
	want := [][]byte{[]byte("super secret password")}
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(rsaPubKey))
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	entity := el[0]
	if err := entity.Serialize(buf); err != nil {
		t.Fatal(err)
	}

	cptx, err := NewOpenPGP(el, "OpenPGP cryptex")
	if err != nil {
		t.Fatal(err)
	}

	inputs := make([][]byte, 2)
	if err := cptx.Close(inputs, want); err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Errorf("want openpgp len(inputs) = 2, got %d", len(inputs))
	}

	el, err = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(rsaPrivKey))
	if err != nil {
		t.Fatal(err)
	}

	buf = bytes.NewBuffer(nil)
	if err := el[0].SerializePrivate(buf, nil); err != nil {
		t.Fatal(err)
	}
	inputs[1] = buf.Bytes()

	got := make([][]byte, len(want))
	if err := cptx.Open(got, inputs); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("want secret %q, got %q", want, got)
	}

	inputs[0][0] = inputs[0][0] ^ 1
	if err := cptx.Open(got, inputs); err == nil {
		t.Errorf("openpgp cryptex unlocked with invalid solution")
	}
}

func TestRoundTripOpenPGP(t *testing.T) {
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(rsaPubKey))
	if err != nil {
		t.Fatal(err)
	}

	buf := bytes.NewBuffer(nil)
	entity := el[0]
	if err := entity.Serialize(buf); err != nil {
		t.Fatal(err)
	}

	want, err := NewOpenPGP(el, "OpenPGP cryptex")
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

	if !reflect.DeepEqual(want, got.(*OpenPGP)) {
		t.Errorf("want OpenPGP cryptex %v, got %v", want, got)
	}
}

var (
	rsaPubKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFThW5wBCADY1+WZXNcok0cgK2dDECc1xOSD63IMKs+Z5b8TG/u7DHsuz5zX
UnZrECAvV1gFQuOsYmzRRDPFMW5xm/mgH+wD9de5ZJ+MXTkzLa5ipHx10RUedq+7
WbacZmg/eLnnrjKEC7FvPKcbXBC+0YnGhK8QHVmYyr9Xog28/cfqh2VBPqgpAele
uQLNT9Xau+1bek4aQl7sbirfooLCQ07pje8TnHCwyBBvdxHj3v0xB/tC6EC+QScS
QMoe+NLd+/AaNZyAQpeT27C9jRRKaX0dzsmgBbApm2ooX+g+QtMWS0ATow8zoBSD
+xergeycpaRgBtH3jxC7IKkYPT8CmHdPEG6fABEBAAG0KlRlc3QgS2V5IChUZXN0
IFJTQSBLZXkpIDx0ZXN0QGV4YW1wbGUuY29tPokBOAQTAQIAIgUCVOFbnAIbAwYL
CQgHAwIGFQgCCQoLBBYCAwECHgECF4AACgkQrp06evrt3nqEFQf+OBVOp7iq1zhV
OzcWKXeDDwICbiYSe6nE0fnn8eyI4GtpN6CDosy9RGpIJkQy/Gqat5DGofhCQ4Bq
bsW1Xhq+9MHq9gPpmbvhQEWp/GPOVoDf+gkbwcEgPGdDyFQL41SqcANfTZFMXkIc
Vi/mp0PqQlpcghHE9E0yKBIndH1BieakMDl9DxgPN0Q0WuoKjmdCqwxBMp/c9kFC
asvE7hJbvg8JQq3cu9RFweg7Svg7uEiSPZR2t3ga4IDAGd3xt4dhbKyeooyik9yu
rkA0UpVEISAuk24IMncg/GGfvCAwo0uv/oAr6eAQcol3BK8dCJRX3oM2Z81OId84
VOfeEjstorkBDQRU4VucAQgAtCZWcYnZL2WSrCmSZwdsjb8FDGREZxqQGCzh5Su5
Aq+YE9YkmO+bGTAoCUkQmAp5OSUMcH8EQ15xb7Cms3Rf8fsNW6GMGMxiT/4bLRgc
0iccJWjVXC/SHKsWH4WkwJFahmLIAfKBqemKzjMfotlOhqkbv5Ni94yHmmUNWelf
IL9EtPmJdGWFeGAWCzwfprWQtESN7B3W2tOhfxqj4V0SvlYpMhaO63Mwk9VCJVaK
DRT2+PKoxzRNmXi9iaKZxjxMoB7NJXm6er4WqxFPfzDUUa8XlXeIKMkpl45S6OhC
85gxCDTG+SszUQob/hbTCN1yEObQr2IsazwTnZ+XNx4RJQARAQABiQEfBBgBAgAJ
BQJU4VucAhsMAAoJEK6dOnr67d56guMH/0Jz5cT2goIM+pmHsiBgHgCWfJ/N12gY
6zljsGEbG24XHM+hKU4y54jxaOBi5rLzH/QEg04bhH/bk5EXAmYfpMWAcaGHO9TW
B+i/xw78vbqTRfD8ejYZTe1G6t5ceFmYJ/4ZNcL19DlO5xFmelp52skPJ9WEsURA
36iu6S3CF51V04KbTpjALJouLT7kuDy916tCOXY35NoSoMlcYkso+bZooeCoaftI
ZVqBZvXoiXzUpMg1b7jTStHnVT707ZXyXV40urp1Ec7/nBv75gPoazFD1/a6Hq7r
IouoOWzFwp1vrV/iJwq2jBXxYo1vAIzbqBdHylc9/5Tgyz2KcM+6+F0=
=5Mhy
-----END PGP PUBLIC KEY BLOCK-----`

	rsaPrivKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1

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
=35nZ
-----END PGP PRIVATE KEY BLOCK-----`
)
