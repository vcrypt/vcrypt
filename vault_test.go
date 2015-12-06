package vcrypt

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/vcrypt/vcrypt/internal/test"
	"github.com/vcrypt/vcrypt/secret"
	"golang.org/x/crypto/openpgp"
)

var (
	twoManVault, twoManSecret     = buildVault(twoManPlan, twoManDriver)
	twoPartyVault, twoPartySecret = buildVault(twoPartyPlan, twoPartyDriver)
	diamondVault, diamondSecret   = buildVault(diamondPlan, diamondDriver)
	dnsSecVault, dnsSecSecret     = buildVault(dnsSecPlan, dnsSecDriver)

	twoManDriver = test.Driver(map[string][]byte{
		"op 1 secret": []byte("key #1"),
		"op 2 secret": []byte("key #2"),
	})

	twoPartyDriver = test.Driver(map[string][]byte{
		"party 1 password 2": []byte("step #3 secret"),
		"party 2 password":   []byte("step #2 secret"),
		"party 1 password 1": []byte("step #1 secret"),
	})

	diamondDriver = test.Driver(map[string][]byte{
		"step 3 password":  []byte("step #3 password"),
		"step 2a password": []byte("step #2a password"),
		"step 2b password": []byte("step #2b password"),
		"step 1 password":  []byte("step #1 password"),
	})

	dnsSecDriver = test.Driver(map[string][]byte{
		test.OpenPGPKeys["alice"].KeyID:  mustOpenPGPKey(test.OpenPGPKeys["alice"].Private),
		test.OpenPGPKeys["bob"].KeyID:    mustOpenPGPKey(test.OpenPGPKeys["bob"].Private),
		test.OpenPGPKeys["claire"].KeyID: mustOpenPGPKey(test.OpenPGPKeys["claire"].Private),
		test.OpenPGPKeys["david"].KeyID:  mustOpenPGPKey(test.OpenPGPKeys["david"].Private),
		test.OpenPGPKeys["emily"].KeyID:  mustOpenPGPKey(test.OpenPGPKeys["emily"].Private),
		test.OpenPGPKeys["frank"].KeyID:  mustOpenPGPKey(test.OpenPGPKeys["frank"].Private),
		test.OpenPGPKeys["gloria"].KeyID: mustOpenPGPKey(test.OpenPGPKeys["gloria"].Private),
	})
)

func TestVault(t *testing.T) {
	tests := []struct {
		vault  *Vault
		drv    Driver
		secret []byte
	}{
		{twoManVault, twoManDriver, twoManSecret},
		{twoPartyVault, twoPartyDriver, twoPartySecret},
		{diamondVault, diamondDriver, diamondSecret},
		{dnsSecVault, dnsSecDriver, dnsSecSecret},
	}

	for _, test := range tests {
		var got bytes.Buffer
		if _, err := test.vault.Unlock(&got, test.drv); err != nil {
			t.Error(err)
			continue
		}

		want := test.secret
		if !bytes.Equal(want, got.Bytes()) {
			t.Errorf("vault unlocked bad secret: want %v, got %v", want, got.Bytes())
		}
	}
}

type skipDriver struct {
	test.Driver

	skippable map[string]bool
}

func (d skipDriver) LoadSecret(sec secret.Secret) ([][]byte, bool, error) {
	if _, ok := d.Driver[sec.Comment()]; !ok {
		return [][]byte{[]byte{}}, true, nil
	}

	return d.Driver.LoadSecret(sec)
}

func TestMultiPassVault(t *testing.T) {
	vault := dnsSecVault
	want, got := dnsSecSecret, bytes.Buffer{}

	driver := skipDriver{
		Driver: test.Driver{},
	}

	step := 0
	for _, key := range test.OpenPGPKeys {
		driver.Driver[key.KeyID] = mustOpenPGPKey(key.Private)

		ok, err := vault.Unlock(&got, driver)
		if err != nil {
			t.Fatal(err)
		}

		if step++; step == 5 {
			if !ok {
				t.Fatalf("vault failed to unlock after 5th pass")
			}

			break
		}

		if ok {
			t.Fatalf("vault opened too early")
		}
		if len(got.Bytes()) > 0 {
			t.Fatalf("vault unlock wrote secret prior to successful unlock")
		}

		delete(driver.Driver, key.KeyID)
	}

	if !bytes.Equal(want, got.Bytes()) {
		t.Errorf("vault unlocked bad secret: want %v, got %v", want, got.Bytes())
	}
}

func buildVault(plan *Plan, drv Driver) (*Vault, []byte) {
	secret := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		panic(err)
	}

	vault, err := NewVault(plan, plan.Comment())
	if err != nil {
		panic(err)
	}

	if err := vault.Lock(bytes.NewBuffer(secret), drv); err != nil {
		panic(err)
	}
	return vault, secret
}

func mustOpenPGPKey(keyPEM string) []byte {
	el, err := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(keyPEM))
	if err != nil {
		panic(err)
	}

	buf := bytes.NewBuffer(nil)
	if err := el[0].SerializePrivate(buf, nil); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
