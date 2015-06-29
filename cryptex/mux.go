package cryptex

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/codahale/sskg"
	"golang.org/x/crypto/hkdf"
)

// NewMux constructs a new Mux cryptex. The HKDF cryptographic key derivation
// function is used to stretch the secret into multiple inputs.
func NewMux(comment string) (*Mux, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return &Mux{
		Seed:    seed,
		comment: comment,
	}, nil
}

// Comment string
func (c *Mux) Comment() string {
	return c.comment
}

// Close seals a single secret to two or more inputs. Each input is unique and
// any single input may recover the secret.
func (c *Mux) Close(inputs, secrets [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) <= 1 {
		return errors.New("Mux requires 2 or more inputs")
	}
	if len(secrets) != 1 {
		return errors.New("Mux supports 1 secret")
	}
	secret := secrets[0]

	hfn := sha256.New
	hsize := sha256.Size

	mask := make([]byte, len(secret))
	seq := seedSeq(c.Seed, len(inputs))
	for i := range inputs {
		input := make([]byte, len(secret)+hsize)

		if _, err := io.ReadFull(rand.Reader, input[:hsize]); err != nil {
			return err
		}

		seed := xorMask(nil, input[:hsize], seq.Key(hsize))
		mrdr := hkdf.New(hfn, seed, nil, nil)
		if _, err := io.ReadFull(mrdr, mask); err != nil {
			return err
		}

		xorMask(input[hsize:], secret, mask)
		inputs[i] = input

		seq.Next()
	}

	return nil
}

// Open unseals a single secret from at least one input.
func (c *Mux) Open(secrets, inputs [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) == 0 {
		return errors.New("Not enough inputs")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	hfn := sha256.New
	hsize := sha256.Size

	seq := seedSeq(c.Seed, len(inputs))
	for _, input := range inputs {
		if input == nil {
			seq.Next()
			continue
		}

		mask := make([]byte, len(input)-hsize)

		seed := xorMask(nil, input[:hsize], seq.Key(hsize))
		mrdr := hkdf.New(hfn, seed, nil, nil)
		if _, err := io.ReadFull(mrdr, mask); err != nil {
			return err
		}

		secrets[0] = xorMask(nil, input[hsize:], mask)
		return nil
	}

	return errors.New("Mux requires at least 1 non-nil input")
}

func (c *Mux) validate() error {
	if len(c.Seed) != sha256.Size {
		return errors.New("Seed must be 32 bytes")
	}
	return nil
}

func seedSeq(seed []byte, inputLen int) sskg.Seq {
	return sskg.New(sha256.New, seed, uint(inputLen))
}

func xorMask(dst, a, b []byte) []byte {
	if dst == nil {
		dst = make([]byte, len(a))
	}

	for i := range a {
		dst[i] = a[i] ^ b[i]
	}
	return dst
}
