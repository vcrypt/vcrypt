package cryptex

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// NewDemux constructs a new Demux cryptex. The HKDF cryptographic key
// derivation function is combined with XOR pads to map a multiple secrets to a
// single input.
func NewDemux(comment string) (*Demux, error) {
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, err
	}
	return &Demux{
		Seed:    seed,
		comment: comment,
	}, nil
}

// Comment string
func (c *Demux) Comment() string {
	return c.comment
}

// Close seals two or more non-nil secrets to an input.
func (c *Demux) Close(inputs, secrets [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) != 1 {
		return errors.New("Demux requires 1 input")
	}
	if len(secrets) <= 1 {
		return errors.New("Demux supports 2 or more secrets")
	}
	if nonNilLen(secrets) != len(secrets) {
		return errors.New("Demux secrets must be non-nil")
	}

	bs := &ByteStream{Chunks: make([][]byte, len(secrets))}

	hfn := sha256.New
	hsize := sha256.Size

	seq := seedSeq(c.Seed, len(secrets))
	for i, secret := range secrets {
		chunk := make([]byte, hsize+len(secret))
		mask := make([]byte, len(secret))

		if _, err := io.ReadFull(rand.Reader, chunk[:hsize]); err != nil {
			return err
		}

		seed := xorMask(nil, chunk[:hsize], seq.Key(hsize))
		mrdr := hkdf.New(hfn, seed, nil, nil)
		if _, err := io.ReadFull(mrdr, mask); err != nil {
			return err
		}

		xorMask(chunk[hsize:], secret, mask)
		bs.Chunks[i] = chunk
	}

	input, err := bs.Marshal()
	if err != nil {
		return err
	}

	inputs[0] = input
	return nil
}

// Open unseals two or more secrets from a single input.
func (c *Demux) Open(secrets, inputs [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(secrets) <= 1 {
		return errors.New("Not enough secrets")
	}
	if len(inputs) != 1 {
		return errors.New("More inputs required")
	}
	input := inputs[0]

	bs := &ByteStream{}
	if err := bs.Unmarshal(input); err != nil {
		return err
	}

	if len(secrets) != len(bs.Chunks) {
		return errors.New("secret count must equal chunk count")
	}

	hfn := sha256.New
	hsize := sha256.Size

	seq := seedSeq(c.Seed, len(secrets))
	for i := range secrets {
		chunk := bs.Chunks[i]
		if len(chunk) < hsize {
			return errors.New("chunk length below minimum")
		}

		mask := make([]byte, len(chunk)-hsize)
		seed := xorMask(nil, chunk[:hsize], seq.Key(hsize))
		mrdr := hkdf.New(hfn, seed, nil, nil)
		if _, err := io.ReadFull(mrdr, mask); err != nil {
			return err
		}

		secrets[i] = xorMask(nil, chunk[hsize:], mask)
	}

	return nil
}

func (c *Demux) validate() error {
	if len(c.Seed) != sha256.Size {
		return errors.New("Seed must be 32 bytes")
	}
	return nil
}
