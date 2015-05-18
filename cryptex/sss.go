package cryptex

import (
	"errors"
	"fmt"

	"github.com/codahale/sss"
)

// NewSSS constructs a new SSS for N shares of which K are required to recover
// the secrets.
func NewSSS(n, k uint32, comment string) *SSS {
	return &SSS{
		N:       n,
		K:       k,
		comment: comment,
	}
}

// Comment string
func (c *SSS) Comment() string {
	return c.comment
}

// Close seals the secret to the N inputs.
func (c *SSS) Close(inputs, secrets [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if len(inputs) < int(c.K) || len(inputs) > int(c.N) {
		return fmt.Errorf("between %d and %d inputs required", c.N, c.K)
	}
	if len(secrets) != 1 {
		return errors.New("SSS supports only a single secret")
	}

	shares, err := sss.Split(byte(c.N), byte(c.K), secrets[0])
	if err != nil {
		return err
	}

	for k, v := range shares {
		if idx := int(k - 1); idx < len(inputs) {
			inputs[idx] = v
		}
	}
	return nil
}

// Open unseals the secret from the N inputs, of which K are required.
func (c *SSS) Open(secrets, inputs [][]byte) error {
	if err := c.validate(); err != nil {
		return err
	}
	if nonNilLen(inputs) < int(c.K) {
		return errors.New("Not enough inputs")
	}
	if nonNilLen(inputs) > int(c.N) {
		return errors.New("Too many inputs")
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	shares := make(map[byte][]byte, len(inputs))
	for i, v := range inputs {
		if v != nil {
			shares[byte(i+1)] = v
		}
	}

	secrets[0] = sss.Combine(shares)
	return nil
}

func (c *SSS) validate() error {
	if c.N <= 2 {
		return errors.New("N must be > 2")
	}
	if c.K <= 1 {
		return errors.New("K must be > 1")
	}
	if c.N > 255 {
		return errors.New("N must be < 256")
	}
	if c.K > 255 {
		return errors.New("K must be < 256")
	}
	if c.K >= c.N {
		return errors.New("N must be > K")
	}
	return nil
}
