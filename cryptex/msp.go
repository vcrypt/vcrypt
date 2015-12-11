package cryptex

import (
	"errors"
	"fmt"

	"github.com/Bren2010/msp"
)

// NewMSP constructs a new MSP for a predicate string and an input table of
// role names.
func NewMSP(predicate string, inputTable []string, comment string) (*MSP,
	error) {
	_, err := msp.StringToMSP(predicate)
	if err != nil {
		return nil, err
	}

	return &MSP{
		Predicate:  predicate,
		InputTable: inputTable,
		comment:    comment,
	}, nil
}

// Comment string
func (c *MSP) Comment() string {
	return c.comment
}

// Close seals the secret to the Monotone Span Program.
func (c *MSP) Close(inputs, secrets [][]byte) error {
	if len(inputs) != len(c.InputTable) {
		return fmt.Errorf("exactly %d inputs required", len(c.InputTable))
	}

	if len(secrets) != 1 {
		return errors.New("MSP supports only a single secret")
	}

	pred, err := msp.StringToMSP(c.Predicate)
	if err != nil {
		return err
	}

	db := mspDatabase{}
	for _, name := range c.InputTable {
		db[name] = [][]byte{}
	}

	shares, err := pred.DistributeShares(secrets[0], db)
	if err != nil {
		return err
	}

	for i, name := range c.InputTable {
		share := &MSP_Share{
			Parts: shares[name],
		}

		data, err := share.Marshal()
		if err != nil {
			return nil
		}

		inputs[i] = data
	}
	return nil
}

// Open unseals the secret from the inputs that map to ordered role names in
// the input table.
func (c *MSP) Open(secrets, inputs [][]byte) error {
	if len(inputs) != len(c.InputTable) {
		return fmt.Errorf("exactly %d inputs expected", len(c.InputTable))
	}
	if len(secrets) != 1 {
		return errors.New("Too many secrets expected")
	}

	pred, err := msp.StringToMSP(c.Predicate)
	if err != nil {
		return err
	}

	db := mspDatabase{}
	for i, name := range c.InputTable {
		if len(inputs[i]) == 0 {
			continue
		}

		share := new(MSP_Share)
		if err := share.Unmarshal(inputs[i]); err != nil {
			return err
		}

		db[name] = share.Parts
	}

	secrets[0], err = pred.RecoverSecret(db)
	return err
}

type mspDatabase map[string][][]byte

func (d mspDatabase) ValidUser(name string) bool {
	_, ok := d[name]
	return ok
}

func (d mspDatabase) CanGetShare(name string) bool {
	_, ok := d[name]
	return ok
}

func (d mspDatabase) GetShare(name string) ([][]byte, error) {
	out, ok := d[name]

	if ok {
		return out, nil
	}
	return nil, fmt.Errorf("missing share %q", name)
}
