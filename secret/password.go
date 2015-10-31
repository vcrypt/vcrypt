package secret

import (
	"io"
	"io/ioutil"
)

// NewPassword constructs a Password secret.
func NewPassword(comment string) *Password {
	return &Password{
		comment: comment,
	}
}

// Comment string
func (s *Password) Comment() string {
	return s.comment
}

// Phase is Dual
func (s *Password) Phase() Phase { return Dual }

// Load reads the input data and returns the password bytes.
func (*Password) Load(r io.Reader) ([][]byte, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return [][]byte{data}, nil
}
