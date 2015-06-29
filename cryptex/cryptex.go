package cryptex

// Cryptex lock intermediate secrets.
type Cryptex interface {
	// Optional description of the cryptex usage.
	Comment() string

	// Close encloses the inputs into the secret.
	Close(inputs, secrets [][]byte) error

	// Open unwraps the secrets contained in the inputs.
	Open(secrets, inputs [][]byte) error

	// Marshal returns the binary representation of the Cryptex.
	Marshal() (data []byte, err error)

	// Unmarshal parses the Cryptex encoded in data.
	Unmarshal(data []byte) error
}
