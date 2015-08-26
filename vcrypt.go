package vcrypt

import "github.com/benburkert/vcrypt/seal"

//go:generate -command protoc protoc --proto_path=$GOPATH/src:$GOPATH/src/github.com/gogo/protobuf/protobuf:. --gogo_out=.
//go:generate protoc cryptex/cryptex.proto cryptex/sss.proto cryptex/xor.proto cryptex/secretbox.proto cryptex/box.proto cryptex/rsa.proto cryptex/openpgp.proto cryptex/mux.proto cryptex/demux.proto
//go:generate protoc material/material.proto
//go:generate protoc seal/seal.proto seal/openpgp.proto
//go:generate protoc secret/secret.proto secret/password.proto secret/openpgpkey.proto
//go:generate protoc marker.proto node.proto

// Sealer is an interface for the Seal method.
type Sealer interface {
	// Seal constructs a new seal for the data.
	Seal([]byte) (seal.Seal, error)
}
