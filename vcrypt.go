package vcrypt

//go:generate -command protoc protoc --proto_path=$GOPATH/src:$GOPATH/src/github.com/gogo/protobuf/protobuf:. --gogo_out=.
//go:generate protoc cryptex/cryptex.proto cryptex/sss.proto cryptex/xor.proto cryptex/secretbox.proto cryptex/box.proto cryptex/rsa.proto cryptex/openpgp.proto cryptex/mux.proto cryptex/demux.proto
//go:generate protoc secret/secret.proto secret/password.proto secret/openpgpkey.proto
