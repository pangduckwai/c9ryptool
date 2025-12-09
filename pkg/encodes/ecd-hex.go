package encodes

import (
	"encoding/hex"
)

// /// //
// hex
type Hex int

func (n Hex) Name() string {
	return "hex encoding"
}

func (n Hex) Padding() bool {
	return false
}

func (n Hex) Encode(inp []byte) string {
	return hex.EncodeToString(inp)
}

func (n Hex) Decode(inp string) (out []byte, err error) {
	out, err = hex.DecodeString(inp)
	return
}
