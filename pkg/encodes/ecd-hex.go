package encodes

import (
	"encoding/hex"
)

// /// //
// hex
type Hex int

func (n Hex) Name() string {
	return "hex"
}

func (n Hex) Padding(inp []byte) []byte {
	return inp
}

func (n Hex) Multiple() (int, int) {
	return 1, 1
}

func (n Hex) Encode(inp []byte) string {
	return hex.EncodeToString(inp)
}

func (n Hex) Decode(inp string) (out []byte, err error) {
	out, err = hex.DecodeString(inp)
	return
}
