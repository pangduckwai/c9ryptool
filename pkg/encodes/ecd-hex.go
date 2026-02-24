package encodes

import (
	"encoding/hex"
	"io"
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

func (n Hex) EncodeToString(inp []byte) string {
	return hex.EncodeToString(inp)
}

func (n Hex) Encode(in io.Reader, out io.Writer) error {
	return encode(n, in, out)
}

func (n Hex) DecodeString(inp string) (out []byte, err error) {
	out, err = hex.DecodeString(inp)
	return
}

func (n Hex) Decode(in io.Reader, out io.Writer) error {
	return decode(n, in, out)
}
