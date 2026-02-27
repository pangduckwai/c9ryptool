package encodes

import (
	"encoding/base64"
	"fmt"
	"io"
)

func padding(inp []byte) (out []byte, err error) {
	ln := len(inp)
	out = make([]byte, 0)
	switch ln % 4 {
	case 2:
		out = append(inp, '=', '=')
	case 3:
		out = append(inp, '=')
	case 1:
		err = fmt.Errorf("invalid input \"%s\", %v %% 4 = 1", inp, len(inp))
		return
	default:
		out = inp
	}
	return
}

// ////// //
// Base64
type Base64 int

func (n Base64) Name() string {
	return "base64"
}

func (n Base64) Type() int {
	return 0
}

func (n Base64) Padding(inp []byte) []byte {
	out, err := padding(inp)
	if err != nil {
		panic(err)
	}
	return out
}

func (n Base64) Multiple() (int, int) {
	return 3, 4
}

func (n Base64) EncodeToString(inp []byte) string {
	return base64.StdEncoding.EncodeToString(inp)
}

func (n Base64) Encode(in io.Reader, out io.Writer) error {
	return encode(n, in, out)
}

func (n Base64) DecodeString(inp string) (out []byte, err error) {
	out, err = base64.StdEncoding.DecodeString(inp)
	return
}

func (n Base64) Decode(in io.Reader, out io.Writer) error {
	return decode(n, in, out)
}

// ///////// //
// Base64Url
type Base64Url int

func (n Base64Url) Name() string {
	return "base64url"
}

func (n Base64Url) Type() int {
	return 0
}

func (n Base64Url) Padding(inp []byte) []byte {
	out, err := padding(inp)
	if err != nil {
		panic(err)
	}
	return out
}

func (n Base64Url) Multiple() (int, int) {
	return 3, 4
}

func (n Base64Url) EncodeToString(inp []byte) string {
	return base64.URLEncoding.EncodeToString(inp)
}

func (n Base64Url) Encode(in io.Reader, out io.Writer) error {
	return encode(n, in, out)
}

func (n Base64Url) DecodeString(inp string) (out []byte, err error) {
	out, err = base64.URLEncoding.DecodeString(inp)
	return
}

func (n Base64Url) Decode(in io.Reader, out io.Writer) error {
	return decode(n, in, out)
}

// //////////// //
// RawBase64Url
type RawBase64Url int

func (n RawBase64Url) Name() string {
	return "raw-base64url"
}

func (n RawBase64Url) Type() int {
	return 0
}

func (n RawBase64Url) Padding(inp []byte) []byte {
	return inp
}

func (n RawBase64Url) Multiple() (int, int) {
	return 3, 4
}

func (n RawBase64Url) EncodeToString(inp []byte) string {
	return base64.RawURLEncoding.EncodeToString(inp)
}

func (n RawBase64Url) Encode(in io.Reader, out io.Writer) error {
	return encode(n, in, out)
}

func (n RawBase64Url) DecodeString(inp string) (out []byte, err error) {
	out, err = base64.RawURLEncoding.DecodeString(inp)
	return
}

func (n RawBase64Url) Decode(in io.Reader, out io.Writer) error {
	return decode(n, in, out)
}
