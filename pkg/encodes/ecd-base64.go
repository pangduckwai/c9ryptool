package encodes

import (
	"encoding/base64"
)

// ////// //
// Base64
type Base64 int

func (n Base64) Name() string {
	return "base64 encoding"
}

func (n Base64) Padding() bool {
	return true
}

func (n Base64) Encode(inp []byte) string {
	return base64.StdEncoding.EncodeToString(inp)
}

func (n Base64) Decode(inp string) (out []byte, err error) {
	out, err = base64.StdEncoding.DecodeString(inp)
	return
}

// ///////// //
// Base64Url
type Base64Url int

func (n Base64Url) Name() string {
	return "base64 URL encoding"
}

func (n Base64Url) Padding() bool {
	return true
}

func (n Base64Url) Encode(inp []byte) string {
	return base64.URLEncoding.EncodeToString(inp)
}

func (n Base64Url) Decode(inp string) (out []byte, err error) {
	out, err = base64.URLEncoding.DecodeString(inp)
	return
}

// //////////// //
// RawBase64Url
type RawBase64Url int

func (n RawBase64Url) Name() string {
	return "raw base64 URL encoding"
}

func (n RawBase64Url) Padding() bool {
	return false
}

func (n RawBase64Url) Encode(inp []byte) string {
	return base64.RawURLEncoding.EncodeToString(inp)
}

func (n RawBase64Url) Decode(inp string) (out []byte, err error) {
	out, err = base64.RawURLEncoding.DecodeString(inp)
	return
}
