package encodes

import (
	"bufio"
	"fmt"
	"sort"
)

// Encoding encoding scheme
type Encoding interface {
	// Name algorithm name.
	Name() string

	EncodeImpl([]byte) string

	// Encode encode the given input and returns the encoded result.
	Encode(*bufio.Reader, *bufio.Writer) error

	DecodeImpl(string) ([]byte, error)

	// Decode decode the given input and returns the decoded result.
	Decode(*bufio.Reader, *bufio.Writer) error
}

var eNCODINGS = map[string]Encoding{
	//"direct": nil,
	"base64":       Base64(0),
	"base64url":    Base64Url(0),
	"rawbase64url": RawBase64Url(0),
	"hex":          Hex(0),
}

func Default() string {
	return "rawbase64url"
}

func List() (list []string) {
	list = make([]string, 0)
	for k := range eNCODINGS {
		list = append(list, k)
	}
	sort.Strings(list)
	return
}

func Get(scheme string) Encoding {
	return eNCODINGS[scheme]
}

// Validate validate the given scheme name.
func Validate(scheme string) (err error) {
	if _, okay := eNCODINGS[scheme]; !okay {
		err = fmt.Errorf("[ENCD] unsupported encoding scheme '%v'", scheme)
	}
	return
}
