package encodes

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"sea9.org/go/cryptool/pkg/utils"
)

// Encoding encoding scheme
type Encoding interface {
	// Name algorithm name.
	Name() string

	// Encode encode the given input and returns the encoded result.
	Encode([]byte) string

	// Decode decode the given input and returns the decoded result.
	Decode(string) ([]byte, error)
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

func Encode(n Encoding, rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	var buf strings.Builder

	encode := func(inp []byte, ln int, flush bool) {
		if ln > 0 {
			encoded := n.Encode(inp)
			if !isStdout {
				fmt.Fprint(wtr, encoded)
			} else {
				buf.WriteString(encoded)
			}
		}
		if flush {
			if !isStdout {
				wtr.Flush()
			} else {
				fmt.Print(buf.String())
			}
		}
	}

	err = utils.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 3 // num of characters to encode each time is multiple of 3
		encode(dat[:lgh], lgh, false)

		if len(dat) > lgh {
			dat = dat[lgh:]
			lgh = len(dat)
		} else {
			dat = dat[:0]
			lgh = 0
		}
	})
	if err != nil {
		return
	}

	encode(dat, lgh, true)
	return
}

func Decode(n Encoding, rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	buf := make([]byte, 0)

	decode := func(inp []byte, ln int, flush bool) error {
		if ln > 0 {
			switch ln % 4 {
			case 2:
				inp = append(inp, '=')
				fallthrough
			case 3:
				inp = append(inp, '=')
			case 1:
				return fmt.Errorf("invalid input \"%s\", %v %% 4 = 1", inp, len(inp))
			}
			decoded, err := n.Decode(string(inp))
			if err != nil {
				return err
			}
			if !isStdout {
				_, err = wtr.Write(decoded)
				if err != nil {
					return err
				}
			} else {
				buf = append(buf, decoded...)
			}
		}
		if flush {
			if !isStdout {
				wtr.Flush()
			} else {
				fmt.Printf("%s\n", buf) // Show string (%s) or hex encoding (%x) ?
			}
		}
		return nil
	}

	err = utils.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 4 // num of characters to decode each time is multiple of 4
		err = decode(dat[:lgh], lgh, false)

		if len(dat) > lgh {
			dat = dat[lgh:]
			lgh = len(dat)
		} else {
			dat = dat[:0]
			lgh = 0
		}
	})
	if err != nil {
		return
	}

	err = decode(dat, lgh, true)
	return
}
