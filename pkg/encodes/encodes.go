package encodes

import (
	"bufio"
	"fmt"
	"sort"
	"strings"

	"sea9.org/go/c9ryptool/pkg/utils"
)

// Encoding encoding scheme
type Encoding interface {
	// Name algorithm name.
	Name() string

	// Padding fill the input with the specific padding.
	Padding([]byte) []byte

	// Multiple return the multiple of number of characters processed in each encoding / decoding invocation.
	Multiple() (int, int)

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
func Validate(inp string) (err error) {
	scheme := Parse(inp)
	if scheme == "" {
		err = fmt.Errorf("[ENCD] unsupported encoding scheme '%v'", inp)
	}
	return
}

// Parse return the actual encoding scheme name
func Parse(inp string) (name string) {
	algrs := make([]string, len(eNCODINGS))
	i := 0
	for n := range eNCODINGS {
		algrs[i] = n
		i++
	}

	indices, str, _ := utils.BestMatch(inp, algrs, true)
	if len(indices) == 1 {
		name = str
	}
	return
}

func Encode(n Encoding, rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	var buf strings.Builder
	enc, _ := n.Multiple()

	encode := func(inp []byte, ln int, flush bool) (err error) {
		if ln > 0 {
			encoded := n.Encode(inp)
			if !isStdout {
				_, err = fmt.Fprint(wtr, encoded)
				if err != nil {
					return
				}
			} else {
				buf.WriteString(encoded)
			}
		}
		if flush {
			if !isStdout {
				err = wtr.Flush()
			} else {
				fmt.Print(buf.String())
			}
		}
		return
	}

	err = utils.BufferedRead(rdr, size, func(cnt int, inp []byte) (err error) {
		if enc > 1 {
			lgh += cnt
			dat = append(dat, inp...)

			lgh -= lgh % enc // num of characters to encode each time is multiple of 3
			err = encode(dat[:lgh], lgh, false)

			if len(dat) > lgh {
				dat = dat[lgh:]
				lgh = len(dat)
			} else {
				dat = dat[:0]
				lgh = 0
			}
		} else {
			err = encode(inp[:cnt], cnt, false)
		}

		return err
	})
	if err != nil {
		return
	}

	err = encode(dat, lgh, true)
	return
}

func Decode(n Encoding, rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	buf := make([]byte, 0)
	_, dec := n.Multiple()

	decode := func(inp []byte, ln int, flush bool) (err error) {
		if ln > 0 {
			inp = n.Padding(inp)
			var decoded []byte
			decoded, err = n.Decode(string(inp))
			if err != nil {
				return
			}
			if !isStdout {
				_, err = wtr.Write(decoded)
				if err != nil {
					return
				}
			} else {
				buf = append(buf, decoded...)
			}
		}
		if flush {
			if !isStdout {
				err = wtr.Flush()
			} else {
				fmt.Printf("%s", buf) // Show string (%s) or hex encoding (%x) ?
			}
		}
		return
	}

	err = utils.BufferedRead(rdr, size, func(cnt int, inp []byte) (err error) {
		if dec > 1 {
			lgh += cnt
			dat = append(dat, inp...)

			lgh -= lgh % dec // num of characters to decode each time is multiple of 4
			err = decode(dat[:lgh], lgh, false)

			if len(dat) > lgh {
				dat = dat[lgh:]
				lgh = len(dat)
			} else {
				dat = dat[:0]
				lgh = 0
			}
		} else {
			err = decode(inp[:cnt], cnt, false)
		}

		return err
	})
	if err != nil {
		return
	}

	err = decode(dat, lgh, true)
	return
}
