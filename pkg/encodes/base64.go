package encodes

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strings"

	"sea9.org/go/cryptool/pkg/cryptool"
)

// ////// //
// Base64
type Base64 int

func (n Base64) Name() string {
	return "base64 encoding"
}

func (n Base64) Encode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	var buf strings.Builder

	encode := func(inp []byte, left, flush bool) {
		if left {
			encoded := base64.StdEncoding.EncodeToString(inp)
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

	err = cryptool.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 3 // num of characters to encode each time is multiple of 3
		encode(dat[:lgh], true, false)

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

	encode(dat, lgh > 0, true)
	return
}

func (n Base64) Decode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	isStdout := wtr == nil
	buf := make([]byte, 0)

	decode := func(inp []byte, left, flush bool) error {
		if left {
			decoded, err := base64.StdEncoding.DecodeString(string(inp))
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

	err = cryptool.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 4 // num of characters to decode each time is multiple of 4
		err = decode(dat[:lgh], true, false)

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

	err = decode(dat, lgh > 0, true)
	return
}
