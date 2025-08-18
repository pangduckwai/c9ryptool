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
	var buf strings.Builder

	encode := func(inp []byte, flush bool) {
		encoded := base64.StdEncoding.EncodeToString(inp)
		if wtr != nil {
			fmt.Fprint(wtr, encoded)
			if flush {
				wtr.Flush()
			}
		} else {
			buf.WriteString(encoded)
			if flush {
				fmt.Print(buf.String())
			}
		}
	}

	err = cryptool.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 3 // num of characters to encode each time is multiple of 3
		encode(dat[:lgh], false)

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

	if lgh > 0 {
		encode(dat, true)
	}
	return
}

func (n Base64) Decode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	buf := make([]byte, 0)

	decode := func(inp []byte, flush bool) error {
		decoded, err := base64.StdEncoding.DecodeString(string(inp))
		if err != nil {
			return err
		}
		if wtr != nil {
			_, err = wtr.Write(decoded)
			if err != nil {
				return err
			}
			if flush {
				wtr.Flush()
			}
		} else {
			buf = append(buf, decoded...)
			if flush {
				fmt.Printf("%s", buf) // Show string (%s) or hex encoding (%x) ?
			}
		}
		return nil
	}

	err = cryptool.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		lgh += cnt
		dat = append(dat, buf...)

		lgh -= lgh % 4 // num of characters to decode each time is multiple of 4
		err = decode(dat[:lgh], false)

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

	if lgh > 0 {
		err = decode(dat, true)
	}
	return
}
