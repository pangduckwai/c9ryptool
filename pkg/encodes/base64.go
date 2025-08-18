package encodes

import (
	"bufio"
	"encoding/base64"
	"fmt"

	"sea9.org/go/cryptool/pkg/cryptool"
)

// ////// //
// Base64
type Base64 struct {
	N string
}

func (n *Base64) Name() string {
	return n.N
}

func (n *Base64) Encode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)

	encode := func(inp []byte, flush bool) {
		encoded := base64.StdEncoding.EncodeToString(inp)
		if wtr != nil {
			fmt.Fprint(wtr, encoded)
			if flush {
				wtr.Flush()
			}
		} else {
			fmt.Print(encoded)
		}
	}

	err = cryptool.BufferedRead(rdr, size, false, func(cnt int, buf []byte) {
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

func (n *Base64) Decode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)

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
			fmt.Printf("%s", decoded) // Show string (%s) or hex encoding (%x) ?
		}
		return nil
	}

	err = cryptool.BufferedRead(rdr, size, false, func(cnt int, buf []byte) {
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
