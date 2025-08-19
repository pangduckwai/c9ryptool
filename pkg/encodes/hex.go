package encodes

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strings"

	"sea9.org/go/cryptool/pkg/cryptool"
)

// /// //
// hex
type Hex int

func (n Hex) Name() string {
	return "hex encoding"
}

func (n Hex) Encode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	isStdout := wtr == nil
	var buf strings.Builder

	err = cryptool.BufferedRead(rdr, size, func(cnt int, inp []byte) {
		encoded := hex.EncodeToString(inp[:cnt])
		if !isStdout {
			fmt.Fprint(wtr, encoded)
		} else {
			buf.WriteString(encoded)
		}
	})
	if err != nil {
		return
	}

	if !isStdout {
		wtr.Flush()
	} else {
		fmt.Print(buf.String())
	}
	return
}

func (n Hex) Decode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	isStdout := wtr == nil
	buf := make([]byte, 0)

	err = cryptool.BufferedRead(rdr, size, func(cnt int, inp []byte) {
		var decoded []byte
		decoded, err = hex.DecodeString(string(inp[:cnt]))
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
	})
	if err != nil {
		return
	}

	if !isStdout {
		wtr.Flush()
	} else {
		fmt.Printf("%s\n", buf) // Show string (%s) or hex encoding (%x) ?
	}
	return
}
