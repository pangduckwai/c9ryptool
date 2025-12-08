package encodes

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strings"

	"sea9.org/go/cryptool/pkg/utils"
)

// /// //
// hex
type Hex int

func (n Hex) Name() string {
	return "hex encoding"
}

func (n Hex) EncodeImpl(inp []byte) string {
	return hex.EncodeToString(inp)
}

func (n Hex) Encode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	isStdout := wtr == nil
	var buf strings.Builder

	err = utils.BufferedRead(rdr, size, func(cnt int, inp []byte) {
		encoded := n.EncodeImpl(inp[:cnt])
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

func (n Hex) DecodeImpl(inp string) (out []byte, err error) {
	out, err = hex.DecodeString(inp)
	return
}

func (n Hex) Decode(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	isStdout := wtr == nil
	buf := make([]byte, 0)

	err = utils.BufferedRead(rdr, size, func(cnt int, inp []byte) {
		var decoded []byte
		decoded, err = n.DecodeImpl(string(inp[:cnt]))
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
