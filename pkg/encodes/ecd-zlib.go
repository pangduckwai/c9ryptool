package encodes

import (
	"bufio"
	"compress/zlib"
	"fmt"
	"io"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func compressZlib(in io.Reader, out io.Writer) error {
	rdr, ok := in.(*bufio.Reader)
	if !ok {
		rdr = bufio.NewReaderSize(in, cfgs.BUFFER)
	}

	wtr := zlib.NewWriter(out)
	defer wtr.Close()

	err := utils.BufferedRead(
		rdr, rdr.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				_, err = wtr.Write(inp[:cnt])
			}
			return
		},
	)
	if err != nil {
		return err
	}
	err = wtr.Flush()
	return err
}

func decompressZlib(in io.Reader, out io.Writer) error {
	rbf, ok := in.(*bufio.Reader)
	if !ok {
		rbf = bufio.NewReaderSize(in, cfgs.BUFFER)
	}
	rz, err := zlib.NewReader(in)
	if err != nil {
		return err
	}
	defer rz.Close()
	rdr := bufio.NewReaderSize(rz, rbf.Size())

	wtr, ok := out.(*bufio.Writer)
	if !ok {
		wtr = bufio.NewWriter(out)
	}

	err = utils.BufferedRead(
		rdr, rdr.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				_, err = wtr.Write(inp[:cnt])
			}
			return
		},
	)
	if err != nil {
		return err
	}
	err = wtr.Flush()
	return err
}

// //// //
// Zlib
type Zlib int

func (n Zlib) Name() string {
	return "zlib"
}

func (n Zlib) Type() int {
	if n == 0 {
		panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
	}
	return int(n)
}

func (n Zlib) Padding(inp []byte) []byte {
	return inp
}

func (n Zlib) Multiple() (int, int) {
	return 1, 1
}

func (n Zlib) EncodeToString(inp []byte) string {
	panic("'EncodeToString' not supported for 'zlib'")
}

// Encode read input from 'in' and write zlib compressed result to 'out'
func (n Zlib) Encode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressZlib(in, out)
	} else if n < 0 {
		return decompressZlib(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}

func (n Zlib) DecodeString(inp string) (out []byte, err error) {
	panic("'DecodeString' not supported for 'zlib'")
}

// Decode read input from 'in' and write zlib decompressed result to 'out'
func (n Zlib) Decode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressZlib(in, out)
	} else if n < 0 {
		return decompressZlib(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}
