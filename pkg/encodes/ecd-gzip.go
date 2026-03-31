package encodes

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/pangduckwai/sea9go/pkg/inout"
	"sea9.org/go/c9ryptool/pkg/cfgs"
)

func compressGzip(in io.Reader, out io.Writer) error {
	rdr, ok := in.(*bufio.Reader)
	if !ok {
		rdr = bufio.NewReaderSize(in, cfgs.BUFFER)
	}

	wtr := gzip.NewWriter(out)
	defer wtr.Close()

	err := inout.BufferedRead(
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

func decompressGzip(in io.Reader, out io.Writer) error {
	rbf, ok := in.(*bufio.Reader)
	if !ok {
		rbf = bufio.NewReaderSize(in, cfgs.BUFFER)
	}
	rz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	defer rz.Close()
	rdr := bufio.NewReaderSize(rz, rbf.Size())

	wtr, ok := out.(*bufio.Writer)
	if !ok {
		wtr = bufio.NewWriter(out)
	}

	err = inout.BufferedRead(
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
// Gzip
type Gzip int

func (n Gzip) Name() string {
	return "gzip"
}

func (n Gzip) Type() int {
	if n == 0 {
		panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
	}
	return int(n)
}

func (n Gzip) Padding(inp []byte) []byte {
	return inp
}

func (n Gzip) Multiple() (int, int) {
	return 1, 1
}

func (n Gzip) EncodeToString(inp []byte) string {
	panic("'EncodeToString' not supported for 'gzip'")
}

// Encode read input from 'in' and write gzipped result to 'out'
func (n Gzip) Encode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressGzip(in, out)
	} else if n < 0 {
		return decompressGzip(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}

func (n Gzip) DecodeString(inp string) (out []byte, err error) {
	panic("'DecodeString' not supported for 'gzip'")
}

// Decode read input from 'in' and write ungzipped result to 'out'
func (n Gzip) Decode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressGzip(in, out)
	} else if n < 0 {
		return decompressGzip(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}
