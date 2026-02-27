package encodes

import (
	"bufio"
	"compress/flate"
	"fmt"
	"io"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func compressFlate(in io.Reader, out io.Writer) error {
	rdr, ok := in.(*bufio.Reader)
	if !ok {
		rdr = bufio.NewReaderSize(in, cfgs.BUFFER)
	}

	wtr, err := flate.NewWriter(out, 9)
	if err != nil {
		return err
	}
	defer wtr.Close()

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

func decompressFlate(in io.Reader, out io.Writer) error {
	rbf, ok := in.(*bufio.Reader)
	if !ok {
		rbf = bufio.NewReaderSize(in, cfgs.BUFFER)
	}
	rz := flate.NewReader(in)
	defer rz.Close()
	rdr := bufio.NewReaderSize(rz, rbf.Size())

	wtr, ok := out.(*bufio.Writer)
	if !ok {
		wtr = bufio.NewWriter(out)
	}

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

// //// //
// Flate
type Flate int

func (n Flate) Name() string {
	return "flate"
}

func (n Flate) Type() int {
	if n == 0 {
		panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
	}
	return int(n)
}

func (n Flate) Padding(inp []byte) []byte {
	return inp
}

func (n Flate) Multiple() (int, int) {
	return 1, 1
}

func (n Flate) EncodeToString(inp []byte) string {
	panic("'EncodeToString' not supported for 'flate'")
}

// Encode read input from 'in' and write flate compressed result to 'out'
func (n Flate) Encode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressFlate(in, out)
	} else if n < 0 {
		return decompressFlate(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}

func (n Flate) DecodeString(inp string) (out []byte, err error) {
	panic("'DecodeString' not supported for 'flate'")
}

// Decode read input from 'in' and write flate decompressed result to 'out'
func (n Flate) Decode(in io.Reader, out io.Writer) error {
	if n > 0 {
		return compressFlate(in, out)
	} else if n < 0 {
		return decompressFlate(in, out)
	}
	panic(fmt.Sprintf("'%v' has invalid value %v", n.Name(), n))
}
