package cryptool

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func BufferedRead(
	rdr *bufio.Reader,
	size int,
	isStd bool,
	action func([]byte),
) (
	err error,
) {
	buf := make([]byte, 0, size)
	cnt := 0
	// var err0 error

	for err == nil {
		// As described in the doc, handle read data first if n > 0 before handling error,
		// it is because the returned error could have been EOF
		cnt, err = rdr.Read(buf[:cap(buf)])

		// If getting input from stdin interactively, pressing <enter> would signify the end of an input line.
		// An entire line with a signle period ('.') means the end of input.
		if cnt > 0 && isStd && buf[:cnt][0] == 46 { // ASCII code 46 is period ('.')
			cnt = 0
			err = io.EOF
		}

		if cnt > 0 {
			action(buf[:cnt])
		}
	}

	if err == io.EOF {
		err = nil
	}
	return
}

func Read(
	path string,
	buffer int,
	decode, verbose bool,
) (
	dat []byte,
	err error,
) {
	inp := os.Stdin
	if path != "" {
		inp, err = os.Open(path)
		if err != nil {
			err = fmt.Errorf("[READ] %v", err)
			return
		}
		defer inp.Close()
	}

	rdr := bufio.NewReaderSize(inp, buffer)
	if rdr.Size() != buffer {
		if verbose {
			fmt.Printf("Read buffer size %v mismatching with the specified size %v, changing buffer size...\n", rdr.Size(), buffer)
		}
		buffer = rdr.Size()
		rdr = bufio.NewReaderSize(inp, buffer)
	}

	dat = make([]byte, 0, buffer*2)
	err = BufferedRead(rdr, buffer, path == "", func(buf []byte) {
		if decode {
			decoded, errr := base64.StdEncoding.DecodeString(string(buf))
			if errr != nil {
				err = fmt.Errorf("[READ] %v", errr)
				panic(err)
			}
			dat = append(dat, decoded...)
		} else {
			dat = append(dat, buf...)
		}
	})
	return
}

func Write(
	path string,
	encode bool,
	dat []byte,
) (err error) {
	var out *os.File
	var wtr *bufio.Writer
	if path != "" {
		out, err = os.Create(path)
		if err != nil {
			err = fmt.Errorf("[WRITE] %v", err)
			return
		}
		wtr = bufio.NewWriter(out)
		defer out.Close()
	}

	if wtr == nil {
		if encode {
			fmt.Println(base64.StdEncoding.EncodeToString(dat))
		} else {
			fmt.Printf("%s", dat)
		}
	} else {
		if encode {
			fmt.Fprint(wtr, base64.StdEncoding.EncodeToString(dat))
		} else {
			fmt.Fprintf(wtr, "%s", dat)
		}
		wtr.Flush()
	}
	return
}
