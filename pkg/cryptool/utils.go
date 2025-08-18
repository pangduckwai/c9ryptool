package cryptool

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

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

	cnt, off := 0, 0
	var err1 error
	buf := make([]byte, 0, buffer)
	dat = make([]byte, 0, buffer*2)
	for idx := 0; ; idx++ {
		// As described in the doc, handle read data first if n > 0 before handling error,
		// it is because the returned error could have been EOF
		if err1 == nil { // When loop for the last time, skip read
			cnt, err = rdr.Read(buf[:cap(buf)])
		}

		if cnt > 0 && path == "" {
			// If getting input from stdin interactively, pressing <enter> would signify the end of an input line.
			if buf[:cnt][0] == 46 { // ASCII code 46 is period ('.')
				if cnt == 2 && buf[:cnt][1] == 10 { // ASCII code 10 is line feed LF ('\n')
					cnt = 0
					off = 1
					err = io.EOF
				} else if cnt == 3 && buf[:cnt][1] == 13 && buf[:cnt][2] == 10 { // ASCII code 13 is carriage return CR
					cnt = 0
					off = 2
					err = io.EOF
				}
			}
			if off > len(dat) {
				off = len(dat)
			}
		}

		if err1 != nil {
			if err1 == io.EOF {
				err = nil
				break // Done
			} else {
				dat = nil
				err = fmt.Errorf("[READ] %v", err1)
				return
			}
		}

		if decode {
			decoded, errr := base64.StdEncoding.DecodeString(string(buf[:cnt]))
			if errr != nil {
				err = fmt.Errorf("[READ] %v", errr)
				return
			}
			dat = append(dat[:len(dat)-off], decoded...)
		} else {
			dat = append(dat[:len(dat)-off], buf[:cnt]...)
		}
		err1 = err
	}
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
