package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
)

type Encoder interface {
	Encode(io.Reader, io.Writer) error
}

type Decoder interface {
	Decode(io.Reader, io.Writer) error
}

func BufferedRead(
	rdr *bufio.Reader,
	size int,
	action func(int, []byte) error,
) (
	err error,
) {
	buf := make([]byte, 0, size)
	cnt := 0

	for err == nil {
		// As described in the doc, handle read data first if n > 0 before handling error,
		// it is because the returned error could have been EOF
		cnt, err = rdr.Read(buf[:cap(buf)])

		// If getting input from stdin interactively, pressing <enter> would signify the end of an input line.
		// An entire line with a signle period ('.') means the end of input.
		if (cnt == 2 && buf[:cnt][1] == 10) || (cnt == 3 && (buf[:cnt][1] == 13 && buf[:cnt][2] == 10 || buf[:cnt][1] == 10 && buf[:cnt][2] == 13)) {
			// ASCII code 10: line feed (LF)
			// ASCII code 13: carriage return (CR)
			// ASCII code 46: period ('.')
			if buf[:cnt][0] == 46 {
				cnt = 0
				err = io.EOF
			}
		}

		if cnt > 0 {
			err = action(cnt, buf[:cnt])
			if err != nil {
				break
			}
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
	dec Decoder,
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

	if dec == nil {
		dat = make([]byte, 0, buffer*2)
		err = BufferedRead(rdr, buffer, func(cnt int, buf []byte) error {
			dat = append(dat, buf...)
			return nil
		})
	} else {
		var buf bytes.Buffer
		wtr := bufio.NewWriter(&buf)
		err = dec.Decode(rdr, wtr)
		if err != nil {
			return
		}
		dat = buf.Bytes()
	}
	return
}

func Write(
	path string,
	dat []byte,
	enc Encoder,
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

	if enc == nil {
		if wtr == nil {
			fmt.Printf("%s", dat)
		} else {
			fmt.Fprintf(wtr, "%s", dat)
			wtr.Flush()
		}
	} else {
		rdr := bytes.NewReader(dat)
		if wtr == nil {
			wtr = bufio.NewWriter(os.Stdout)
		}
		err = enc.Encode(rdr, wtr)
		if err != nil {
			err = fmt.Errorf("[WRITE_ENCODED] %v", err)
			return
		}
		wtr.Flush()
	}
	return
}

// InteractiveSingle get a single line interactive input from the prompt
func InteractiveSingle(header, prompt string) (str string, err error) {
	rdr := bufio.NewReader(os.Stdin)
	fmt.Printf("%v:\n", header)
	fmt.Printf("%v: ", prompt)
	str, err = rdr.ReadString('\n')
	if err != nil {
		if err == io.EOF {
			err = fmt.Errorf("[IACTS] stdin already ended, cannot read input")
		} else {
			err = fmt.Errorf("[IACTS] %v", err)
		}
	}

	buf := []byte(str)
	lgh := len(buf)
	if lgh > 1 && (buf[lgh-2] == 13 && buf[lgh-1] == 10 || buf[lgh-2] == 10 && buf[lgh-1] == 13) {
		str = str[:lgh-2]
	} else if lgh > 0 && buf[lgh-1] == 10 {
		str = str[:lgh-1]
	}

	return
}
