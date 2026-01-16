package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

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
		if (cnt == 2 && buf[:cnt][1] == 10) || (cnt == 3 && buf[:cnt][1] == 13 && buf[:cnt][2] == 10) {
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
	verbose bool,
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
	err = BufferedRead(rdr, buffer, func(cnt int, buf []byte) error {
		dat = append(dat, buf...)
		return nil
	})
	return
}

func Write(
	path string,
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
		fmt.Printf("%s", dat)
	} else {
		fmt.Fprintf(wtr, "%s", dat)
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

	switch []byte(str)[len(str)-1] {
	case 10:
		fallthrough
	case 13:
		str = str[:len(str)-1]
	}
	return
}
