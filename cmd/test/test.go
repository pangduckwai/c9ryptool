package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/config"
)

func read(
	cfg *config.Config,
) (
	dat []byte,
	err error,
) {
	inp := os.Stdin
	if cfg.Input != "" {
		inp, err = os.Open(cfg.Input)
		if err != nil {
			return
		}
		defer inp.Close()
	}

	rdr := bufio.NewReaderSize(inp, cfg.Buffer)
	if rdr.Size() != cfg.Buffer {
		if cfg.Verbose {
			fmt.Printf("Read buffer size %v mismatching with the specified size %v, changing buffer size...\n", rdr.Size(), cfg.Buffer)
		}
		cfg.Buffer = rdr.Size()
		rdr = bufio.NewReaderSize(inp, cfg.Buffer)
	}

	cnt, off := 0, 0
	var err1 error
	buf := make([]byte, 0, cfg.Buffer)
	dat = make([]byte, 0, cfg.Buffer*2)
	for idx := 0; ; idx++ {
		// As described in the doc, handle read data first if n > 0 before handling error,
		// it is because the returned error could have been EOF
		if err1 == nil { // When loop for the last time, skip read
			cnt, err = rdr.Read(buf[:cap(buf)])
		}

		if cnt > 0 && cfg.Input == "" {
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
				err = err1
				return
			}
		}

		dat = append(dat[:len(dat)-off], buf[:cnt]...)
		err1 = err
		fmt.Printf("TEMP!!! cnt:%3v off:%3v '%v'\n", cnt, off, string(buf[:cnt]))
	}
	return
}

func main() {
	// fmt.Println("Test command line input...")
	// rdr := bufio.NewReader(os.Stdin)
	// fmt.Print(" enter input: ")
	// inp, err := rdr.ReadString('\n')
	// if err != nil {
	// 	log.Fatalf("[TEST]%v", err)
	// }
	// fmt.Printf("Your input is '%v' (%v)\n", inp[:len(inp)-1], len(inp))

	fmt.Println("Test read multiple lines...")
	cfg := &config.Config{
		Buffer:  32768,
		Verbose: true,
	}
	buff, err := read(cfg)
	if err != nil {
		log.Fatalf("[TEST]%v", err)
	}
	fmt.Printf("Result:\n'%v'\n", string(buff))
}
