package utils

import (
	"bufio"
	"fmt"
	"os"

	"github.com/pangduckwai/sea9go/pkg/inout"
)

func Read(
	path string,
	buffer int,
	decr ...inout.Decoder,
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
	return inout.Read(inp, buffer, decr...)
}

func Write(
	path string,
	dat []byte,
	encr ...inout.Encoder,
) error {
	var wtr *bufio.Writer = bufio.NewWriter(os.Stdout)
	if path != "" {
		out, err := os.Create(path)
		if err != nil {
			return fmt.Errorf("[WRITE] %v", err)
		}
		wtr = bufio.NewWriter(out)
		defer out.Close()
	}
	return inout.Write(wtr, dat, encr...)
}
