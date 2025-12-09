package main

import (
	"bufio"
	"fmt"
	"os"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
)

func encode(
	cfg *cfgs.Config,
	ecd encodes.Encoding,
) (err error) {
	inp := os.Stdin
	if cfg.Input != "" {
		inp, err = os.Open(cfg.Input)
		if err != nil {
			err = fmt.Errorf("[READ] %v", err)
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

	var out *os.File
	var wtr *bufio.Writer
	if cfg.Output != "" {
		out, err = os.Create(cfg.Output)
		if err != nil {
			err = fmt.Errorf("[WRITE] %v", err)
			return
		}
		wtr = bufio.NewWriter(out)
		defer out.Close()
	}

	err = encodes.Encode(ecd, rdr, wtr)
	if err != nil {
		err = fmt.Errorf("[ENCODE] %v", err)
	}
	return
}

func decode(
	cfg *cfgs.Config,
	ecd encodes.Encoding,
) (err error) {
	inp := os.Stdin
	if cfg.Input != "" {
		inp, err = os.Open(cfg.Input)
		if err != nil {
			err = fmt.Errorf("[READ] %v", err)
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

	var out *os.File
	var wtr *bufio.Writer
	if cfg.Output != "" {
		out, err = os.Create(cfg.Output)
		if err != nil {
			err = fmt.Errorf("[WRITE] %v", err)
			return
		}
		wtr = bufio.NewWriter(out)
		defer out.Close()
	}

	err = encodes.Decode(ecd, rdr, wtr)
	if err != nil {
		err = fmt.Errorf("[DECODE] %v", err)
	}
	return
}
