package main

import (
	"bufio"
	"fmt"
	"hash"
	"os"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/hashes"
)

func calcHash(
	cfg *cfgs.Config,
	hsh hash.Hash,
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

	err = hashes.Hash(hsh, rdr, wtr)
	if err != nil {
		err = fmt.Errorf("[HASH] %v", err)
	}
	return
}
