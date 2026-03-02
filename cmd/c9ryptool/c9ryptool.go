package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/hashes"
)

const LOG_FRM_MILLI = "2006-01-02T15:04:05.000"

func desc() string {
	return fmt.Sprintf("c9rypTool (version %v)", cfgs.Version())
}

func main() {
	cfg, err := parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, desc(), usage())
	}

	switch cfg.Cmd() {
	case CMD_HELP:
		fmt.Printf("%v\n%v\n", desc(), help())
	case CMD_VERSION:
		fmt.Println(desc())

	case CMD_ENCRYPT:
		fallthrough
	case CMD_DECRYPT:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(desc())
			for i, n := range encrypts.List(0) {
				a := encrypts.Get(n)
				if a.Type() {
					fmt.Printf(" %2v sym  %v\n", i+1, n)
				} else {
					fmt.Printf(" %2v asym %v\n", i+1, n)
				}
			}
			return
		}

		algr := encrypts.Get(encrypts.Parse(cfg.Algr))
		if algr == nil {
			log.Fatalf("[MAIN] unsupported algorithm '%v'", cfg.Algr)
		}

		enci := encodes.Get(encodes.Parse(cfg.Encd))
		encv := encodes.Get(encodes.Parse(cfg.Encv))
		enct := encodes.Get(encodes.Parse(cfg.Enct))
		enca := encodes.Get(encodes.Parse(cfg.Enca))
		enco := encodes.Get(encodes.Parse(cfg.Enco))
		enck := encodes.Get(encodes.Parse(cfg.Enck))
		zip := encodes.Get(encodes.Parse(cfg.Zip))

		switch cfg.Format {
		case FORMAT_YAML:
			if cfg.Cmd() == CMD_ENCRYPT {
				if enco == nil {
					log.Fatalf("[MAIN] unsupported output encoding '%v'", cfg.Enco)
				}
				err = yamlEncrypt(cfg, algr, enco, enck, encv, enca)
			} else {
				if enci == nil {
					log.Fatalf("[MAIN] unsupported input encoding '%v'", cfg.Encd)
				}
				err = yamlDecrypt(cfg, algr, enci, enck, encv, enct, enca)
			}
		case FORMAT_JSON:
			// TODO HERE!!! add json value encryption!
		default:
			if cfg.Cmd() == CMD_ENCRYPT {
				err = encrypt(cfg, algr, enci, enco, enck, encv, enca, zip)
			} else {
				err = decrypt(cfg, algr, enci, enco, enck, encv, enct, enca, zip)
			}
		}
		if cfg.Verbose {
			fmt.Printf("\n%v [%v] finished:\n%v\n", time.Now().Format(LOG_FRM_MILLI), desc(), cfg)
		}

	case CMD_ARCHIVE:
		if cfg.IsList() {
			i := 1
			fmt.Println(desc())
			for _, n := range encodes.List() {
				c := encodes.Get(n)
				t := c.Type()
				if t == 0 {
					continue
				} else if t > 0 {
					fmt.Printf(" %2v compress   %v\n", i, n)
				} else {
					fmt.Printf(" %2v decompress %v\n", i, n)
				}
				i++
			}
			return
		}
		fallthrough
	case CMD_ENCODE:
		fallthrough
	case CMD_DECODE:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			i := 1
			fmt.Println(desc())
			for _, n := range encodes.List() {
				c := encodes.Get(n)
				t := c.Type()
				if t == 0 {
					fmt.Printf(" %2v %v\n", i, n)
					i++
				} else {
					continue
				}
			}
			return
		}

		encd := encodes.Get(encodes.Parse(cfg.Encd))
		if encd == nil {
			log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Encd)
		}
		switch cfg.Cmd() {
		case CMD_ARCHIVE: // don't care encode or decode for archiving
			fallthrough
		case CMD_ENCODE:
			err = encode(cfg, encd)
		case CMD_DECODE:
			err = decode(cfg, encd)
		}
		if cfg.Verbose {
			fmt.Printf("\n%v [%v] finished:\n%v\n", time.Now().Format(LOG_FRM_MILLI), desc(), cfg)
		}

	case CMD_DISPLAY:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		var encd encodes.Encoding
		if cfg.Encd != "" {
			encd = encodes.Get(encodes.Parse(cfg.Encd))
			if encd == nil {
				log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Encd)
			}
		}
		err = display(cfg, encd)

	case CMD_HASHING:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(desc())
			for i, n := range hashes.List() {
				fmt.Printf(" %2v %v\n", i+1, n)
			}
			return
		}

		hshs := hashes.Get(hashes.Parse(cfg.Hash))
		if hshs == nil {
			log.Fatalf("[MAIN] unsupported algorithm '%v'", cfg.Hash)
		}
		err = calcHash(cfg, hshs)
		if cfg.Verbose {
			fmt.Printf("\n%v [%v] finished:\n%v\n", time.Now().Format(LOG_FRM_MILLI), desc(), cfg)
		}

	default:
		err = fmt.Errorf(" unsupported command '%v'", cfg.Cmd())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
