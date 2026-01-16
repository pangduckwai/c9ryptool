package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/hashes"
)

func version() string {
	return "v1.3.0 2026011611"
}

func desc() string {
	return fmt.Sprintf("c9rypTool (version %v)", version())
}

func main() {
	cfg, err := cfgs.Parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, desc(), cfgs.Usage())
	}

	switch cfg.Command() {
	case cfgs.CMD_HELP:
		fmt.Printf("%v\n%v\n", desc(), cfgs.Help())
	case cfgs.CMD_VERSION:
		fmt.Println(desc())

	case cfgs.CMD_ENCRYPT:
		fallthrough
	case cfgs.CMD_DECRYPT:
		err = cfgs.Validate(cfg)
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

		encd := encodes.Get(cfg.Encd)

		switch cfg.Format {
		case cfgs.FORMAT_YAML:
			if encd == nil {
				log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Encd)
			}
			if cfg.Command() == cfgs.CMD_ENCRYPT {
				err = yamlEncrypt(cfg, algr, encd)
			} else {
				err = yamlDecrypt(cfg, algr, encd)
			}
		case cfgs.FORMAT_JSON:
			// TODO HERE!!! add json value encryption!
		default:
			if cfg.Command() == cfgs.CMD_ENCRYPT {
				err = encrypt(cfg, algr, encd)
			} else {
				err = decrypt(cfg, algr, encd)
			}
		}
		if cfg.Verbose {
			fmt.Printf("%v finished '%v' using '%v'\n", desc(), cfgs.COMMANDS[cfg.Command()], algr.Name())
		}

	case cfgs.CMD_ENCODE:
		fallthrough
	case cfgs.CMD_DECODE:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(desc())
			for i, n := range encodes.List() {
				fmt.Printf(" %2v - %v\n", i+1, n)
			}
			return
		}

		encd := encodes.Get(encodes.Parse(cfg.Encd))
		if encd == nil {
			log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Encd)
		}
		if cfg.Command() == cfgs.CMD_ENCODE {
			err = encode(cfg, encd)
		} else {
			err = decode(cfg, encd)
		}
		if cfg.Verbose {
			fmt.Printf("%v finished '%v' using '%v'\n", desc(), cfgs.COMMANDS[cfg.Command()], encd.Name())
		}

	case cfgs.CMD_DISPLAY:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		var encd encodes.Encoding
		if cfg.Encd != "" {
			encd = encodes.Get(cfg.Encd)
			if encd == nil {
				log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Encd)
			}
		}
		err = display(cfg, encd)

	case cfgs.CMD_HASHING:
		err = cfgs.Validate(cfg)
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

	default:
		err = fmt.Errorf(" unsupported command '%v'", cfg.Command())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
