package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
)

func desc() string {
	return fmt.Sprintf("c9utils (version %v)", cfgs.Version())
}

func list(typ int) {
	fmt.Println(desc())
	for i, n := range encrypts.List(typ) {
		a := encrypts.Get(n)
		if a.Type() {
			fmt.Printf(" %2v sym  %v\n", i+1, n)
		} else {
			fmt.Printf(" %2v asym %v\n", i+1, n)
		}
	}
}

func main() {
	cfg, err := parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, desc(), usage())
	}

	var typ int
	switch cfg.Command() {
	case CMD_VERSION:
		fmt.Println(desc())

	case CMD_PUBKEY:
		typ = -1
		fallthrough
	case CMD_GENKEY:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			list(typ)
			return
		}

		algr := encrypts.Get(encrypts.Parse(cfg.Algr))
		encd := encodes.Get(cfg.Encd)
		if cfg.Command() == CMD_GENKEY {
			err = genkey(cfg, algr, encd)
			if err == nil {
				if cfg.Verbose {
					ecd := ""
					if encd != nil {
						ecd = fmt.Sprintf(" (%v)", encd.Name())
					}
					pub := ""
					if cfg.Key != "" {
						pub = fmt.Sprintf(" and '%v'", cfg.Key)
					}
					fmt.Printf("%v finished generating new key for '%v'%v to '%v'%v\n", desc(), algr.Name(), ecd, cfg.Output, pub)
				} else {
					fmt.Printf("%v finished generating new key for '%v'\n", desc(), algr.Name())
				}
			}
		} else {
			err = pubkey(cfg, algr.(encrypts.AsymAlgorithm))
			if err == nil {
				if cfg.Verbose {
					fmt.Printf("%v finished extracting public key of '%v' from '%v'\n", desc(), algr.Name(), cfg.Input)
				} else {
					fmt.Printf("%v finished extracting public key from '%v'\n", desc(), cfg.Input)
				}
			}
		}

	case CMD_SPLIT:
		err = validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		err = split(cfg)
		if err == nil {
			inp := "stdin"
			if cfg.Input != "" {
				inp = fmt.Sprintf("'%v'", cfg.Input)
			}
			if cfg.Verbose {
				fmt.Printf("%v finished splitting %v into '%v' and '%v' (%v)\n", desc(), inp, cfg.Output, cfg.Key, cfg.SaltLen)
			} else {
				fmt.Printf("%v finished splitting %v (%v)\n", desc(), inp, cfg.SaltLen)
			}
		}

	default:
		err = fmt.Errorf(" unsupported command '%v'", cfg.Command())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
