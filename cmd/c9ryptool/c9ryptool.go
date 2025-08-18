package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/encodes"
	"sea9.org/go/cryptool/pkg/encrypts"
)

func main() {
	cfg, err := cfgs.Parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, cfgs.Desc(), cfgs.Usage())
	}

	switch cfg.Command() {
	case 0:
		fallthrough
	case 1:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(cfgs.Desc())
			for i, n := range encrypts.List() {
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
		if cfg.Command() == 0 {
			err = encrypt(cfg, algr)
		} else {
			err = decrypt(cfg, algr)
		}
		if cfg.Verbose {
			fmt.Printf("%v finished using '%v'\n", cfgs.Desc(), algr.Name())
		}

	case 2:
		fallthrough
	case 3:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(cfgs.Desc())
			for i, n := range encodes.List() {
				fmt.Printf(" %2v - %v\n", i+1, n)
			}
			return
		}

		encd := encodes.Get(cfg.Algr)
		if encd == nil {
			log.Fatalf("[MAIN] unsupported encoding '%v'", cfg.Algr)
		}
		if cfg.Command() == 2 {
			err = encode(cfg, encd)
		} else {
			err = decode(cfg, encd)
		}
		if cfg.Verbose {
			fmt.Printf("%v finished using '%v'\n", cfgs.Desc(), encd.Name())
		}

	case 5:
		fmt.Printf("%v\n%v\n", cfgs.Desc(), cfgs.Help())
	case 6:
		fmt.Println(cfgs.Desc())
	default:
		err = fmt.Errorf(" unknown command '%v'", cfg.Command())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
