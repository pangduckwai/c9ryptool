package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/encodes"
	"sea9.org/go/cryptool/pkg/encrypts"
)

func version() string {
	return "v0.7.5 2025101413"
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
	case 0:
		fallthrough
	case 1:
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
		if cfg.Command() == 0 {
			err = encrypt(cfg, algr)
		} else {
			err = decrypt(cfg, algr)
		}
		if cfg.Verbose {
			fmt.Printf("%v finished using '%v'\n", desc(), algr.Name())
		}

	case 2:
		fallthrough
	case 3:
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
			fmt.Printf("%v finished using '%v'\n", desc(), encd.Name())
		}

	case 5:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		if cfg.IsList() {
			fmt.Println(desc())
			for i, n := range encrypts.List(-1) {
				fmt.Printf(" %2v - %v\n", i+1, n)
			}
			return
		}

		algr := encrypts.Get(encrypts.Parse(cfg.Algr))
		if algr == nil {
			log.Fatalf("[MAIN] unsupported algorithm '%v'", cfg.Algr)
		}
		err = export(cfg, algr)
		if cfg.Verbose {
			fmt.Printf("%v finished using '%v'\n", desc(), algr.Name())
		}

	case 6:
		fmt.Printf("%v\n%v\n", desc(), cfgs.Help())
	case 7:
		fmt.Println(desc())
	default:
		err = fmt.Errorf(" unknown command '%v'", cfg.Command())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
