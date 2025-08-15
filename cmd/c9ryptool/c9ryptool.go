package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/cryptool"
	"sea9.org/go/cryptool/pkg/encrypt"
)

func listCy() {
	fmt.Println(cfgs.Desc())
	for i, n := range encrypt.List() {
		a := encrypt.Get(n)
		if a.Type() {
			fmt.Printf(" %2v sym  %v\n", i+1, n)
		} else {
			fmt.Printf(" %2v asym %v\n", i+1, n)
		}
	}
}

func listCd() {
	fmt.Println(cfgs.Desc())
	fmt.Println("TEMP!!! HAHAHA list encoding schemes!")
}

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
			listCy()
			return
		}

		algr := encrypt.Get(encrypt.Parse(cfg.Algr))
		if algr == nil {
			log.Fatalf("[MAIN] unsupported algorithm '%v'", cfg.Algr)
		}

		if cfg.Command() == 0 {
			err = cryptool.Encrypt(cfg, algr)
		} else {
			err = cryptool.Decrypt(cfg, algr)
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
			listCd()
			return
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
