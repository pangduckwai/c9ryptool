package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/cryptool"
)

func main() {
	cfg, err := cfgs.Parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, cfgs.Desc(), cfgs.Usage())
	}

	switch cfg.Command {
	case 0:
		fallthrough
	case 1:
		err = cfgs.Validate(cfg)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}

		algr := algs.Get(algs.Parse(cfg.Algr))
		if algr == nil {
			log.Fatalf("[MAIN] unsupported algorithm '%v'", cfg.Algr)
		}

		switch cfg.Command {
		case 0:
			err = cryptool.Encrypt(cfg, algr)
		case 1:
			err = cryptool.Decrypt(cfg, algr)
		}

		if cfg.Verbose {
			fmt.Printf("%v finished using '%v'\n", cfgs.Desc(), algr.Name())
		}
	case 7:
		fmt.Println(cfgs.Desc())
		for i, n := range algs.List() {
			a := algs.Get(n)
			if a.Type() {
				fmt.Printf(" %2v sym  %v\n", i+1, n)
			} else {
				fmt.Printf(" %2v asym %v\n", i+1, n)
			}
		}
	case 8:
		fmt.Printf("%v\n%v\n", cfgs.Desc(), cfgs.Help())
	case 9:
		fmt.Println(cfgs.Desc())
	default:
		err = fmt.Errorf(" unknown command '%v'", cfg.Command)
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
