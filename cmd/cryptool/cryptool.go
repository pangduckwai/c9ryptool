package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/algorithm/sym"
	"sea9.org/go/cryptool/pkg/config"
	"sea9.org/go/cryptool/pkg/crypt"
)

func run(cfg *config.Config) (err error) {
	err = config.Validate(cfg)
	if err != nil {
		return
	}

	algr := algorithm.Get(algorithm.Parse(cfg.Algr))
	if algr == nil {
		err = fmt.Errorf(" unsupported algorithm '%v'", cfg.Algr)
		return
	}

	if cfg.Passwd {
		_, err = sym.PopulateKeyFromPassword(
			config.Desc(), "TEMP!!!!!!!!!!!!!", // TODO HERE!!!!!!!!!!!!!
			algr.KeyLength(), cfg.SaltLen,
			algr.PopulateKey,
		)
		if err != nil {
			return
		}
	} else if cfg.Genkey {
		err = algr.PopulateKey(0, cfg.Key)
		if err != nil {
			return
		}
	} else {
		err = algr.PopulateKey(1, cfg.Key)
		if err != nil {
			return
		}
	}

	switch cfg.Command {
	case 0:
		err = crypt.Encrypt(cfg, algr)
	case 1:
		err = crypt.Decrypt(cfg, algr)
	}

	if cfg.Verbose {
		fmt.Printf("%v finished using '%v'\n", config.Desc(), algr.Name())
	}
	return
}

func main() {
	cfg, err := config.Parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, config.Desc(), config.Usage())
	}

	switch cfg.Command {
	case 0:
		fallthrough
	case 1:
		err = run(cfg)
	case 2:
		fmt.Printf("%v\n%v\n", config.Desc(), config.Help())
	case 3:
		fmt.Println(config.Desc())
	case 4:
		fmt.Println(config.Desc())
		for i, n := range algorithm.List() {
			a := algorithm.Get(n)
			if a.Type() {
				fmt.Printf(" %2v sym  %v\n", i+1, n)
			} else {
				fmt.Printf(" %2v asym %v\n", i+1, n)
			}
		}
	default:
		err = fmt.Errorf(" unknown command '%v'", cfg.Command)
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
