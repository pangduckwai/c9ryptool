package main

import (
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/config"
	"sea9.org/go/cryptool/pkg/crypto"
)

func main() {
	cfg, err := config.Parse(os.Args)
	if err != nil {
		log.Fatalf("%v\n%v\n%v\n", err, config.Desc(), config.Usage())
	}

	switch cfg.Command {
	case 0:
		err = config.Validate(cfg)
		if err != nil {
			log.Fatal(err)
		}
		err = crypto.Encrypt(cfg)
	case 1:
		err = config.Validate(cfg)
		if err != nil {
			log.Fatal(err)
		}
		err = crypto.Decrypt(cfg)
	case 2:
		fmt.Printf("%v\n%v\n", config.Desc(), config.Help())
	case 3:
		fmt.Println(config.Desc())
	}

	if err != nil {
		log.Fatal(err)
	}
}
