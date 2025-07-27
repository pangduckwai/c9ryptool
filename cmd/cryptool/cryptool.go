package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/config"
	"sea9.org/go/cryptool/pkg/crypto"
)

func main() {
	cfg, err := config.Parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, config.Desc(), config.Usage())
	}

	err = config.Validate(cfg)
	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}

	var keyLen, ivLen int
	keyLen, ivLen, err = config.Algorithm(cfg.Algr)
	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}

	var key []byte
	if cfg.Passwd {
		rdr := bufio.NewReader(os.Stdin)
		fmt.Printf("%v:\n", config.Desc())
		fmt.Print("Enter password: ")
		str, err := rdr.ReadString('\n')
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}
		key, err = crypto.FromPassword([]byte(str[:len(str)-1]), keyLen, crypto.SALTLEN)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}
	} else if cfg.Genkey {
		key, err = crypto.GenerateKey(cfg.Key, keyLen)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}
	} else {
		var kecd []byte
		kecd, err = os.ReadFile(cfg.Key)
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}
		key, err = base64.StdEncoding.DecodeString(string(kecd))
		if err != nil {
			log.Fatalf("[MAIN]%v", err)
		}
	}

	switch cfg.Command {
	case 0:
		err = crypto.Encrypt(cfg, key, ivLen)
	case 1:
		err = crypto.Decrypt(cfg, key, ivLen)
	case 2:
		fmt.Printf("%v\n%v\n", config.Desc(), config.Help())
	case 3:
		fmt.Println(config.Desc())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
