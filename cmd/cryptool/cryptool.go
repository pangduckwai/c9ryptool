package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"sea9.org/go/cryptool/pkg/algorithm"
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

	var key []byte
	var str string
	if cfg.Passwd {
		rdr := bufio.NewReader(os.Stdin)
		fmt.Printf("%v:\n", config.Desc())
		fmt.Print("Enter password: ")
		str, err = rdr.ReadString('\n')
		if err != nil {
			return
		}
		key, err = algorithm.FromPassword([]byte(str[:len(str)-1]), algr.KeyLength(), algorithm.SALTLEN, cfg.Salt, cfg.SaltFile)
		if err != nil {
			return
		}
	} else if cfg.Genkey {
		key, err = algorithm.GenerateKey(cfg.Key, algr.KeyLength())
		if err != nil {
			return
		}
	} else {
		var kecd []byte
		kecd, err = os.ReadFile(cfg.Key)
		if err != nil {
			return
		}
		key, err = base64.StdEncoding.DecodeString(string(kecd))
		if err != nil {
			return
		}
	}

	switch cfg.Command {
	case 0:
		err = crypt.Encrypt(cfg, algr, key)
	case 1:
		err = crypt.Decrypt(cfg, algr, key)
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
	default:
		err = fmt.Errorf(" unknown command '%v'", cfg.Command)
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
