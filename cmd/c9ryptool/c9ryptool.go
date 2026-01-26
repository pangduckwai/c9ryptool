package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/hashes"
)

const LOG_FRM_MILLI = "2006-01-02T15:04:05.000"

func desc() string {
	return fmt.Sprintf("c9rypTool (version %v)", cfgs.Version())
}

func main() {
	cfg, err := parse(os.Args)
	if err != nil {
		log.Fatalf("[MAIN]%v\n%v\n%v\n", err, desc(), usage())
	}

	switch cfg.Command() {
	case CMD_HELP:
		fmt.Printf("%v\n%v\n", desc(), help())
	case CMD_VERSION:
		fmt.Println(desc())

	case CMD_ENCRYPT:
		fallthrough
	case CMD_DECRYPT:
		err = validate(cfg)
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

		enci := encodes.Get(cfg.Encd)
		encv := encodes.Get(cfg.Encv)
		enct := encodes.Get(cfg.Enct)
		enca := encodes.Get(cfg.Enca)
		enco := encodes.Get(cfg.Enco)
		enck := encodes.Get(cfg.Enck)

		switch cfg.Format {
		case FORMAT_YAML:
			if cfg.Command() == CMD_ENCRYPT {
				if enco == nil {
					log.Fatalf("[MAIN] unsupported output encoding '%v'", cfg.Enco)
				}
				err = yamlEncrypt(cfg, algr, enco, enck, encv, enca)
			} else {
				if enci == nil {
					log.Fatalf("[MAIN] unsupported input encoding '%v'", cfg.Encd)
				}
				err = yamlDecrypt(cfg, algr, enci, enck, encv, enct, enca)
			}
		case FORMAT_JSON:
			// TODO HERE!!! add json value encryption!
		default:
			if cfg.Command() == CMD_ENCRYPT {
				err = encrypt(cfg, algr, enci, enco, enck, encv, enca)
			} else {
				err = decrypt(cfg, algr, enci, enco, enck, encv, enct, enca)
			}
		}
		if cfg.Verbose {
			cd, ei, ev, et, ea, eo, ek := COMMANDS[cfg.Command()], "nil", "", "", "", "nil", ""
			if cfg.Format == FORMAT_YAML || cfg.Format == FORMAT_JSON {
				cd = fmt.Sprintf("%v(%v)", cd, cfg.Format)
			}
			if enci != nil {
				ei = enci.Name()
			}
			if enco != nil {
				eo = enco.Name()
			}
			if algr.Type() {
				if encv != nil {
					ev = fmt.Sprintf("/V:%v", encv.Name())
				} else {
					ev = "/V:nil"
				}
				if enct != nil {
					et = fmt.Sprintf("/T:%v", enct.Name())
				} else {
					et = "/T:nil"
				}
				if enca != nil {
					ea = fmt.Sprintf("/A:%v", enca.Name())
				} else {
					ea = "/A:nil"
				}
				if enck != nil {
					ek = fmt.Sprintf("/K:%v", enck.Name())
				} else {
					ek = "/K:nil"
				}
			}
			fmt.Printf("\n%v [%v] finished '%v' using '%v' (I:%v%v%v%v/O:%v%v)\n", time.Now().Format(LOG_FRM_MILLI), desc(), cd, algr.Name(), ei, ev, et, ea, eo, ek)
		}

	case CMD_ENCODE:
		fallthrough
	case CMD_DECODE:
		err = validate(cfg)
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
		if cfg.Command() == CMD_ENCODE {
			err = encode(cfg, encd)
		} else {
			err = decode(cfg, encd)
		}
		if cfg.Verbose {
			fmt.Printf("\n%v [%v] finished '%v' using '%v'\n", time.Now().Format(LOG_FRM_MILLI), desc(), COMMANDS[cfg.Command()], encd.Name())
		}

	case CMD_DISPLAY:
		err = validate(cfg)
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

	case CMD_HASHING:
		err = validate(cfg)
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
		if cfg.Verbose {
			fmt.Printf("\n%v [%v] finished '%v' using '%v'\n", time.Now().Format(LOG_FRM_MILLI), desc(), COMMANDS[cfg.Command()], cfg.Hash)
		}

	default:
		err = fmt.Errorf(" unsupported command '%v'", cfg.Command())
	}

	if err != nil {
		log.Fatalf("[MAIN]%v", err)
	}
}
