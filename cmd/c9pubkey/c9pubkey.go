package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"sea9.org/go/c9ryptool/pkg/encrypts/asym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func usage() string {
	return "Usage:\n c9pubkey\n" +
		"   [-k FILE | --key=FILE]\n" +
		"   {-o FILE | --out=FILE}\n"
}

// parse Parse command line arguments.
func parse(args []string) (
	in, out string,
	err error,
) {
	if len(args) < 3 {
		err = fmt.Errorf("[CONF] %v", usage())
		return
	}

	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "-k":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing key filename argument")
				return
			} else {
				in = args[i]
			}
		case strings.HasPrefix(args[i], "--key="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing key filename")
				return
			} else {
				in = args[i][6:]
			}
		case args[i] == "-o":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing output filename argument")
				return
			} else {
				out = args[i]
			}
		case strings.HasPrefix(args[i], "--out="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				out = args[i][6:]
			}
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}
	return
}

func validate(
	in, out string,
) (err error) {
	if in != "" {
		if _, err = os.Stat(in); errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] input file '%v' does not exist", in)
			return
		} else if err != nil {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		}
	}

	if out != "" {
		if _, err = os.Stat(out); err == nil {
			err = fmt.Errorf("[VLDT] output file '%v' already exists", out)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		} else {
			err = nil
		}
	}

	return
}

func main() {
	in, out, err := parse(os.Args)
	if err != nil {
		log.Fatalf("[PUBKEY]%v", err)
	}
	err = validate(in, out)
	if err != nil {
		log.Fatalf("[PUBKEY]%v", err)
	}

	input, err := utils.Read(in, 1048576, false)
	if err != nil {
		log.Fatalf("[PUBKEY][INP]%v", err)
	}

	val, typ, err := asym.ParseKey(input)
	if err != nil {
		log.Fatalf("[PUBKEY][PARSE]%v", err)
	}
	if typ {
		log.Fatalf("[PUBKEY][PARSE] %v does not contain any private key", in)
	}
	if key, ok := val.(*rsa.PrivateKey); ok {
		pkey := &key.PublicKey
		buf, err := x509.MarshalPKIXPublicKey(pkey)
		if err != nil {
			log.Printf("[PUBKEY][PARSE][RSA] %v\n", err)
			buf = x509.MarshalPKCS1PublicKey(pkey)
		}
		ecd := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: buf,
		})
		err = utils.Write(out, ecd)
		if err != nil {
			log.Fatalf("[PUBKEY][OUT]%v", err)
		}
	} else {
		log.Fatalf("[PUBKEY][PARSE][RSA] casting to *rsa.PrivateKey failed")
	}

	fmt.Printf("[PUBKEY] finished exporting public key from %v\n", in)
}
