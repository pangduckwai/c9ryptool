package main

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	ecies "github.com/ecies/go/v2"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func usage() {
	log.Printf("Usage: ./cmd/test [1line|mline|crenc|encdec|eckeygen|eckeyread|yaml]\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	switch cmd {
	case "1line":
		fmt.Println("01. Test command line input...")
		rdr := bufio.NewReader(os.Stdin)
		fmt.Print(" enter input: ")
		inp, err := rdr.ReadString('\n')
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] Your input is '%v' (%v)\n", cmd, inp[:len(inp)-1], len(inp))
	case "mline":
		fmt.Println("02. Test read multiple lines...")
		buff, err := utils.Read("", 32768, true)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] Result:\n'%v'\n", cmd, string(buff))
	case "crenc":
		fmt.Println("03. Test encrypt with CR public key...")
		buff, err := utils.Read("test/cr.pem", 32768, false)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] pkey read:\n%s\n", cmd, buff)

		blck, _ := pem.Decode(buff)
		pkey, err := x509.ParsePKIXPublicKey(blck.Bytes)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}

		cipher, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			pkey.(*rsa.PublicKey),
			[]byte("CrUat001Pa55w0rd"),
			nil,
		)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] cipher text:\n%v\n", cmd, base64.StdEncoding.EncodeToString(cipher))
	case "encdec":
		fmt.Println("04. Test encrypt with public key then decrypt with private key...")
		buff, err := utils.Read("test/self.key", 32768, false)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] key read:\n%s\n", cmd, buff)

		block, _ := pem.Decode(buff)
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}

		var key *rsa.PrivateKey
		var pkey *rsa.PublicKey
		var okay bool
		if key, okay = k.(*rsa.PrivateKey); okay {
			pkey = &key.PublicKey
		}

		cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pkey, []byte("This is top secret... really!"), nil)
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] cipher text:\n%v\n", cmd, base64.StdEncoding.EncodeToString(cipher))

		plainx, err := key.Decrypt(rand.Reader, cipher, &rsa.OAEPOptions{Hash: crypto.SHA256})
		if err != nil {
			log.Fatalf("[TEST][%v] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] the secret is:\n%s\n", cmd, plainx)
	case "eckeygen":
		fmt.Println("05. Test output secp256k1 keys")
		key, err := ecies.GenerateKey()
		if err != nil {
			log.Fatalf("[TEST][%v][0] %v", cmd, err)
		}
		prvb, pubb, err := marshal(key)
		if err != nil {
			log.Fatalf("[TEST][%v][1] %v", cmd, err)
		}
		prv := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: prvb,
		})
		pub := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubb,
		})
		fmt.Printf("[TEST][%v] Private key\n%s\n", cmd, prv)
		fmt.Printf("[TEST][%v] Public key\n%s\n", cmd, pub)
	case "eckeyread":
		fmt.Println("06. Test reading secp256k1 keys")
		prvb, err := utils.Read("test/c9.pem", 65535, false)
		if err != nil {
			log.Fatalf("[TEST][%v][0] %v", cmd, err)
		}
		key, err := parse(prvb)
		if err != nil {
			log.Fatalf("[TEST][%v][0] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] Private key\n%v\n", cmd, key)

		pubb, err := utils.Read("test/c9-pub.pem", 65535, false)
		if err != nil {
			log.Fatalf("[TEST][%v][1] %v", cmd, err)
		}
		pkey, err := parsePub(pubb)
		if err != nil {
			log.Fatalf("[TEST][%v][1] %v", cmd, err)
		}
		fmt.Printf("[TEST][%v] Public key\n%v\n", cmd, pkey)

		prvo, _, err := marshal(key)
		if err != nil {
			log.Fatalf("[TEST][%v][2] %v", cmd, err)
		}

		pubo, _, err := marshalPub(pkey)
		if err != nil {
			log.Fatalf("[TEST][%v][3] %v", cmd, err)
		}

		prv := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: prvo,
		})
		pub := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubo,
		})
		fmt.Printf("[TEST][%v] Private key\n%s\n", cmd, prv)
		fmt.Printf("[TEST][%v] Public key\n%s\n", cmd, pub)
	case "yaml":
		err := yamlTest()
		if err != nil {
			log.Fatalf("[TEST][%v][1] %v", cmd, err)
		}
	default:
		usage()
	}
}
