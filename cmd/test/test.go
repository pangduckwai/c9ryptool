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

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func usage() {
	log.Printf("Usage: ./cmd/test [1line|mline|crenc|encdec|secp256k1]\n")
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
	case "secp256k1":
		fmt.Println("05. Test encrypt / decrypt using secp256k1")
		key, err := secp256k1.GeneratePrivateKey() // ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
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
	default:
		usage()
	}

	// Gen new key pair
	// key, err := ecies.GenerateKey()
	// if err != nil {
	// 	log.Fatalf("[TEST][KEY][0]%v", err)
	// }
	// byt := key.Bytes()
	// fmt.Printf("[TEST][KEY][0] (%v)\n%s\n", len(byt), byt)
	// der, err := asn1.Marshal(byt)
	// if err != nil {
	// 	log.Fatalf("[TEST][KEY][0]%v", err)
	// }
	// key := ecies.NewPrivateKeyFromBytes(byt)
	// inp := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "PRIVATE KEY",
	// 	Bytes: der,
	// })
	// fmt.Printf("[TEST][KEY][0] (%v)\n%s\n", len(inp), inp)

	// Read Emali key pair
	// inp, err := utils.Read("test/emali.key", 10240, false)
	// if err != nil {
	// 	log.Fatalf("[TEST][KEY][0]%v", err)
	// } else {
	// 	fmt.Printf("[TEST][KEY][0] (%v)\n%s\n", len(inp), inp)
	// }

	// Parse key
	// blk, _ := pem.Decode(inp)
	// fmt.Printf("[TEST][KEY][1] %v\n", blk.Type)
	// fmt.Printf("[TEST][KEY][1] %v\n", blk.Headers)
	// fmt.Printf("[TEST][KEY][1] (%v)\n%v\n", len(blk.Bytes), blk.Bytes)

	// key := ecies.NewPrivateKeyFromBytes(blk.Bytes)

	// pkey := key.PublicKey
	// fmt.Printf("[TEST][KEY][2]\n%v\n%v\n", key, pkey)

	// encrypt := func(plaintext []byte) (ciphertext []byte, err error) {
	// 	ciphertext, err = ecies.Encrypt(pkey, plaintext)
	// 	return
	// }

	// decrypt := func(ciphertext []byte) (plaintext []byte, err error) {
	// 	plaintext, err = ecies.Decrypt(key, ciphertext)
	// 	return
	// }

	// Use new message
	// message := []byte("This is top secret")
	// secret, err := encrypt(message)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// secret := make([]byte, 0)

	// Use existing message)
	// secret, err := utils.Read("test/test5.enc", 10240, false)
	// if err != nil {
	// 	log.Fatalf("[TEST][MSG]%v", err)
	// }
	// fmt.Printf("TEST!!!\n%s\n", secret)

	// fmt.Printf("TEST!!!\n%s\n->\n%s\n", message, secret)

	// Decrypt
	// result, err := decrypt(secret)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("->\n%s\n", result)
}
