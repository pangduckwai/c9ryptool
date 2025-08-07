package asym

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func readKey(path string) (
	key any,
	typ bool, // false - private key; true - public key
	err error,
) {
	red, err := os.ReadFile(path)
	if err != nil {
		return
	}

	errs := make([]error, 0)
	pem, _ := pem.Decode(red)
	key, err = x509.ParsePKCS8PrivateKey(pem.Bytes)
	if err != nil {
		errs = append(errs, err)
		key, err = x509.ParsePKCS1PrivateKey(pem.Bytes)
		if err != nil {
			errs = append(errs, err)
			key, err = x509.ParseECPrivateKey(pem.Bytes)
			if err != nil {
				errs = append(errs, err)
				typ = true // try read as public key from this point forward
				key, err = x509.ParsePKIXPublicKey(pem.Bytes)
				if err != nil {
					errs = append(errs, err)
					key, err = x509.ParsePKCS1PublicKey(pem.Bytes)
					if err != nil {
						errs = append(errs, err)
					}
				}
			}
		}
	}

	if err != nil {
		var buf strings.Builder
		fmt.Fprintf(&buf, "[\n - %v", errs[0])
		for _, err := range errs[1:] {
			fmt.Fprintf(&buf, "\n - %v", err)
		}
		err = fmt.Errorf("[ASYM]%v\n]", buf.String())
	}

	return
}

func generateRsaKey(lgth int, path string) (
	key *rsa.PrivateKey,
	err error,
) {
	key, err = rsa.GenerateKey(rand.Reader, lgth)
	if err != nil {
		return
	}
	buf, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return
	}
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	})
	kfile, err := os.Create(path)
	if err != nil {
		return
	}
	wtr := bufio.NewWriter(kfile)
	defer kfile.Close()
	wtr.Write(pem)
	wtr.Flush()
	return
}

func readRsaKey(path string) (
	key *rsa.PrivateKey,
	pkey *rsa.PublicKey,
	err error,
) {
	var ok bool
	buf, typ, err := readKey(path)
	if err != nil {
		return
	}
	if !typ {
		if key, ok = buf.(*rsa.PrivateKey); ok {
			pkey = &key.PublicKey
		} else {
			err = fmt.Errorf("[RSA] casting to *rsa.PrivateKey failed")
		}
	} else {
		if pkey, ok = buf.(*rsa.PublicKey); !ok {
			err = fmt.Errorf("[RSA] casting to *rsa.PublicKey failed")
		}
	}
	return
}
