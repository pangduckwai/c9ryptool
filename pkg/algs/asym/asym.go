package asym

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
)

func parseKey(k []byte) (
	key any,
	typ bool, // false - private key; true - public key
	err error,
) {
	errs := make([]error, 0)
	pem, _ := pem.Decode(k)
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

func getRsaKey(k []byte, lgth int) (
	key *rsa.PrivateKey,
	pkey *rsa.PublicKey,
	err error,
) {
	if k == nil {
		key, err = rsa.GenerateKey(rand.Reader, lgth)
		if err != nil {
			return
		}
		pkey = &key.PublicKey
	} else {
		var ok, typ bool
		var b any
		b, typ, err = parseKey(k)
		if err != nil {
			return
		}
		if !typ {
			if key, ok = b.(*rsa.PrivateKey); ok {
				pkey = &key.PublicKey
			} else {
				err = fmt.Errorf("[RSA] casting to *rsa.PrivateKey failed")
			}
		} else {
			if pkey, ok = b.(*rsa.PublicKey); !ok {
				err = fmt.Errorf("[RSA] casting to *rsa.PublicKey failed")
			}
		}
	}
	return
}
