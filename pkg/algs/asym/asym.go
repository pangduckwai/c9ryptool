package asym

import (
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
