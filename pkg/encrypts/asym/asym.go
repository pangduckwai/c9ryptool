package asym

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pangduckwai/sea9go/pkg/errs"
)

// parseKey parse the given input into a key in one of the PEM formats.
// returns:
// - typ: false - private key; true - public key
func parseKey(k []byte) (
	key any,
	typ bool,
	err error,
) {
	err = errs.New(true)
	blk, _ := pem.Decode(k)
	if blk == nil {
		err = fmt.Errorf("[RSA] non-PEM input not supported")
		return
	}
	key, er := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if er != nil {
		err = errs.Append(err, er)
		key, er = x509.ParsePKCS1PrivateKey(blk.Bytes)
		if er != nil {
			err = errs.Append(err, er)
			key, er = x509.ParseECPrivateKey(blk.Bytes)
			if er != nil {
				err = errs.Append(err, er)
				typ = true // try read as public key from this point forward
				key, er = x509.ParsePKIXPublicKey(blk.Bytes)
				if er != nil {
					err = errs.Append(err, er)
					key, er = x509.ParsePKCS1PublicKey(blk.Bytes)
					if er != nil {
						err = errs.Append(err, er)
					}
				}
			}
		}
	}
	if errs.Count(err) > 0 {
		err = errs.Wrap(err, "ASYM")
	} else {
		err = nil
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
