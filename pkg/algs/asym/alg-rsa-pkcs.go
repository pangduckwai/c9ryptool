package asym

import (
	"crypto/rand"
	"crypto/rsa"
)

// //////////////////// //
// RSA 2048 PKCS 1 v1.5
type Rsa2048Pkcs1v15 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (a *Rsa2048Pkcs1v15) Name() string {
	return "RSA-2048-PKCS1v15"
}

func (a *Rsa2048Pkcs1v15) Type() bool {
	return false
}

func (a *Rsa2048Pkcs1v15) KeyLength() int {
	return 2048
}

func (a *Rsa2048Pkcs1v15) PopulateKey(typ int, str string) (err error) {
	var key *rsa.PrivateKey
	var pkey *rsa.PublicKey
	switch typ {
	case 0: // generate key
		key, err = generateRsaKey(a.KeyLength(), str)
		if err != nil {
			return
		}
		a.PrivateKey = key
		a.PublicKey = &key.PublicKey
	case 1: // read key
		key, pkey, err = readRsaKey(str)
		if err != nil {
			return
		}
		a.PrivateKey = key
		a.PublicKey = pkey
	}
	return
}

func (a *Rsa2048Pkcs1v15) Encrypt(input []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, a.PublicKey, input)
}

func (a *Rsa2048Pkcs1v15) Decrypt(input []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, a.PrivateKey, input)
}
