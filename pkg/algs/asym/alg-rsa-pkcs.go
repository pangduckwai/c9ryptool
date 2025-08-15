package asym

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

/*
  Verify:
	> echo -n "This is top secret" > secret.txt
	> cryptool encrypt -a RSA-PKCS1v15 -k self.key -i secret.txt -o cipher.txt
	> basesf decode -i cipher.txt -o cipher-bin.txt
	> openssl pkeyutl -decrypt -inkey self.key -in cipher-bin.txt -out plain.txt
*/

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

func (a *Rsa2048Pkcs1v15) Key() []byte {
	buf, err := x509.MarshalPKCS8PrivateKey(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	pem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	})
	return pem
}

func (a *Rsa2048Pkcs1v15) PopulateKey(key []byte) (err error) {
	a.PrivateKey, a.PublicKey, err = getRsaKey(key, a.KeyLength())
	return
}

func (a *Rsa2048Pkcs1v15) Encrypt(input ...[]byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, a.PublicKey, input[0])
}

func (a *Rsa2048Pkcs1v15) Decrypt(input ...[]byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, a.PrivateKey, input[0])
}
