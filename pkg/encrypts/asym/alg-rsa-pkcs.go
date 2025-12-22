package asym

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

/*
  Verify:
	> echo -n "This is top secret" > secret.txt
	> c9ryptool encrypt -a RSA-PKCS1v15 -k self.key -i secret.txt -o cipher.txt
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

func (a *Rsa2048Pkcs1v15) GetKey() []byte {
	buf, err := x509.MarshalPKCS8PrivateKey(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Rsa2048Pkcs1v15) GetPublicKey() []byte {
	buf, err := x509.MarshalPKIXPublicKey(a.PublicKey)
	if err != nil {
		buf = x509.MarshalPKCS1PublicKey(a.PublicKey)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Rsa2048Pkcs1v15) PopulateKey(key []byte) (err error) {
	a.PrivateKey, a.PublicKey, err = getRsaKey(key, a.KeyLength())
	return
}

func (a *Rsa2048Pkcs1v15) Encrypt(input ...[]byte) ([]byte, error) {
	if a.PublicKey != nil {
		return nil, fmt.Errorf("key not ready")
	}
	return rsa.EncryptPKCS1v15(rand.Reader, a.PublicKey, input[0])
}

func (a *Rsa2048Pkcs1v15) Decrypt(input ...[]byte) ([]byte, error) {
	if a.PrivateKey == nil {
		if a.PublicKey != nil {
			return nil, fmt.Errorf("public key cannot be used for decryption")
		}
		return nil, fmt.Errorf("keys not ready")
	}
	return rsa.DecryptPKCS1v15(rand.Reader, a.PrivateKey, input[0])
}
