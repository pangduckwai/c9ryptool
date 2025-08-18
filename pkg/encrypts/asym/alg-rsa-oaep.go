package asym

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
)

/*
  Verify:
	> echo -n "This is top secret" > secret.txt
	> cryptool encrypt -a RSA-OAEP-256 -k self.key -i secret.txt -o cipher.txt
	> basesf decode -i cipher.txt -o cipher-bin.txt
	> openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -inkey self.key -in cipher-bin.txt -out plain.txt
*/

// //////////////////// //
// RSA 2048 OAEP SHA256
type Rsa2048OaepSha256 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (a *Rsa2048OaepSha256) Name() string {
	return "RSA-2048-OAEP-SHA256"
}

func (a *Rsa2048OaepSha256) Type() bool {
	return false
}

func (a *Rsa2048OaepSha256) KeyLength() int {
	return 2048
}

func (a *Rsa2048OaepSha256) Key() []byte {
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

func (a *Rsa2048OaepSha256) PopulateKey(key []byte) (err error) {
	a.PrivateKey, a.PublicKey, err = getRsaKey(key, a.KeyLength())
	return
}

func (a *Rsa2048OaepSha256) Encrypt(input ...[]byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, a.PublicKey, input[0], nil)
}

func (a *Rsa2048OaepSha256) Decrypt(input ...[]byte) ([]byte, error) {
	return a.PrivateKey.Decrypt(rand.Reader, input[0], &rsa.OAEPOptions{Hash: crypto.SHA256})
}

// //////////////////// //
// RSA 2048 OAEP SHA512
type Rsa2048OaepSha512 struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func (a *Rsa2048OaepSha512) Name() string {
	return "RSA-2048-OAEP-SHA512"
}

func (a *Rsa2048OaepSha512) Type() bool {
	return false
}

func (a *Rsa2048OaepSha512) KeyLength() int {
	return 2048
}

func (a *Rsa2048OaepSha512) Key() []byte {
	buf, err := x509.MarshalPKCS8PrivateKey(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	return buf
}

func (a *Rsa2048OaepSha512) PopulateKey(key []byte) (err error) {
	a.PrivateKey, a.PublicKey, err = getRsaKey(key, a.KeyLength())
	return
}

func (a *Rsa2048OaepSha512) Encrypt(input ...[]byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, a.PublicKey, input[0], nil)
}

func (a *Rsa2048OaepSha512) Decrypt(input ...[]byte) ([]byte, error) {
	return a.PrivateKey.Decrypt(rand.Reader, input[0], &rsa.OAEPOptions{Hash: crypto.SHA512})
}

// //////////////////// //
// RSA 4096 OAEP SHA512
type Rsa4096OaepSha512 rsa.PrivateKey

func (a *Rsa4096OaepSha512) Name() string {
	return "RSA-4096-OAEP-SHA512"
}

func (a *Rsa4096OaepSha512) Type() bool {
	return false
}

func (a *Rsa4096OaepSha512) KeyLength() int {
	return 4096
}

func (a *Rsa4096OaepSha512) Key() []byte {
	buf, err := x509.MarshalPKCS8PrivateKey(a)
	if err != nil {
		panic(err)
	}
	return buf
}

func (a *Rsa4096OaepSha512) PopulateKey(key []byte) (err error) {
	k, _, err := getRsaKey(key, a.KeyLength())
	a = (*Rsa4096OaepSha512)(k)
	return
}

func (a *Rsa4096OaepSha512) Encrypt(input ...[]byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, &a.PublicKey, input[0], nil)
}

func (a *Rsa4096OaepSha512) Decrypt(input ...[]byte) ([]byte, error) {
	return ((*rsa.PrivateKey)(a)).Decrypt(rand.Reader, input[0], &rsa.OAEPOptions{Hash: crypto.SHA512})
}
