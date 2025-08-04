package asym

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
)

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

func encryptRsa(
	key *rsa.PublicKey,
	input []byte,
	hsh hash.Hash,
) (
	result []byte,
	err error,
) {
	result, err = rsa.EncryptOAEP(hsh, rand.Reader, key, input, nil)
	return
}

func decryptRsa(
	key *rsa.PrivateKey,
	input []byte,
	hsh crypto.Hash,
) (
	result []byte,
	err error,
) {
	result, err = key.Decrypt(rand.Reader, input, &rsa.OAEPOptions{Hash: hsh})
	return
}

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

func (a *Rsa2048OaepSha256) PopulateKey(typ int, str string) (err error) {
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

func (a *Rsa2048OaepSha256) Encrypt(input []byte) ([]byte, error) {
	return encryptRsa(a.PublicKey, input, sha256.New())
}

func (a *Rsa2048OaepSha256) Decrypt(input []byte) ([]byte, error) {
	return decryptRsa(a.PrivateKey, input, crypto.SHA256)
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

func (a *Rsa2048OaepSha512) PopulateKey(typ int, str string) (err error) {
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

func (a *Rsa2048OaepSha512) Encrypt(input []byte) ([]byte, error) {
	return encryptRsa(a.PublicKey, input, sha512.New())
}

func (a *Rsa2048OaepSha512) Decrypt(input []byte) ([]byte, error) {
	return decryptRsa(a.PrivateKey, input, crypto.SHA512)
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

func (a *Rsa4096OaepSha512) PopulateKey(typ int, str string) (err error) {
	var k *rsa.PrivateKey
	switch typ {
	case 0: // generate key
		k, err = generateRsaKey(a.KeyLength(), str)
		if err != nil {
			return
		}
		a = (*Rsa4096OaepSha512)(k)
	case 1: // read key
		k, _, err = readRsaKey(str)
		if err != nil {
			return
		}
		a = (*Rsa4096OaepSha512)(k)
	}
	return
}

func (a *Rsa4096OaepSha512) Encrypt(input []byte) ([]byte, error) {
	return encryptRsa(&a.PublicKey, input, sha512.New())
}

func (a *Rsa4096OaepSha512) Decrypt(input []byte) ([]byte, error) {
	return decryptRsa((*rsa.PrivateKey)(a), input, crypto.SHA512)
}
