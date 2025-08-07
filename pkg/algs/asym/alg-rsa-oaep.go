package asym

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
)

/*
  Verify:
	> cryptool encrypt -k self.key -i go.mod -o cipher.txt
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
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, a.PublicKey, input, nil)
}

func (a *Rsa2048OaepSha256) Decrypt(input []byte) ([]byte, error) {
	return a.PrivateKey.Decrypt(rand.Reader, input, &rsa.OAEPOptions{Hash: crypto.SHA256})
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
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, a.PublicKey, input, nil)
}

func (a *Rsa2048OaepSha512) Decrypt(input []byte) ([]byte, error) {
	return a.PrivateKey.Decrypt(rand.Reader, input, &rsa.OAEPOptions{Hash: crypto.SHA512})
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
	return rsa.EncryptOAEP(sha512.New(), rand.Reader, &a.PublicKey, input, nil)
}

func (a *Rsa4096OaepSha512) Decrypt(input []byte) ([]byte, error) {
	return ((*rsa.PrivateKey)(a)).Decrypt(rand.Reader, input, &rsa.OAEPOptions{Hash: crypto.SHA512})
}
