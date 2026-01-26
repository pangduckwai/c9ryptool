package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func encryptAesGcm(
	key []byte,
	inputs [][]byte,
) (
	results [][]byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[AES-GCM] not ready")
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	var iv, aad []byte
	nsize := gcm.NonceSize()
	switch len(inputs) {
	case 3:
		aad = inputs[2]
		fallthrough
	case 2:
		iv = inputs[1]
	case 0:
		err = fmt.Errorf("input missing")
		return
	}
	if iv == nil {
		iv, err = Generate(nsize)
		if err != nil {
			return
		}
	}

	rst := gcm.Seal(iv, iv, inputs[0], aad)
	tsize := len(rst) - gcm.Overhead()
	results = make([][]byte, 0)
	results = append(results,
		rst,              // the complete output
		rst[:nsize],      // iv/nonce
		rst[nsize:tsize], // the actual ciphertext
		rst[tsize:],      // authentication tag
	)
	return
}

func decryptAesGcm(
	key []byte,
	inputs [][]byte,
) ([][]byte, error) {
	if len(key) <= 0 {
		return nil, fmt.Errorf("[AES-GCM] not ready")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var pay, iv, tag, aad []byte
	switch len(inputs) {
	case 4:
		aad = inputs[3]
		fallthrough
	case 3:
		tag = inputs[2]
		fallthrough
	case 2:
		iv = inputs[1]
	case 0:
		return nil, fmt.Errorf("input missing")
	}
	if iv == nil {
		iv, pay = inputs[0][:gcm.NonceSize()], inputs[0][gcm.NonceSize():]
	} else {
		if bytes.Index(inputs[0], iv) == 0 {
			pay = inputs[0][len(iv):]
		} else {
			pay = inputs[0][:]
		}
	}
	if tag != nil {
		pay = append(pay, tag...)
	}

	rst, err := gcm.Open(nil, iv, pay, aad)
	if err != nil {
		return nil, err
	}
	results := make([][]byte, 0)
	results = append(results, rst)
	return results, nil
}

// /////////// //
// AES-128-GCM
type AesGcm128 []byte

func (a *AesGcm128) Name() string {
	return "AES-128-GCM"
}

func (a *AesGcm128) Type() bool {
	return true
}

func (a *AesGcm128) KeyLength() int {
	return 128 / 8
}

func (a *AesGcm128) GetKey() []byte {
	return *a
}

func (a *AesGcm128) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *AesGcm128) Encrypt(input ...[]byte) ([][]byte, error) {
	return encryptAesGcm(*a, input)
}

func (a *AesGcm128) Decrypt(input ...[]byte) ([][]byte, error) {
	return decryptAesGcm(*a, input)
}

// /////////// //
// AES-192-GCM
type AesGcm192 []byte

func (a *AesGcm192) Name() string {
	return "AES-192-GCM"
}

func (a *AesGcm192) Type() bool {
	return true
}

func (a *AesGcm192) KeyLength() int {
	return 192 / 8
}

func (a *AesGcm192) GetKey() []byte {
	return *a
}

func (a *AesGcm192) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *AesGcm192) Encrypt(input ...[]byte) ([][]byte, error) {
	return encryptAesGcm(*a, input)
}

func (a *AesGcm192) Decrypt(input ...[]byte) ([][]byte, error) {
	return decryptAesGcm(*a, input)
}

// /////////// //
// AES-256-GCM
type AesGcm256 []byte

func (a *AesGcm256) Name() string {
	return "AES-256-GCM"
}

func (a *AesGcm256) Type() bool {
	return true
}

func (a *AesGcm256) KeyLength() int {
	return 256 / 8
}

func (a *AesGcm256) GetKey() []byte {
	return *a
}

func (a *AesGcm256) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *AesGcm256) Encrypt(input ...[]byte) ([][]byte, error) {
	return encryptAesGcm(*a, input)
}

func (a *AesGcm256) Decrypt(input ...[]byte) ([][]byte, error) {
	return decryptAesGcm(*a, input)
}
