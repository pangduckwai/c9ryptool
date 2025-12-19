package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func encryptAesGcm(
	key []byte,
	input []byte,
	iv []byte,
	aad []byte,
) ([]byte, error) {
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

	if iv == nil {
		iv, err = Generate(gcm.NonceSize())
		if err != nil {
			return nil, err
		}
	}

	return gcm.Seal(iv, iv, input, aad), nil
}

func decryptAesGcm(
	key []byte,
	input []byte,
	iv []byte,
	tag []byte,
	aad []byte,
) ([]byte, error) {
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

	var txt []byte
	if iv == nil {
		iv, txt = input[:gcm.NonceSize()], input[gcm.NonceSize():]
	} else {
		if bytes.Index(input, iv) == 0 {
			txt = input[len(iv):]
		} else {
			txt = input[:]
		}
	}
	if tag != nil {
		txt = append(txt, tag...)
	}

	return gcm.Open(nil, iv, txt, aad)
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

func (a *AesGcm128) Marshal() []byte {
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

func (a *AesGcm128) Encrypt(input ...[]byte) ([]byte, error) {
	var iv, aad []byte
	switch len(input) {
	case 3:
		aad = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return encryptAesGcm(*a, input[0], iv, aad)
}

func (a *AesGcm128) Decrypt(input ...[]byte) ([]byte, error) {
	var iv, tag, aad []byte
	switch len(input) {
	case 4:
		aad = input[3]
		fallthrough
	case 3:
		tag = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return decryptAesGcm(*a, input[0], iv, tag, aad)
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

func (a *AesGcm192) Marshal() []byte {
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

func (a *AesGcm192) Encrypt(input ...[]byte) ([]byte, error) {
	var iv, aad []byte
	switch len(input) {
	case 3:
		aad = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return encryptAesGcm(*a, input[0], iv, aad)
}

func (a *AesGcm192) Decrypt(input ...[]byte) ([]byte, error) {
	var iv, tag, aad []byte
	switch len(input) {
	case 4:
		aad = input[3]
		fallthrough
	case 3:
		tag = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return decryptAesGcm(*a, input[0], iv, tag, aad)
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

func (a *AesGcm256) Marshal() []byte {
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

func (a *AesGcm256) Encrypt(input ...[]byte) ([]byte, error) {
	var iv, aad []byte
	switch len(input) {
	case 3:
		aad = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return encryptAesGcm(*a, input[0], iv, aad)
}

func (a *AesGcm256) Decrypt(input ...[]byte) ([]byte, error) {
	var iv, tag, aad []byte
	switch len(input) {
	case 4:
		aad = input[3]
		fallthrough
	case 3:
		tag = input[2]
		fallthrough
	case 2:
		iv = input[1]
	}
	return decryptAesGcm(*a, input[0], iv, tag, aad)
}
