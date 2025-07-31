package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"sea9.org/go/cryptool/pkg/algorithm/keys"
)

func EncryptGcm(
	key []byte,
	input []byte,
) (
	result []byte,
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

	iv, err := keys.Generate(gcm.NonceSize())
	if err != nil {
		return
	}

	result = gcm.Seal(iv, iv, input, nil)
	return
}

func DecryptGcm(
	key []byte,
	input []byte,
) (
	result []byte,
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

	iv := input[:gcm.NonceSize()]
	txt := input[gcm.NonceSize():]

	result, err = gcm.Open(nil, iv, txt, nil)
	return
}

// ///////////////
// AES-128-GCM
// ///////////////
type AesGcm128 []byte

func (a AesGcm128) Name() string {
	return "AES-128-GCM"
}

func (a AesGcm128) Type() bool {
	return true
}

func (a AesGcm128) KeyLength() int {
	return 128 / 8
}

func (a AesGcm128) PopulateKey(typ int, path string) (err error) {
	a, err = keys.PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a AesGcm128) Encrypt(input []byte) ([]byte, error) {
	return EncryptGcm(a, input)
}

func (a AesGcm128) Decrypt(input []byte) (result []byte, err error) {
	return DecryptGcm(a, input)
}

// ///////////////
// AES-192-GCM
// ///////////////
type AesGcm192 []byte

func (a AesGcm192) Name() string {
	return "AES-192-GCM"
}

func (a AesGcm192) Type() bool {
	return true
}

func (a AesGcm192) KeyLength() int {
	return 192 / 8
}

func (a AesGcm192) PopulateKey(typ int, path string) (err error) {
	a, err = keys.PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a AesGcm192) Encrypt(input []byte) ([]byte, error) {
	return EncryptGcm(a, input)
}

func (a AesGcm192) Decrypt(input []byte) (result []byte, err error) {
	return DecryptGcm(a, input)
}

// ///////////////
// AES-256-GCM
// ///////////////
type AesGcm256 []byte

func (a AesGcm256) Name() string {
	return "AES-256-GCM"
}

func (a AesGcm256) Type() bool {
	return true
}

func (a AesGcm256) KeyLength() int {
	return 256 / 8
}

func (a AesGcm256) PopulateKey(typ int, path string) (err error) {
	a, err = keys.PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a AesGcm256) Encrypt(input []byte) ([]byte, error) {
	return EncryptGcm(a, input)
}

func (a AesGcm256) Decrypt(input []byte) (result []byte, err error) {
	return DecryptGcm(a, input)
}
