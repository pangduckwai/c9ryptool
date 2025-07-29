package algorithm

import (
	"crypto/aes"
	"crypto/cipher"
)

func EncryptGcm(
	key []byte,
	input []byte,
) (
	result []byte,
	err error,
) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return
	}

	iv, err := Generate(gcm.NonceSize())
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
