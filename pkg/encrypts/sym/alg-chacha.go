package sym

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptChacha20Poly1305(
	key []byte,
	input []byte,
	iv []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[CHACHA] not ready")
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	if iv == nil {
		iv, err = Generate(aead.NonceSize())
		if err != nil {
			return
		}
	}

	result = aead.Seal(iv, iv, input, nil)
	return
}

func decryptChacha20Poly1305(
	key []byte,
	input []byte,
	iv []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[CHACHA] not ready")
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	var txt []byte
	if iv == nil {
		iv, txt = input[:aead.NonceSize()], input[aead.NonceSize():]
	} else {
		if bytes.Index(input, iv) == 0 {
			txt = input[len(iv):]
		} else {
			txt = input
		}
	}

	result, err = aead.Open(nil, iv, txt, nil)
	return
}

// ///////////////// //
// ChaCha20-Poly1305
type ChaCha20Poly1305 []byte

func (a *ChaCha20Poly1305) Name() string {
	return "ChaCha20-Poly1305"
}

func (a *ChaCha20Poly1305) Type() bool {
	return true
}

func (a *ChaCha20Poly1305) KeyLength() int {
	return 256 / 8
}

func (a *ChaCha20Poly1305) Key() []byte {
	return *a
}

func (a *ChaCha20Poly1305) PubKey() []byte {
	return nil
}

func (a *ChaCha20Poly1305) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *ChaCha20Poly1305) Encrypt(input ...[]byte) ([]byte, error) {
	var iv []byte
	if len(input) > 1 {
		iv = input[1]
	}
	return encryptChacha20Poly1305(*a, input[0], iv)
}

func (a *ChaCha20Poly1305) Decrypt(input ...[]byte) (result []byte, err error) {
	var iv []byte
	if len(input) > 1 {
		iv = input[1]
	}
	return decryptChacha20Poly1305(*a, input[0], iv)
}
