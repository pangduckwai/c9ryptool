package sym

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptChacha20Poly1305(
	key []byte,
	input []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[CHA-CHA] not ready")
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	iv, err := Generate(aead.NonceSize())
	if err != nil {
		return
	}

	result = aead.Seal(iv, iv, input, nil)
	return
}

func decryptChacha20Poly1305(
	key []byte,
	input []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[CHA-CHA] not ready")
		return
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	iv, txt := input[:aead.NonceSize()], input[aead.NonceSize():]
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

func (a *ChaCha20Poly1305) PopulateKey(typ int, path string) (err error) {
	*a, err = PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a *ChaCha20Poly1305) Encrypt(input []byte) ([]byte, error) {
	return encryptChacha20Poly1305(*a, input)
}

func (a *ChaCha20Poly1305) Decrypt(input []byte) (result []byte, err error) {
	return decryptChacha20Poly1305(*a, input)
}
