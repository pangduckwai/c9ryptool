package sym

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"sea9.org/go/cryptool/pkg/algorithm/keys"
)

func EncryptChacha(
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

	iv, err := keys.Generate(aead.NonceSize())
	if err != nil {
		return
	}

	result = aead.Seal(iv, iv, input, nil)
	return
}

func DecryptChacha(
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

// ///////////////
// AES-128-GCM
// ///////////////
type ChaCha20Poly1305 []byte

func (a ChaCha20Poly1305) Name() string {
	return "ChaCha20-Poly1305"
}

func (a ChaCha20Poly1305) Type() bool {
	return true
}

func (a ChaCha20Poly1305) KeyLength() int {
	return 256 / 8
}

func (a ChaCha20Poly1305) PopulateKey(typ int, path string) (err error) {
	a, err = keys.PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a ChaCha20Poly1305) Encrypt(input []byte) ([]byte, error) {
	return EncryptGcm(a, input)
}

func (a ChaCha20Poly1305) Decrypt(input []byte) (result []byte, err error) {
	return DecryptGcm(a, input)
}
