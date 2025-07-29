package algorithm

import "golang.org/x/crypto/chacha20poly1305"

func EncryptChacha(
	key []byte,
	input []byte,
) (
	result []byte,
	err error,
) {
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

func DecryptChacha(
	key []byte,
	input []byte,
) (
	result []byte,
	err error,
) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return
	}

	iv, txt := input[:aead.NonceSize()], input[aead.NonceSize():]
	result, err = aead.Open(nil, iv, txt, nil)
	return
}
