package sym

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func encryptChacha20Poly1305(
	key []byte,
	inputs [][]byte,
) (
	results [][]byte,
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

	var iv, aad []byte
	nsize := aead.NonceSize()
	switch len(inputs) {
	case 3:
		aad = inputs[2]
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

	rst := aead.Seal(iv, iv, inputs[0], aad)
	tsize := len(rst) - aead.Overhead()
	results = make([][]byte, 0)
	results = append(results,
		rst,              // the complete output
		rst[:nsize],      // nonce
		rst[nsize:tsize], // the actual ciphertext
		rst[tsize:],      // authentication tag
	)
	return
}

func decryptChacha20Poly1305(
	key []byte,
	inputs [][]byte,
) ([][]byte, error) {
	if len(key) <= 0 {
		return nil, fmt.Errorf("[CHACHA] not ready")
	}

	aead, err := chacha20poly1305.New(key)
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
		iv, pay = inputs[0][:aead.NonceSize()], inputs[0][aead.NonceSize():]
	} else {
		if bytes.Index(inputs[0], iv) == 0 {
			pay = inputs[0][len(iv):]
		} else {
			pay = inputs[0]
		}
	}
	if tag != nil {
		pay = append(pay, tag...)
	}

	rst, err := aead.Open(nil, iv, pay, aad)
	if err != nil {
		return nil, err
	}
	results := make([][]byte, 0)
	results = append(results, rst)
	return results, nil
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

func (a *ChaCha20Poly1305) GetKey() []byte {
	return *a
}

func (a *ChaCha20Poly1305) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *ChaCha20Poly1305) Encrypt(input ...[]byte) ([][]byte, error) {
	return encryptChacha20Poly1305(*a, input)
}

func (a *ChaCha20Poly1305) Decrypt(input ...[]byte) ([][]byte, error) {
	return decryptChacha20Poly1305(*a, input)
}
