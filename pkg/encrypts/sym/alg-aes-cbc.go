package sym

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"slices"
)

func encryptAesCbc(
	key []byte,
	input []byte,
	iv []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[AES-CBC] not ready")
		return
	}

	// padding
	padSize := aes.BlockSize - (len(input) % aes.BlockSize)
	input = append(input, slices.Repeat([]byte{byte(padSize)}, padSize)...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if iv == nil {
		fmt.Printf("TEMP!!! GEN\n")
		iv, err = Generate(aes.BlockSize)
		if err != nil {
			return
		}
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	result = make([]byte, len(input)+aes.BlockSize)
	result = append(result, iv...)
	cbc.CryptBlocks(result[aes.BlockSize:], input)

	fmt.Printf("TEMP!!! %v\nIV:\n%s\n\nCIPHER:\n%s\n", padSize, iv, result[aes.BlockSize:]) // TODO HERE!!! ciphertexts must be authenticated to be secure
	return
}

func decryptAesCbc(
	key []byte,
	input []byte,
	iv []byte,
) (
	result []byte,
	err error,
) {
	if len(key) <= 0 {
		err = fmt.Errorf("[AES-CBC] not ready")
		return
	}

	// // padding
	// padSize := aes.BlockSize - (len(input) % aes.BlockSize)
	// if padSize != aes.BlockSize {
	// 	input = append(input, slices.Repeat([]byte{byte(32)}, padSize)...)
	// }

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	var txt []byte
	if iv == nil {
		iv = input[:aes.BlockSize]
		txt = input[aes.BlockSize:]
	} else {
		if bytes.Index(input, iv) == 0 {
			fmt.Printf("TEMP!!! YES\n")
			txt = input[len(iv):]
		} else {
			fmt.Printf("TEMP!!! NOOOO\n")
			txt = input[:]
		}
	}
	fmt.Printf("TEMP!!! Block size: %v\n", aes.BlockSize)
	fmt.Printf("TEMP!!! IV  (%3v): '%s'\n", len(iv), iv)
	fmt.Printf("TEMP!!! In  (%3v): '%s'\n", len(txt), txt)
	fmt.Printf("TEMP!!! Key (%3v): '%s'\n", len(key), key)

	cbc := cipher.NewCBCDecrypter(block, iv)

	result = make([]byte, len(txt))
	cbc.CryptBlocks(result, txt)

	// var idx int
	// for idx = len(result) - 1; idx >= 0; idx-- {
	// 	if result[idx] != 0 {
	// 		break
	// 	}
	// }
	// if idx > 0 && idx < len(result)-1 {
	// 	result = result[:idx+1]
	// }

	// fmt.Printf("TEMP!!! %v\nIV:\n%s\n\nCIPHER:\n%s\n", aes.BlockSize, iv, result)
	return
}

// /////////// //
// AES-256-CBC
type AesCbc256 []byte

func (a *AesCbc256) Name() string {
	return "AES-256-CBC"
}

func (a *AesCbc256) Type() bool {
	return true
}

func (a *AesCbc256) KeyLength() int {
	return 256 / 8
}

func (a *AesCbc256) Marshal() []byte {
	return *a
}

func (a *AesCbc256) PopulateKey(key []byte) (err error) {
	if key == nil {
		*a, err = Generate(a.KeyLength())
	} else {
		*a = key
	}
	return
}

func (a *AesCbc256) Encrypt(input ...[]byte) ([]byte, error) {
	var iv []byte
	if len(input) > 1 {
		iv = input[1]
	}
	return encryptAesCbc(*a, input[0], iv)
}

func (a *AesCbc256) Decrypt(input ...[]byte) ([]byte, error) {
	var iv []byte
	if len(input) > 1 {
		iv = input[1]
	}
	return decryptAesCbc(*a, input[0], iv)
}
