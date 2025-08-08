package sym

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"slices"
)

func encryptAesCbc(
	key []byte,
	input []byte,
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

	// iv, err := Generate(aes.BlockSize)
	// if err != nil {
	// 	return
	// }
	iv := []byte("ed029dfc4939dedb")

	cbc := cipher.NewCBCEncrypter(block, iv)

	result = make([]byte, len(input)+aes.BlockSize)
	result = append(result, iv...)
	cbc.CryptBlocks(result[aes.BlockSize:], input)

	// TODO HERE!!! ciphertexts must be authenticated to be secure
	fmt.Printf("TEMP!!! %v\nIV:\n%s\n\nCIPHER:\n%s\n", padSize, iv, result[aes.BlockSize:])
	return
}

func decryptAesCbc(
	key []byte,
	txt []byte,
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

	// iv := input[:aes.BlockSize]
	iv := []byte("ed029dfc4939dedb")
	// txt := input[aes.BlockSize:]

	//ed029dfc4939dedbz7chD4VCurG2fbKb7z1ChhNn98+q3GlmU1CydO2CcpfFK/katC5vBZ+yReR4W+/myfyGT4/oioBw3RT1b9gITZpe8JSCerA0cKC3B6npQe1QADYjm1Uu8BDefgu7G4zQjSg7SkLDUqIi/GK1aOITD9X1jCPNC/iOEVqew5sdI1nohWaZ1JcOi3llEMqD1pixpMZCe3pLD0F50PW5cZXxKw==
	//{"id":"036ec720-46ab-4bdd-bc19-a55544db9e6c","type":"Diagnostic","status":"Pinged","updateTime":{"t":1754622429,"humanT":"2025-08-08 11:07:09"}}
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

func (a *AesCbc256) PopulateKey(typ int, path string) (err error) {
	*a, err = PopulateKey(typ, a.KeyLength(), path)
	return
}

func (a *AesCbc256) Encrypt(input []byte) ([]byte, error) {
	return encryptAesCbc(*a, input)
}

func (a *AesCbc256) Decrypt(input []byte) (result []byte, err error) {
	return decryptAesCbc(*a, input)
}
