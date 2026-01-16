package sym

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const SALTLEN = 16
const N = 65536
const R = 16
const P = 1

// PopulateKeyFromPassword get a key of 'keyLen' bytes long from the given passpharse
// using the scrypt method. The salt to use is stored at the end of the cipher text,
// separated by a dot (`.`)
func PopulateKeyFromPassword(
	passwd string,
	input []byte,
	keyLen, saltLen int,
	populate func([]byte) error,
) (
	salt []byte,
	err error,
) {
	if input != nil {
		salt = input[len(input)-saltLen:]
	} else {
		salt = make([]byte, saltLen)
		_, err = rand.Read(salt)
		if err != nil {
			err = fmt.Errorf("[PASS] %v", err)
			return
		}
	}

	key, err := scrypt.Key([]byte(passwd[:len(passwd)-1]), salt, N, R, P, keyLen)
	if err != nil {
		err = fmt.Errorf("[PASS] %v", err)
		return
	}
	err = populate(key)

	return
}

// Generate generate 'lgth' bytes of random value.
func Generate(lgth int) (result []byte, err error) {
	result = make([]byte, lgth)
	_, err = rand.Read(result)
	if err != nil {
		result = nil
		err = fmt.Errorf("[GEN] %v", err)
	}
	return
}
