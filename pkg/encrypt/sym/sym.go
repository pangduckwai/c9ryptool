package sym

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"os"

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
	prompt string,
	input []byte,
	keyLen, saltLen int,
	populate func([]byte) error,
) (
	salt []byte,
	err error,
) {
	if input != nil {
		idx := bytes.LastIndex(input, []byte("."))
		if idx < 0 || idx > len(input)-2 {
			err = fmt.Errorf("[PWD] salt missing: %v", idx)
			return
		}

		sln := len(input) - saltLen
		if idx == sln-1 {
			salt = input[sln:]
		} else {
			err = fmt.Errorf("[PWD] salt with length %v, expecting %v", sln-1, saltLen)
			return
		}
	} else {
		salt = make([]byte, saltLen)
		_, err = rand.Read(salt)
		if err != nil {
			err = fmt.Errorf("[PWD] %v", err)
			return
		}
	}

	var str string
	rdr := bufio.NewReader(os.Stdin)
	fmt.Printf("%v:\n", prompt)
	fmt.Print("Enter password: ")
	str, err = rdr.ReadString('\n')
	if err != nil {
		err = fmt.Errorf("[PWD] %v", err)
		return
	}
	key, err := scrypt.Key([]byte(str[:len(str)-1]), salt, N, R, P, keyLen)
	if err != nil {
		err = fmt.Errorf("[PWD] %v", err)
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
