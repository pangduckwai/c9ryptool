package sym

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/scrypt"
)

const SALTLEN = 16
const N = 65536
const R = 16
const P = 1

// PopulateKeyFromPassword get a key of 'keyLen' bytes long from the given passpharse using the
// scrypt method. The salt to use is stored in the file 'salt.txt'. If 'salt.txt' doesn't
// exist, one with random value will be created.
func PopulateKeyFromPassword(
	prompt string,
	input []byte,
	keyLen, saltLen int,
	populate func(int, string) error,
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
			return
		}
	}

	var str string
	rdr := bufio.NewReader(os.Stdin)
	fmt.Printf("%v:\n", prompt)
	fmt.Print("Enter password: ")
	str, err = rdr.ReadString('\n')
	if err != nil {
		return
	}
	key, err := scrypt.Key([]byte(str[:len(str)-1]), salt, N, R, P, keyLen)
	if err != nil {
		return
	}
	err = populate(2, string(key))

	return
}

// Generate generate 'lgth' bytes of random value.
func Generate(lgth int) (result []byte, err error) {
	result = make([]byte, lgth)
	_, err = rand.Read(result)
	if err != nil {
		result = nil
	}
	return
}

// GenerateKey generate a random symmetric key of 'keyLen' bytes long, and store the key
// as base64 encoded text in the file of the given path.
func GenerateKey(path string, keyLen int) (
	key []byte,
	err error,
) {
	key, err = Generate(keyLen)
	if err != nil {
		return
	}
	kfile, err := os.Create(path)
	if err != nil {
		return
	}
	wtr := bufio.NewWriter(kfile)
	defer kfile.Close()
	fmt.Fprint(wtr, base64.StdEncoding.EncodeToString(key))
	wtr.Flush()
	return
}

// ReadKey read key
func ReadKey(
	path string,
) (
	key []byte,
	err error,
) {
	kecd, err := os.ReadFile(path)
	if err != nil {
		return
	}
	key, err = base64.StdEncoding.DecodeString(string(kecd))
	return
}

func PopulateKey(typ, lgth int, str string) (
	key []byte,
	err error,
) {
	switch typ {
	case 0: // generate key
		key, err = GenerateKey(str, lgth)
	case 1: // read key
		key, err = ReadKey(str)
	case 2: // from password
		key = []byte(str)
	}
	return
}
