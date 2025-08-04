package sym

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
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
	prompt, salts, saltPath string,
	keyLen, saltLen int,
	populate func(int, string) error,
) (err error) {
	var sfile *os.File
	var salt []byte
	if salts != "" {
		salt, err = base64.StdEncoding.DecodeString(salts)
		if err != nil {
			return
		}
	} else {
		if _, err = os.Stat(saltPath); errors.Is(err, os.ErrNotExist) {
			// salt file not exists
			salt = make([]byte, saltLen)
			_, err = rand.Read(salt)
			if err != nil {
				return
			}
			sfile, err = os.Create(saltPath)
			if err != nil {
				return
			}
			wtr := bufio.NewWriter(sfile)
			defer sfile.Close()
			fmt.Fprint(wtr, base64.StdEncoding.EncodeToString(salt))
			wtr.Flush()
		} else if err != nil {
			return
		} else {
			// salt file found
			var sstr []byte
			sstr, err = os.ReadFile(saltPath)
			if err != nil {
				return
			}
			salt, err = base64.StdEncoding.DecodeString(string(sstr))
			if err != nil {
				return
			}
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

// SaltFileExists for validation
func SaltFileExists(path string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
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
