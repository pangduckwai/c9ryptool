package keys

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

// FromPassword get a key of 'keyLen' bytes long from the given passpharse using the
// scrypt method. The salt to use is stored in the file 'salt.txt'. If 'salt.txt' doesn't
// exist, one with random value will be created.
func FromPassword(pwd []byte, keyLen, saltLen int, salts, saltPath string) (
	key []byte,
	err error,
) {
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
	key, err = scrypt.Key(pwd, salt, N, R, P, keyLen)
	return
}
