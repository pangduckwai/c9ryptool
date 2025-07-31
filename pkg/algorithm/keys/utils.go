package keys

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

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
		// key, err = keys.FromPassword([]byte(str), lgth, keys.SALTLEN, cfg.Salt, cfg.SaltFile)
	}
	return
}
