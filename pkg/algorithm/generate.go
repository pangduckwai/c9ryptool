package algorithm

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

// GenerateKey generate a random key of 'keyLen' bytes long, and store the key
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
