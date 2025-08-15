package cryptool

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
	"sea9.org/go/cryptool/pkg/cfgs"
)

func TestRandom(t *testing.T) {
	key := make([]byte, 32)
	x, err := rand.Read(key)
	if err != nil {
		t.Fatalf("TestRandom() %v", err)
	}
	ecd := base64.StdEncoding.EncodeToString(key)
	dcd, err := base64.StdEncoding.DecodeString(ecd)
	if err != nil {
		t.Fatalf("TestRandom() %v", err)
	}
	fmt.Printf("TestRandom() %3v - %v\n", x, ecd)
	fmt.Printf("TestRandom() %3v - %v\n", x, key)
	fmt.Printf("TestRandom() %3v - %v\n", x, dcd)
}

func TestScrypt(t *testing.T) {
	// salt := make([]byte, 16)
	// _, err := rand.Read(salt)
	// if err != nil {
	// 	t.Fatalf("TestScrypt() %v", err)
	// }
	// fmt.Printf("salt: %v\n", base64.StdEncoding.EncodeToString(salt))
	salt, err := base64.StdEncoding.DecodeString("QXLj3fCsq9o08rw/8rYj0w==")
	if err != nil {
		t.Fatalf("TestScrypt() %v", err)
	}

	pwd := []byte("qwer123#")
	key, err := scrypt.Key(pwd, salt, 65536, 16, 1, 32)
	if err != nil {
		t.Fatalf("TestScrypt() %v", err)
	}
	fmt.Printf("TestScrypt() %3v - %v\n", len(key), key)
}

func TestBcrypt(t *testing.T) {
	pwd := []byte("qwer123#")
	key, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("TestBcrypt() %v", err)
	}
	fmt.Printf("TestBcrypt() %3v - %v\n", len(key), key)
}

func TestReadfile(t *testing.T) {
	f, err := os.Open("README.md")
	if errors.Is(err, os.ErrNotExist) {
		fmt.Println("File not exists")
	} else if err != nil {
		t.Fatalf("TestReadfile() %v", err)
	} else {
		fmt.Println("File exists")
	}
	f.Close()
}

func TestRead(t *testing.T) {
	cfg := &cfgs.Config{
		Input:   "../../README.md",
		Buffer:  16,
		Verbose: true,
	}
	buff, err := read(cfg.Input, cfg.Buffer, false, cfg.Verbose)
	if err != nil {
		t.Fatalf("TestRead() %v", err)
	}
	fmt.Printf("TestRead():\n%v\n", string(buff))
}

const MASK_LIST = 128
const MASK_FLAG = 127

func TestBitwise(t *testing.T) {
	var a0 uint8 = 0
	var a1 uint8 = 1
	var a2 uint8 = 2
	var a3 uint8 = 3
	a0 |= MASK_LIST
	a2 |= MASK_LIST
	fmt.Printf("TestBitwise() 0: %3v - %v %v\n", a0, a0&MASK_FLAG, a0&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 1: %3v - %v %v\n", a1, a1&MASK_FLAG, a1&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 2: %3v - %v %v\n", a2, a2&MASK_FLAG, a2&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 3: %3v - %v %v\n", a3, a3&MASK_FLAG, a3&MASK_LIST > 0)
}
