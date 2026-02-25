package utils

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
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

// func TestRead(t *testing.T) {
// 	buff, err := Read("../../README.md", 16)
// 	if err != nil {
// 		t.Fatalf("TestRead() %v", err)
// 	}
// 	fmt.Printf("TestRead():\n%v\n", string(buff))
// }

func TestWrite(t *testing.T) {
	in := []byte("HelloHowAreYou?I'mFineThankYouVeryMuch!")
	var e0, e1 Encoder = nil, nil
	err := Write("", in, e0, e1)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPipeUsage(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	in := bytes.NewReader([]byte("H4sIAAAAAAAA//JIzcnJ98gvdyxKjcwvtfdUz3XLzEsNyUjMy47MLw1LLar0LU3OUAQAAAD//wEAAP//L9lnyicAAAA="))
	var e0, e1 Decoder = nil, nil

	err := pipedDecode(in, out)
	if err == nil {
		t.Fatal(err)
	}
	fmt.Printf("TestPipeUsage() not piped: %v\n", err)

	err = pipedDecode(in, out, e0, e1) // should panic
	if err == nil {
		t.Fatal(err)
	}
}
