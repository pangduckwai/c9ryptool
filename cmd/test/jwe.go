package main

import (
	"fmt"
	"time"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/utils"
)

// jweTest generate and encrypt sample data into JWE format
// Usage:
//
//  0. CD to a test directory
//     $ cd test
//
//  1. Generate JWE formatted encryption results: get 5 base64 encode files (./aad.jwe, ./cek.jwe, ./iv.jwe, ./pay.jwe, ./tag.jwe) if successful
//     $ ~/test jwe [header path] [payload path] [public key path]
//     > 2026-01-26T17:19:51.068 finished generating JWE parts
//
//  2. Obtain CEK (base64 encoded; ./cek.hex) if successful
//     $ ~/c9ryptool decrypt -v -a RSA-OAEP-256 -k [private key path] -i cek.jwe --encode-in=base64 -o cek.hex --encode-out=hex
//     > 2026-01-26T17:31:37.722 [c9rypTool (version v1.5.3 2026012615)] finished 'decrypt' using 'RSA-2048-OAEP-SHA256' (I:base64/O:hex)
//
//  3. Decrypt payload (as console output) if successful
//     $ ~/c9ryptool decrypt -v -a AES-256-GCM -k cek.hex --encode-key=hex -i pay.jwe --encode-in=base64 --iv=iv.jwe --encode-iv=base64 --tag=tag.jwe --encode-tag=base64 --aad=aad.jwe
//     > [content of payload path in step 1]
//     > 2026-01-26T17:33:02.277 [c9rypTool (version v1.5.3 2026012615)] finished 'decrypt' using 'AES-256-GCM' (I:base64/V:base64/T:base64/A:nil/O:nil/K:hex)
func jweTest(hdrPath, inpPath, keyPath string) (err error) {
	ecdr := encodes.Get(encodes.Parse("base64"))

	alg0 := encrypts.Get(encrypts.Parse("RSA-OAEP-256"))
	kek, err := utils.Read(keyPath, cfgs.BUFFER, true)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][KEK][RDR]%v", err)
		return
	}
	err = alg0.PopulateKey(kek)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][KEK][POP]%v", err)
		return
	}

	alg1 := encrypts.Get(encrypts.Parse("AES256-GCM"))
	err = alg1.PopulateKey(nil)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][CEK][POP]%v", err)
		return
	}
	tmp, err := alg0.Encrypt(alg1.GetKey())
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][CEK][ECY]%v", err)
		return
	} else if len(tmp) < 1 || tmp[0] == nil {
		err = fmt.Errorf("[TEST][JWE][CEK][ECY] result missing")
		return
	}
	cek := []byte(ecdr.Encode(tmp[0])) // OUTPUT 1

	hdr, err := utils.Read(hdrPath, cfgs.BUFFER, true)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][HDR][RDR]%v", err)
		return
	}
	hdr = []byte(ecdr.Encode(hdr)) // OUTPUT 0

	pay, err := utils.Read(inpPath, cfgs.BUFFER, true)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][INP][RDR]%v", err)
		return
	}
	tmp, err = alg1.Encrypt(pay, nil, hdr) // Note!!! the encoded content of 'header' is used here
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][INP][ECY]%v", err)
		return
	} else if len(tmp) < 4 || tmp[0] == nil {
		err = fmt.Errorf("[TEST][JWE][INP][ECY] result missing")
		return
	}
	iv := []byte(ecdr.Encode(tmp[1]))  // OUTPUT 2
	pay = []byte(ecdr.Encode(tmp[2]))  // OUTPUT 3
	tag := []byte(ecdr.Encode(tmp[3])) // OUTPUT 4

	err = utils.Write("aad.jwe", hdr)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][OUT][AAD]%v", err)
		return
	}

	err = utils.Write("cek.jwe", cek)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][OUT][CEK]%v", err)
		return
	}

	err = utils.Write("iv.jwe", iv)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][OUT][IV]%v", err)
		return
	}

	err = utils.Write("pay.jwe", pay)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][OUT][PAY]%v", err)
		return
	}

	err = utils.Write("tag.jwe", tag)
	if err != nil {
		err = fmt.Errorf("[TEST][JWE][OUT][TAG]%v", err)
		return
	}

	fmt.Printf("\n%v finished generating JWE encryption results\n", time.Now().Format("2006-01-02T15:04:05.000"))
	return
}
