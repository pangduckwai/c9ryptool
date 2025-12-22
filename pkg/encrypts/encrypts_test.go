package encrypts

import (
	"fmt"
	"testing"

	"sea9.org/go/c9ryptool/pkg/utils"
)

// func display(i int, s string) {
// 	r := algrPattern.FindStringSubmatch(s)
// 	if len(r) > 2 {
// 		for i := 0; i < len(r); i++ {
// 			if r[i] == "" {
// 				r[i] = "."
// 			}
// 		}
// 		fmt.Printf("TestParse() %2v - %-5v %-23v (%v) %v -> '%v'\n", i, algrPattern.MatchString(s), r[0], len(r), r[1:], Parse(s))
// 	} else {
// 		fmt.Printf("TestParse() %2v x %-5v %-23v (0) %v -> '%v'\n", i, algrPattern.MatchString(s), s, r, Parse(s))
// 	}
// }

func display(i int, s string) {
	algrs := make([]string, 0)
	for _, n := range aLGORITHMS {
		algrs = append(algrs, n.Name())
	}
	for _, n := range aSYMALGORITHMS {
		algrs = append(algrs, n.Name())
	}

	indices, str, _ := utils.BestMatch(s, algrs, true)
	switch len(indices) {
	case 0:
		fmt.Printf("TestParse() %2v x false %-23v (0) -> match not found ('%v')\n", i, s, Parse(s))
	case 1:
		p := Parse(s)
		if p == str {
			fmt.Printf("TestParse() %2v v true  %-23v (%v) -> '%v'\n", i, s, len(indices), p)
		} else {
			fmt.Printf("TestParse() %2v v true  %-23v (%v) mismatched '%v' vs ''%v\n", i, s, len(indices), p, str)
		}
	default:
		mths := make([]string, 0)
		for _, idx := range indices {
			mths = append(mths, algrs[idx])
		}
		fmt.Printf("TestParse() %2v - true  %-23v (%v) -> %v ('%v')\n", i, s, len(indices), mths, Parse(s))
	}
}

func TestParse(t *testing.T) {
	inputs := []string{
		"AES-128-GCM",
		"AES-192-GCM",
		"AES-256-GCM", "a256gcm", "AES256-GCM",
		"AES-256-CBC", "a256cbc", "AES-256-CBC-HS512",
		"AES-256",
		"CHACHA20-POLY1305", "chapoly",
		"RSA-2048-OAEP-SHA256", "RSA-OAEP-256", "rsa256",
		"RSA-2048-OAEP-SHA512",
		"RSA-4096-OAEP-SHA512",
		"rsa-oaep", "rsa512",
		"RSA-2048-PKCS1V15", "RSA-PKCS1v15",
		"ECIES-SECP256K1-DECRED", "decred",
		"ECIES-SECP256K1-ECIESGO", "iesgo",
		"SECP256K1", "ecies",
		"AES-192-CBC-HS512",
		"A128CBC-HS256",
		"3DES-64-GCM",
		"abcde-def",
		"abc3de-def",
	}
	for i, inp := range inputs {
		display(i, inp)
	}
}
