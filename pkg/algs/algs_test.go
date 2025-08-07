package algs

import (
	"fmt"
	"testing"
)

func display(i int, s string) {
	r := algrPattern.FindStringSubmatch(s)
	if len(r) > 2 {
		for i := 0; i < len(r); i++ {
			if r[i] == "" {
				r[i] = "."
			}
		}
		fmt.Printf("TestParse() %2v - %-5v %-17v (%v) %v -> '%v'\n", i, algrPattern.MatchString(s), r[0], len(r), r[1:], Parse(s))
	} else {
		fmt.Printf("TestParse() %2v x %-5v %-17v (0) %v -> '%v'\n", i, algrPattern.MatchString(s), s, r, Parse(s))
	}
}

func TestParse(t *testing.T) {
	display(0, "AES-192-CBC-HS512")
	display(1, "AES256-GCM")
	display(2, "A128CBC-HS256")
	display(3, "3DES-GCM")
	display(4, "3DES-64-GCM")
	display(5, "AES-256-GCM")
	display(6, "ChaCha20-Poly1305")
	display(7, "AES-256")
	display(8, "abcde-def")
	display(9, "abc3de-def")
	display(10, "A128CBC")
	display(11, "RSA-OAEP-256")
	display(12, "RSA-2048-PKCS1v15")
	display(13, "RSA-PKCS1v15")
}
