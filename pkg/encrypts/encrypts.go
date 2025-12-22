package encrypts

import (
	"fmt"
	"sort"

	"sea9.org/go/c9ryptool/pkg/encrypts/asym"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

// Algorithm encryption algorithms
type Algorithm interface {
	// Name algorithm name.
	Name() string

	// Type type of encryption algorithms. 'true' is symmetric, false is asymmetric
	Type() bool

	// KeyLength may be in bytes or bits, depends on the algorithm.
	KeyLength() int

	// GetKey get key
	GetKey() []byte

	// PopulateKey populate key for the algorithm to use. If input byte slice is empty, a new key is generated.
	PopulateKey([]byte) error

	// Encrypt encrypt the given parameters (plain-text and IV respectively), returns the encrypted result.
	Encrypt(...[]byte) ([]byte, error)

	// Decrypt decrypt the given parameters (plain-text and IV respectively), returns the decrypted result.
	Decrypt(...[]byte) ([]byte, error)
}

type AsymAlgorithm interface {
	Algorithm

	// GetPublicKey get public key
	GetPublicKey() []byte
}

var aLGORITHMS = map[string]Algorithm{
	"AES-128-GCM":       &sym.AesGcm128{},
	"AES-192-GCM":       &sym.AesGcm192{},
	"AES-256-GCM":       &sym.AesGcm256{},
	"AES-256-CBC":       &sym.AesCbc256{},
	"ChaCha20-Poly1305": &sym.ChaCha20Poly1305{},
}

var aSYMALGORITHMS = map[string]AsymAlgorithm{
	"RSA-2048-OAEP-SHA256":    &asym.Rsa2048OaepSha256{},
	"RSA-2048-OAEP-SHA512":    &asym.Rsa2048OaepSha512{},
	"RSA-4096-OAEP-SHA512":    &asym.Rsa4096OaepSha512{},
	"RSA-2048-PKCS1v15":       &asym.Rsa2048Pkcs1v15{},
	"ECIES-SECP256K1-DECRED":  &asym.Secp256k1Decred{},
	"ECIES-SECP256K1-ECIESGO": &asym.Secp256k1Eciesgo{},
}

func Default() string {
	return "ChaCha20-Poly1305" //"AES-256-GCM"
}

// List list available algorithm names.
// typ: -1 - asymmetric; 0 - don't care; 1 - symmetric
func List(typ int) (list []string) {
	list = make([]string, 0)
	if typ >= 0 {
		for k := range aLGORITHMS {
			list = append(list, k)
		}
	}
	if typ <= 0 {
		for k := range aSYMALGORITHMS {
			list = append(list, k)
		}
	}

	sort.Strings(list)
	return
}

func Get(inp string) Algorithm {
	a, ok := aLGORITHMS[inp]
	if !ok {
		a = aSYMALGORITHMS[inp]
	}
	return a
}

// Validate validate the given algorithm name.
// typ: -1 - asymmetric; 0 - don't care; 1 - symmetric
func Validate(algr string, typ int) (err error) {
	real := Parse(algr)
	if real == "" {
		err = fmt.Errorf("[ENCR] invalid encryption algorithm name pattern '%v'", algr)
	} else {
		a0, k0 := aLGORITHMS[real]
		a1, k1 := aSYMALGORITHMS[real]
		if !k0 && !k1 {
			err = fmt.Errorf("[ENCR] unsupported encryption algorithm '%v'", real)
		} else if typ < 0 && k0 {
			err = fmt.Errorf("[ENCR] %v is not an asymmetric algorithm as expected", a0.Name())
		} else if typ > 0 && k1 {
			err = fmt.Errorf("[ENCR] %v is not a symmetric algorithm as expected", a1.Name())
		}
	}
	return
}

// Parse return details of the given encryption algorithm
func Parse(inp string) (name string) {
	algrs := make([]string, len(aLGORITHMS)+len(aSYMALGORITHMS))
	i := 0
	for _, a := range aLGORITHMS {
		algrs[i] = a.Name()
		i++
	}
	for _, a := range aSYMALGORITHMS {
		algrs[i] = a.Name()
		i++
	}

	indices, str, _ := utils.BestMatch(inp, algrs, true)
	if len(indices) == 1 {
		name = str
	}
	return
}
