package encrypts

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"sea9.org/go/c9ryptool/pkg/encrypts/asym"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
)

// Algorithm encryption algorithms
type Algorithm interface {
	// Name algorithm name.
	Name() string

	// Type type of encryption algorithms. 'true' is symmetric, false is asymmetric
	Type() bool

	// KeyLength may be in bytes or bits, depends on the algorithm.
	KeyLength() int

	// Marshal get key
	Marshal() []byte

	// PopulateKey populate key for the algorithm to use. If input byte slice is empty, a new key is generated.
	PopulateKey([]byte) error

	// Encrypt encrypt the given parameters (plain-text and IV respectively), returns the encrypted result.
	Encrypt(...[]byte) ([]byte, error)

	// Decrypt decrypt the given parameters (plain-text and IV respectively), returns the decrypted result.
	Decrypt(...[]byte) ([]byte, error)
}

var aLGORITHMS = map[string]Algorithm{
	"AES-128-GCM":          &sym.AesGcm128{},
	"AES-192-GCM":          &sym.AesGcm192{},
	"AES-256-GCM":          &sym.AesGcm256{},
	"AES-256-CBC":          &sym.AesCbc256{},
	"ChaCha20-Poly1305":    &sym.ChaCha20Poly1305{},
	"RSA-2048-OAEP-SHA256": &asym.Rsa2048OaepSha256{},
	"RSA-2048-OAEP-SHA512": &asym.Rsa2048OaepSha512{},
	"RSA-4096-OAEP-SHA512": &asym.Rsa4096OaepSha512{},
	"RSA-2048-PKCS1v15":    &asym.Rsa2048Pkcs1v15{},
	"SECP256K1-ECIES":      &asym.Secp256k1{},
}

func Default() string {
	return "ChaCha20-Poly1305" //"AES-256-GCM"
}

// List list available algorithm names.
// typ: -1 - asymmetric; 0 - don't care; 1 - symmetric
func List(typ int) (list []string) {
	list = make([]string, 0)
	for k := range aLGORITHMS {
		if typ == 0 || (typ < 0 && !aLGORITHMS[k].Type()) || (typ > 0 && aLGORITHMS[k].Type()) {
			list = append(list, k)
		}
	}
	sort.Strings(list)
	return
}

func Get(inp string) Algorithm {
	return aLGORITHMS[inp]
}

var algrPattern = regexp.MustCompile("^([0-9]{0,1}[A-Za-z]+)[-]{0,1}([0-9]*)[-]{0,1}([A-Za-z0-9]*?)[-]{0,1}([A-Za-z0-9]*?)$")

// Validate validate the given algorithm name.
// typ: -1 - asymmetric; 0 - don't care; 1 - symmetric
func Validate(algr string, typ int) (err error) {
	real := Parse(algr)
	if real == "" {
		err = fmt.Errorf("[ENCR] invalid encryption algorithm name pattern '%v'", algr)
	} else if alg, okay := aLGORITHMS[real]; !okay {
		err = fmt.Errorf("[ENCR] unsupported encryption algorithm '%v'", real)
	} else if (typ < 0 && alg.Type()) || (typ > 0 && !alg.Type()) {
		art := "a"
		pfx := ""
		if typ < 0 {
			art = "an"
			pfx = "a"
		}
		err = fmt.Errorf("[ENCR] %v is not %v %vsymmetric algorithm as expected", alg.Name(), art, pfx)
	}
	return
}

// Parse return details of the given encryption algorithm
func Parse(inp string) (name string) {
	parts := algrPattern.FindStringSubmatch(inp)
	if len(parts) < 5 {
		return
	}

	switch parts[1] {
	case "A":
		fallthrough
	case "AES":
		l, err := strconv.Atoi(parts[2])
		if err != nil {
			return
		}
		mo := parts[3]
		if parts[4] != "" {
			s0 := ""
			if mo != "" {
				s0 = "-"
			}
			mo = fmt.Sprintf("%v%v%v", mo, s0, parts[4])
		}
		s1 := ""
		if mo != "" {
			s1 = "-"
		}
		name = fmt.Sprintf("AES-%v%v%v", l, s1, mo)
	case "ChaCha":
		if parts[2] == "20" && parts[4] == "Poly1305" {
			name = inp
		}

	case "RSA":
		var err error
		var l, h int
		if parts[2] != "" {
			if l, err = strconv.Atoi(parts[2]); err != nil {
				return
			}
		} else {
			l = 2048
		}
		hsh := parts[4]
		if h, err = strconv.Atoi(hsh); err == nil {
			hsh = fmt.Sprintf("SHA%v", h)
		}
		if parts[3] == "OAEP" {
			name = fmt.Sprintf("RSA-%v-%v-%v", l, parts[3], hsh)
		} else {
			s3 := ""
			if parts[3] != "" {
				s3 = "-"
			}
			s4 := ""
			if parts[4] != "" {
				s4 = "-"
			}
			name = fmt.Sprintf("RSA-%v%v%v%v%v", l, s3, parts[3], s4, parts[4])
		}

	case "SECP":
		switch parts[4] {
		case "ECIES":
			name = fmt.Sprintf("%v%v%v-%v", parts[1], parts[2], parts[3], parts[4])
		case "K1":
			name = fmt.Sprintf("%v%v%v-ECIES", parts[1], parts[2], parts[4])
		default:
			name = "SECP256K1-ECIES"
		}
	}
	return
}
