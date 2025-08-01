package algorithm

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"sea9.org/go/cryptool/pkg/algorithm/sym"
)

type Algorithm interface {
	// Name algorithm name.
	Name() string

	// Type type of algorithm. 'true' is symmetric, false is asymmetric
	Type() bool

	// KeyLength may be in bytes or bits, depends on algorithm.
	KeyLength() int

	// PopulateKey 1st parameter is flag:
	//  - 0 - generate key, 2nd parameter is the file path to write the new key;
	//  - 1 - read key, 2nd parameter is the file path to read the key from;
	//  - 2 - save 2nd parameter as key
	PopulateKey(int, string) error

	// Encrypt encrypt the given parameter, returns the encrypted result.
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypt the given parameter, returns the decrypted result.
	Decrypt([]byte) ([]byte, error)
}

var aLGORITHMS = map[string]Algorithm{
	"AES-128-GCM":       &sym.AesGcm128{},
	"AES-192-GCM":       &sym.AesGcm192{},
	"AES-256-GCM":       &sym.AesGcm256{},
	"ChaCha20-Poly1305": &sym.ChaCha20Poly1305{},
}

// var aLGORITHMS = map[string]*Algorithm{
// 	"AES-128-GCM": {
// 		Symmetric: true,
// 		Length:    128,
// 		Encrypt:   EncryptGcm,
// 		Decrypt:   DecryptGcm,
// 	},
// 	"AES-192-GCM": {
// 		Symmetric: true,
// 		Length:    192,
// 		Encrypt:   EncryptGcm,
// 		Decrypt:   DecryptGcm,
// 	},
// 	"AES-256-GCM": {
// 		Symmetric: true,
// 		Length:    256,
// 		Encrypt:   EncryptGcm,
// 		Decrypt:   DecryptGcm,
// 	},
// 	"ChaCha20-Poly1305": {
// 		Symmetric: true,
// 		Length:    256,
// 		Encrypt:   EncryptChacha,
// 		Decrypt:   DecryptChacha,
// 	},
// }

func Default() string {
	return "ChaCha20-Poly1305" //"AES-256-GCM"
}

func List() (list []string) {
	list = make([]string, 0)
	for k := range aLGORITHMS {
		list = append(list, k)
	}
	sort.Strings(list)
	return
}

func Get(inp string) Algorithm {
	return aLGORITHMS[inp]
}

var algrPattern = regexp.MustCompile("^([0-9]{0,1}[A-Za-z]+)[-]{0,1}([0-9]*)[-]{0,1}([A-Za-z0-9]*?)[-]{0,1}([A-Za-z0-9]*?)$")

func Validate(algr string) (err error) {
	if !algrPattern.MatchString(algr) {
		err = fmt.Errorf("[ALGR] invalid encryption algorithm name pattern '%v'", algr)
	} else if _, okay := aLGORITHMS[algr]; !okay {
		err = fmt.Errorf("[ALGR] unsupported encryption algorithm '%v'", algr)
	}
	return
}

// Parse return details of the given encryption algorithm
// TODO NOTE!!!! add GCM/CBC etc.
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
	}
	return
}
