package algr

import (
	"fmt"
	"slices"
)

type Algorithm struct {
	N string // algorithm name
	K int    // key length
	V int    // iv length, 0 means to defer iv initialization
	M int    // mode of operation
}

var ALGORITHMS = [...]string{
	"AES-128-GCM", "AES-256-GCM",
}

func Validate(algr string) (err error) {
	if !slices.Contains(ALGORITHMS[:], algr) {
		err = fmt.Errorf("[ALGR] unsupported encryption algorithm '%v'", algr)
	}
	return
}

// Parse return details of the given encryption algorithm
// TODO NOTE!!!! add GCM/CBC etc.
func Parse(name string) *Algorithm {
	err := Validate(name)
	if err != nil {
		return nil
	}
	switch name {
	case ALGORITHMS[0]:
		return &Algorithm{
			N: name,
			K: 16,
			V: 0,
			M: 0,
		}
	case ALGORITHMS[1]:
		return &Algorithm{
			N: name,
			K: 32,
			V: 0,
			M: 0,
		}
	default:
		return nil
	}
}
