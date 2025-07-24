package config

import (
	"fmt"
	"slices"
)

var ALGORITHMS = [...]string{
	"AES-128", "AES-256",
}

func validateAlg(algr string) (err error) {
	if !slices.Contains(ALGORITHMS[:], algr) {
		err = fmt.Errorf("unsupported encryption algorithm '%v'", algr)
	}
	return
}

func Algorithm(algr string) (
	keyLen int,
	ivLen int,
	err error,
) {
	err = validateAlg(algr)
	if err != nil {
		return
	}
	switch algr {
	case ALGORITHMS[0]:
		keyLen = 16
		ivLen = 16
		return
	case ALGORITHMS[1]:
		keyLen = 32
		ivLen = 16
	}
	return
}
