package crypt

import (
	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/config"
)

func Encrypt(
	cfg *config.Config,
	alg algorithm.Algorithm,
) (err error) {
	var input, result []byte

	input, err = read(cfg, false)
	if err != nil {
		return
	}

	result, err = alg.Encrypt(input)
	if err != nil {
		return
	}

	err = write(cfg, true, result)
	return
}
