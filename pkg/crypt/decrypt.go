package crypt

import (
	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/config"
)

func Decrypt(
	cfg *config.Config,
	alg *algorithm.Algorithm,
	key []byte,
) (err error) {
	var input, result []byte

	input, err = read(cfg, true)
	if err != nil {
		return
	}

	result, err = alg.Decrypt(key, input)
	if err != nil {
		return
	}

	err = write(cfg, false, result)
	return
}
