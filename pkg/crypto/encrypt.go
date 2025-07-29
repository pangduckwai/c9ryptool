package crypto

import (
	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/config"
)

func Encrypt(
	cfg *config.Config,
	alg *algorithm.Algorithm,
	key []byte,
) (err error) {
	var input, result []byte

	input, err = read(cfg, false)
	if err != nil {
		return
	}

	result, err = alg.Encrypt(key, input)
	if err != nil {
		return
	}

	err = write(cfg, true, result)
	return
}
