package crypt

import (
	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/algorithm/sym"
	"sea9.org/go/cryptool/pkg/config"
)

func Decrypt(
	cfg *config.Config,
	alg algorithm.Algorithm,
) (err error) {
	var input, result []byte

	input, err = read(cfg, true)
	if err != nil {
		return
	}

	var salt []byte
	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			config.Desc(),
			input,
			alg.KeyLength(), cfg.SaltLen,
			alg.PopulateKey,
		)
		if err != nil {
			return
		}
	} else if cfg.Genkey {
		err = alg.PopulateKey(0, cfg.Key)
		if err != nil {
			return
		}
	} else {
		err = alg.PopulateKey(1, cfg.Key)
		if err != nil {
			return
		}
	}

	result, err = alg.Decrypt(input[:len(input)-len(salt)-1])
	if err != nil {
		return
	}

	err = write(cfg, false, result)
	return
}
