package cryptool

import (
	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/algs/sym"
	"sea9.org/go/cryptool/pkg/cfgs"
)

func Decrypt(
	cfg *cfgs.Config,
	alg algs.Algorithm,
) (err error) {
	var input, result []byte

	input, err = read(cfg, true)
	if err != nil {
		return
	}

	var salt []byte
	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			cfgs.Desc(),
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

	if salt != nil {
		result, err = alg.Decrypt(input[:len(input)-len(salt)-1])
	} else {
		result, err = alg.Decrypt(input)
	}
	if err != nil {
		return
	}

	err = write(cfg, false, result)
	return
}
