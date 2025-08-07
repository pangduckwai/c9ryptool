package cryptool

import (
	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/algs/sym"
	cfgs "sea9.org/go/cryptool/pkg/cfgs"
)

func Encrypt(
	cfg *cfgs.Config,
	alg algs.Algorithm,
) (err error) {
	var input, result []byte

	input, err = read(cfg, false)
	if err != nil {
		return
	}

	var salt []byte
	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			cfgs.Desc(),
			nil,
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

	result, err = alg.Encrypt(input)
	if err != nil {
		return
	}

	if salt != nil {
		result = append(result, '.')
		result = append(result, salt...)
	}
	err = write(cfg, true, result)
	return
}
