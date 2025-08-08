package cryptool

import (
	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/algs/sym"
	"sea9.org/go/cryptool/pkg/cfgs"
)

func Encrypt(
	cfg *cfgs.Config,
	alg algs.Algorithm,
) (err error) {
	var key, input, result []byte

	input, err = read(cfg.Input, cfg.Buffer, false, cfg.Verbose)
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
		err = alg.PopulateKey(nil)
		if err != nil {
			return
		}
		err = write(cfg.Key, true, alg.Key())
		if err != nil {
			return
		}
	} else {
		key, err = read(cfg.Key, cfg.Buffer, true, cfg.Verbose)
		if err != nil {
			return
		}
		err = alg.PopulateKey(key)
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
	err = write(cfg.Output, true, result)
	return
}
