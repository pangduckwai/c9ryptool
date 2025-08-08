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
	var key, input, result []byte

	input, err = read(cfg.Input, cfg.Buffer, true, cfg.Verbose)
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
		// err = alg.PopulateKey(nil)
		// if err != nil {
		// 	return
		// }
		// TODO Not supported!!!!!!!!!!!!!
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

	if salt != nil {
		result, err = alg.Decrypt(input[:len(input)-len(salt)-1])
	} else {
		result, err = alg.Decrypt(input)
	}
	if err != nil {
		return
	}

	err = write(cfg.Output, false, result)
	return
}
