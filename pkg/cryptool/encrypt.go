package cryptool

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/algs/sym"
	"sea9.org/go/cryptool/pkg/cfgs"
)

func Encrypt(
	cfg *cfgs.Config,
	alg algs.Algorithm,
) (err error) {
	var key, input, result, salt []byte

	input, err = read(cfg.Input, cfg.Buffer, false, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[ECY][INP]%v", err)
		return
	}

	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			cfgs.Desc(),
			nil,
			alg.KeyLength(), cfg.SaltLen,
			alg.PopulateKey,
		)
		if err != nil {
			err = fmt.Errorf("[ECY][PWD]%v", err)
			return
		}
	} else if cfg.Genkey {
		err = alg.PopulateKey(nil)
		if err != nil {
			err = fmt.Errorf("[ECY][GEN]%v", err)
			return
		}
		err = write(cfg.Key, alg.Type(), alg.Key())
		if err != nil {
			return
		}
	} else {
		key, err = read(cfg.Key, cfg.Buffer, alg.Type(), cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[ECY][KEY]%v", err)
			return
		}
		err = alg.PopulateKey(key)
		if err != nil {
			err = fmt.Errorf("[ECY][POP]%v", err)
			return
		}
	}

	result, err = alg.Encrypt(input)
	if err != nil {
		err = fmt.Errorf("[ECY]%v", err)
		return
	}

	if salt != nil {
		result = append(result, '.')
		result = append(result, salt...)
	}
	err = write(cfg.Output, true, result)
	if err != nil {
		err = fmt.Errorf("[ECY][OUT]%v", err)
	}
	return
}
