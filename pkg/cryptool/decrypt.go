package cryptool

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/algs"
	"sea9.org/go/cryptool/pkg/algs/sym"
	"sea9.org/go/cryptool/pkg/cfgs"
)

func Decrypt(
	cfg *cfgs.Config,
	alg algs.Algorithm,
) (err error) {
	var key, input, result, salt []byte

	input, err = read(cfg.Input, cfg.Buffer, true, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[DCY][INP]%v", err)
		return
	}

	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			cfgs.Desc(),
			input,
			alg.KeyLength(), cfg.SaltLen,
			alg.PopulateKey,
		)
		if err != nil {
			err = fmt.Errorf("[DCY][PWD]%v", err)
			return
		}
	} else if cfg.Genkey {
		// not allowed
	} else {
		key, err = read(cfg.Key, cfg.Buffer, alg.Type(), cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][KEY]%v", err)
			return
		}
		err = alg.PopulateKey(key)
		if err != nil {
			err = fmt.Errorf("[DCY][POP]%v", err)
			return
		}
	}

	if salt != nil {
		result, err = alg.Decrypt(input[:len(input)-len(salt)-1])
	} else {
		result, err = alg.Decrypt(input)
	}
	if err != nil {
		err = fmt.Errorf("[DCY]%v", err)
		return
	}

	err = write(cfg.Output, false, result)
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
