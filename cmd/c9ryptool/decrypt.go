package main

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/cryptool"
	"sea9.org/go/cryptool/pkg/encrypts"
	"sea9.org/go/cryptool/pkg/encrypts/sym"
)

func decrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key, input, result, salt []byte

	input, err = cryptool.Read(cfg.Input, cfg.Buffer, true, cfg.Verbose)
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
		key, err = cryptool.Read(cfg.Key, cfg.Buffer, false, cfg.Verbose)
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
		result, err = alg.Decrypt(input[:len(input)-len(salt)-1], cfg.Iv)
	} else {
		result, err = alg.Decrypt(input, cfg.Iv)
	}
	if err != nil {
		err = fmt.Errorf("[DCY]%v", err)
		return
	}

	err = cryptool.Write(cfg.Output, false, result)
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
