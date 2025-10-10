package main

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/encrypts"
	"sea9.org/go/cryptool/pkg/encrypts/sym"
	"sea9.org/go/cryptool/pkg/utils"
)

func encrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key, input, result, salt []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, false, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[ECY][INP]%v", err)
		return
	}

	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			desc(),
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
		err = utils.Write(cfg.Key, false, alg.Key())
		if err != nil {
			return
		}
	} else {
		key, err = utils.Read(cfg.Key, cfg.Buffer, false, cfg.Verbose)
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

	result, err = alg.Encrypt(input, cfg.Iv)
	if err != nil {
		err = fmt.Errorf("[ECY]%v", err)
		return
	}

	if salt != nil {
		result = append(result, salt...)
	}
	err = utils.Write(cfg.Output, true, result)
	if err != nil {
		err = fmt.Errorf("[ECY][OUT]%v", err)
	}
	return
}

func decrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key, input, result, salt []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, true, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[DCY][INP]%v", err)
		return
	}

	if cfg.Passwd {
		salt, err = sym.PopulateKeyFromPassword(
			desc(),
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
		key, err = utils.Read(cfg.Key, cfg.Buffer, false, cfg.Verbose)
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
		result, err = alg.Decrypt(input[:len(input)-len(salt)], cfg.Iv)
	} else {
		result, err = alg.Decrypt(input, cfg.Iv)
	}
	if err != nil {
		err = fmt.Errorf("[DCY]%v", err)
		return
	}

	err = utils.Write(cfg.Output, false, result)
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
