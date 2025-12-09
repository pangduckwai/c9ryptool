package main

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func encrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key, input, result, salt, iv, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
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
		err = utils.Write(cfg.Key, alg.Key())
		if err != nil {
			return
		}
	} else {
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
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

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[ECY][IV]%v", err)
			return
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[ECY][AAD]%v", err)
			return
		}
	}

	result, err = alg.Encrypt(input, iv, aad)
	if err != nil {
		err = fmt.Errorf("[ECY]%v", err)
		return
	}

	if salt != nil {
		result = append(result, salt...)
	}
	err = utils.Write(cfg.Output, result)
	if err != nil {
		err = fmt.Errorf("[ECY][OUT]%v", err)
	}
	return
}

func decrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key, input, result, salt, iv, tag, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
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
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
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

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][IV]%v", err)
			return
		}
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][TAG]%v", err)
			return
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][AAD]%v", err)
			return
		}
	}

	if salt != nil {
		result, err = alg.Decrypt(input[:len(input)-len(salt)], iv, tag, aad)
	} else {
		result, err = alg.Decrypt(input, iv, tag, aad)
	}
	if err != nil {
		err = fmt.Errorf("[DCY]%v", err)
		return
	}

	err = utils.Write(cfg.Output, result)
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
