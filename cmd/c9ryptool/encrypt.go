package main

import (
	"fmt"
	"time"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func encrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eci, eco, eck, ecv, eca, zip encodes.Encoding,
) (err error) {
	var results [][]byte
	var key, input, result, salt, iv, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, eci, zip) // decode, then zip before encrypt
	if err != nil {
		err = fmt.Errorf("[ECY][INP]%v", err)
		return
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == PWD_INTERACTIVE {
			hdr := ""
			if cfg.Verbose {
				hdr = fmt.Sprintf("%v [%v]", time.Now().Format(LOG_FRM_MILLI), desc())
			}
			pwd, err = utils.Prompt(hdr, "Enter password: ")
		}
		salt, err = sym.PopulateKeyFromPassword(
			pwd,
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
		if eck == nil || !alg.Type() { // since asymmetric keys uses PEM encoding
			err = utils.Write(cfg.Key, alg.GetKey())
		} else {
			err = utils.Write(cfg.Key, alg.GetKey(), eck)
		}
		if err != nil {
			return
		}
	} else {
		if eck == nil || !alg.Type() {
			key, err = utils.Read(cfg.Key, cfg.Buffer)
			if err != nil {
				err = fmt.Errorf("[ECY][KEY]%v", err)
				return
			}
		} else {
			key, err = utils.Read(cfg.Key, cfg.Buffer, eck)
			if err != nil {
				err = fmt.Errorf("[ECY][KEY]%v", err)
				return
			}
		}
		err = alg.PopulateKey(key)
		if err != nil {
			err = fmt.Errorf("[ECY][POP]%v", err)
			return
		}
	}

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, ecv)
		if err != nil {
			err = fmt.Errorf("[ECY][IV]%v", err)
			return
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, eca)
		if err != nil {
			err = fmt.Errorf("[ECY][AAD]%v", err)
			return
		}
	}

	results, err = alg.Encrypt(input, iv, aad)
	if err != nil {
		err = fmt.Errorf("[ECY]%v", err)
		return
	} else if len(results) < 1 || results[0] == nil {
		err = fmt.Errorf("[ECY] result missing")
		return
	}

	result = results[0]
	if salt != nil {
		result = append(result, salt...)
	}
	err = utils.Write(cfg.Output, result, eco)
	if err != nil {
		err = fmt.Errorf("[ECY][OUT]%v", err)
	}
	return
}

func decrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eci, eco, eck, ecv, ect, eca, unzip encodes.Encoding,
) (err error) {
	var results [][]byte
	var key, input, result, salt, iv, tag, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, eci)
	if err != nil {
		err = fmt.Errorf("[DCY][INP]%v", err)
		return
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == PWD_INTERACTIVE {
			hdr := ""
			if cfg.Verbose {
				hdr = fmt.Sprintf("%v [%v]", time.Now().Format(LOG_FRM_MILLI), desc())
			}
			pwd, err = utils.Prompt(hdr, "Enter password: ")
		}
		salt, err = sym.PopulateKeyFromPassword(
			pwd,
			input,
			alg.KeyLength(), cfg.SaltLen,
			alg.PopulateKey,
		)
		if err != nil {
			err = fmt.Errorf("[DCY][PWD]%v", err)
			return
		}
	} else if cfg.Genkey {
		err = fmt.Errorf("[DCY][GEN] generate new key for decryption makes no sense")
		return
	} else {
		if eck == nil || !alg.Type() {
			key, err = utils.Read(cfg.Key, cfg.Buffer)
			if err != nil {
				err = fmt.Errorf("[DCY][KEY]%v", err)
				return
			}
		} else {
			key, err = utils.Read(cfg.Key, cfg.Buffer, eck)
			if err != nil {
				err = fmt.Errorf("[DCY][KEY]%v", err)
				return
			}
		}
		err = alg.PopulateKey(key)
		if err != nil {
			err = fmt.Errorf("[DCY][POP]%v", err)
			return
		}
	}

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, ecv)
		if err != nil {
			err = fmt.Errorf("[DCY][IV]%v", err)
			return
		}
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, ect)
		if err != nil {
			err = fmt.Errorf("[DCY][TAG]%v", err)
			return
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, eca)
		if err != nil {
			err = fmt.Errorf("[DCY][AAD]%v", err)
			return
		}
	}

	if salt != nil {
		results, err = alg.Decrypt(input[:len(input)-len(salt)], iv, tag, aad)
	} else {
		results, err = alg.Decrypt(input, iv, tag, aad)
	}
	if err != nil {
		err = fmt.Errorf("[DCY]%v", err)
		return
	} else if len(results) < 1 || results[0] == nil {
		err = fmt.Errorf("[DCY] result missing")
		return
	}

	result = results[0]
	err = utils.Write(cfg.Output, result, unzip, eco)
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
