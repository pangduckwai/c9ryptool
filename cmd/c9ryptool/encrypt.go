package main

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func encrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eci, eco, eck, ecv, ect, eca encodes.Encoding,
) (err error) {
	var buf, key, input, result, salt, iv, tag, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[ECY][INP]%v", err)
		return
	}
	if eci != nil {
		input, err = eci.Decode(string(input))
		if err != nil {
			err = fmt.Errorf("[ECY][INP][DCD]%v", err)
			return
		}
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == PWD_INTERACTIVE {
			pwd, err = utils.InteractiveSingle(desc(), "Enter password: ")
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
			err = utils.Write(cfg.Key, []byte(eck.Encode(alg.GetKey())))
		}
		if err != nil {
			return
		}
	} else {
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[ECY][KEY]%v", err)
			return
		}
		if eck == nil || !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = eck.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[ECY][POP][DCD]%v", err)
				return
			}
			err = alg.PopulateKey(buf)
		}
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
		if ecv != nil {
			iv, err = ecv.Decode(string(iv))
			if err != nil {
				err = fmt.Errorf("[ECY][IV][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][TAG]%v", err)
			return
		}
		if ect != nil {
			tag, err = ect.Decode(string(tag))
			if err != nil {
				err = fmt.Errorf("[DCY][TAG][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[ECY][AAD]%v", err)
			return
		}
		if eca != nil {
			aad, err = eca.Decode(string(aad))
			if err != nil {
				err = fmt.Errorf("[ECY][AAD][DCD]%v", err)
				return
			}
		}
	}

	result, err = alg.Encrypt(input, iv, tag, aad)
	if err != nil {
		err = fmt.Errorf("[ECY]%v", err)
		return
	}

	if salt != nil {
		result = append(result, salt...)
	}
	if eco == nil {
		err = utils.Write(cfg.Output, result)
	} else {
		err = utils.Write(cfg.Output, []byte(eco.Encode(result)))
	}
	if err != nil {
		err = fmt.Errorf("[ECY][OUT]%v", err)
	}
	return
}

func decrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eci, eco, eck, ecv, ect, eca encodes.Encoding,
) (err error) {
	var buf, key, input, result, salt, iv, tag, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[DCY][INP]%v", err)
		return
	}
	if eci != nil {
		input, err = eci.Decode(string(input))
		if err != nil {
			err = fmt.Errorf("[DCY][INP][DCD]%v", err)
			return
		}
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == PWD_INTERACTIVE {
			pwd, err = utils.InteractiveSingle(desc(), "Enter password: ")
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
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][KEY]%v", err)
			return
		}
		if eck == nil || !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = eck.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[DCY][POP][DCD]%v", err)
				return
			}
			err = alg.PopulateKey(buf)
		}
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
		if ecv != nil {
			iv, err = ecv.Decode(string(iv))
			if err != nil {
				err = fmt.Errorf("[DCY][IV][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][TAG]%v", err)
			return
		}
		if ect != nil {
			tag, err = ect.Decode(string(tag))
			if err != nil {
				err = fmt.Errorf("[DCY][TAG][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[DCY][AAD]%v", err)
			return
		}
		if eca != nil {
			aad, err = eca.Decode(string(aad))
			if err != nil {
				err = fmt.Errorf("[DCY][AAD][DCD]%v", err)
				return
			}
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

	if eco == nil {
		err = utils.Write(cfg.Output, result)
	} else {
		err = utils.Write(cfg.Output, []byte(eco.Encode(result)))
	}
	if err != nil {
		err = fmt.Errorf("[DCY][OUT]%v", err)
	}
	return
}
