package main

import (
	"fmt"
	"strconv"

	"gopkg.in/yaml.v2"
	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

// yamlEncrypt yaml input is printable, so don't need input encoding. but IV and AAG may need encoding so use output encoding in these cases.
func yamlEncrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eco, eck encodes.Encoding,
) (err error) {
	var buf, key, input, output, salt, iv, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][INP]%v", err)
		return
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
			err = fmt.Errorf("[YAML][ECY][PWD]%v", err)
			return
		}
	} else if cfg.Genkey {
		err = alg.PopulateKey(nil)
		if err != nil {
			err = fmt.Errorf("[YAML][ECY][GEN]%v", err)
			return
		}
		if eck == nil || !alg.Type() {
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
			err = fmt.Errorf("[YAML][ECY][KEY]%v", err)
			return
		}
		if eck == nil || !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = eck.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[YAML][ECY][POP][DCD]%v", err)
				return
			}
			err = alg.PopulateKey(buf)
		}
		if err != nil {
			err = fmt.Errorf("[YAML][ECY][POP]%v", err)
			return
		}
	}

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][ECY][IV]%v", err)
			return
		}
		if eco != nil {
			iv, err = eco.Decode(string(iv))
			if err != nil {
				err = fmt.Errorf("[YAML][ECY][IV][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][ECY][AAD]%v", err)
			return
		}
		if eco != nil {
			aad, err = eco.Decode(string(aad))
			if err != nil {
				err = fmt.Errorf("[YAML][ECY][AAD][DCD]%v", err)
				return
			}
		}
	}

	encrypt := func(inp interface{}) (interface{}, error) {
		switch typ := inp.(type) {
		case string:
			enc, err := alg.Encrypt([]byte(typ), iv, aad)
			if err != nil {
				return nil, err
			}
			return eco.Encode(enc), nil
		case int:
			enc, err := alg.Encrypt([]byte(fmt.Sprintf("%v", typ)), iv, aad)
			if err != nil {
				return nil, err
			}
			return eco.Encode(enc), nil
		case bool:
			enc, err := alg.Encrypt([]byte(fmt.Sprintf("%v", typ)), iv, aad)
			if err != nil {
				return nil, err
			}
			return eco.Encode(enc), nil
		default:
			return inp, nil
		}
	}

	inp := make([]yaml.MapItem, 0)
	err = yaml.Unmarshal(input, &inp)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][UNM]%v", err)
		return
	}

	sec, err := utils.Traverse(inp, encrypt)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][NAV]%v", err)
		return
	}

	if salt != nil {
		sec = append(sec, yaml.MapItem{Key: "salt", Value: eco.Encode(salt)}) // TODO name of "salt"
	}

	output, err = yaml.Marshal(sec)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][MRS]%v", err)
		return
	}

	err = utils.Write(cfg.Output, output)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][OUT]%v", err)
	}
	return
}

func yamlDecrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	eci, eck encodes.Encoding,
) (err error) {
	var buf, key, input, output, salt, iv, tag, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[YAML][DCY][INP]%v", err)
		return
	}

	inp := make([]yaml.MapItem, 0)
	err = yaml.Unmarshal(input, &inp)
	if err != nil {
		err = fmt.Errorf("[YAML][DCY][UNM]%v", err)
		return
	}

	for i, itm := range inp {
		if itm.Key.(string) == "salt" { // TODO name of "salt"
			salt, err = eci.Decode(itm.Value.(string))
			inp = append(inp[:i], inp[i+1:]...)
			break
		}
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == PWD_INTERACTIVE {
			pwd, err = utils.InteractiveSingle(desc(), "Enter password: ")
		}
		_, err = sym.PopulateKeyFromPassword(
			pwd,
			salt,
			alg.KeyLength(), cfg.SaltLen,
			alg.PopulateKey,
		)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][PWD]%v", err)
			return
		}
	} else if cfg.Genkey {
		err = fmt.Errorf("[YAML][DCY][GEN] generate new key for decryption makes no sense")
		return
	} else {
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][KEY]%v", err)
			return
		}
		if eck == nil || !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = eck.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[YAML][DCY][POP][DCD]%v", err)
				return
			}
			err = alg.PopulateKey(buf)
		}
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][POP]%v", err)
			return
		}
	}

	if cfg.Iv != "" {
		iv, err = utils.Read(cfg.Iv, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][IV]%v", err)
			return
		}
		if eci != nil {
			iv, err = eci.Decode(string(iv))
			if err != nil {
				err = fmt.Errorf("[YAML][DCY][IV][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][TAG]%v", err)
			return
		}
		if eci != nil {
			tag, err = eci.Decode(string(tag))
			if err != nil {
				err = fmt.Errorf("[YAML][DCY][TAG][DCD]%v", err)
				return
			}
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][AAD]%v", err)
			return
		}
		if eci != nil {
			aad, err = eci.Decode(string(aad))
			if err != nil {
				err = fmt.Errorf("[YAML][DCY][AAD][DCD]%v", err)
				return
			}
		}
	}

	decrypt := func(inp interface{}) (interface{}, error) {
		switch typ := inp.(type) {
		case string:
			enc, err := eci.Decode(typ)
			if err != nil {
				return nil, err
			}
			dec, err := alg.Decrypt(enc, iv, tag, aad)
			if err != nil {
				return nil, err
			}

			str := string(dec)
			v0, err := strconv.Atoi(str)
			if err == nil {
				return v0, nil
			}
			v1, err := strconv.ParseBool(str)
			if err == nil {
				return v1, nil
			}

			return str, nil
		default:
			return inp, nil
		}
	}

	clr, err := utils.Traverse(inp, decrypt)
	if err != nil {
		err = fmt.Errorf("[YAML][DCY][NAV]%v", err)
		return
	}

	output, err = yaml.Marshal(clr)
	if err != nil {
		err = fmt.Errorf("[YAML][DCY][MRS]%v", err)
		return
	}

	err = utils.Write(cfg.Output, output)
	if err != nil {
		err = fmt.Errorf("[YAML][DCY][OUT]%v", err)
	}
	return
}
