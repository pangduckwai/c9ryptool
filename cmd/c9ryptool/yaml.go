package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func yamlEncrypt(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	ecd encodes.Encoding,
) (err error) {
	var buf, key, input, output, salt, iv, aad []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][INP]%v", err)
		return
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == cfgs.PWD_INTERACTIVE {
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
		if !alg.Type() {
			err = utils.Write(cfg.Key, alg.GetKey())
		} else {
			err = utils.Write(cfg.Key, []byte(ecd.Encode(alg.GetKey())))
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
		if !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = ecd.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[YAML][ECY][DCD]%v", err)
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
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][ECY][AAD]%v", err)
			return
		}
	}

	encrypt := func(inp string) (out string, err error) {
		enc, err := alg.Encrypt([]byte(inp), iv, aad)
		if err != nil {
			return
		}
		out = ecd.Encode(enc)
		return
	}

	inp := make([]yaml.MapItem, 0)
	err = yaml.Unmarshal(input, &inp)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][UNM]%v", err)
		return
	}

	// sec := make(map[string]interface{})
	sec, err := utils.Traverse(inp, encrypt)
	if err != nil {
		err = fmt.Errorf("[YAML][ECY][NAV]%v", err)
		return
	}

	if salt != nil {
		sec = append(sec, yaml.MapItem{Key: "salt", Value: ecd.Encode(salt)}) // TODO name of "salt"
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
	ecd encodes.Encoding,
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
			salt, err = ecd.Decode(itm.Value.(string))
			inp = append(inp[:i], inp[i+1:]...)
			break
		}
	}

	if cfg.Passwd != "" {
		pwd := cfg.Passwd
		if cfg.Passwd == cfgs.PWD_INTERACTIVE {
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
		// not allowed
	} else {
		key, err = utils.Read(cfg.Key, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][KEY]%v", err)
			return
		}
		if !alg.Type() {
			err = alg.PopulateKey(key)
		} else {
			buf, err = ecd.Decode(string(key))
			if err != nil {
				err = fmt.Errorf("[YAML][DCY][DCD]%v", err)
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
	}

	if cfg.Tag != "" {
		tag, err = utils.Read(cfg.Tag, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][TAG]%v", err)
			return
		}
	}

	if cfg.Aad != "" {
		aad, err = utils.Read(cfg.Aad, cfg.Buffer, cfg.Verbose)
		if err != nil {
			err = fmt.Errorf("[YAML][DCY][AAD]%v", err)
			return
		}
	}

	decrypt := func(inp string) (out string, err error) {
		enc, err := ecd.Decode(inp)
		if err != nil {
			return
		}
		var dec []byte
		dec, err = alg.Decrypt(enc, iv, tag, aad)
		if err != nil {
			return
		}
		out = string(dec)
		return
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
