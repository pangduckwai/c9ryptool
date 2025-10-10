package main

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/cfgs"
	"sea9.org/go/cryptool/pkg/encrypts"
	"sea9.org/go/cryptool/pkg/utils"
)

func export(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
) (err error) {
	var key []byte

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

	err = utils.Write(cfg.Output, false, alg.PubKey())
	return
}
