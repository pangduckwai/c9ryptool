package main

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func pubkey(
	cfg *cfgs.Config,
	alg encrypts.AsymAlgorithm,
) (err error) {
	var input []byte

	input, err = utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[PUBKEY][INP]%v", err)
		return
	}

	err = alg.PopulateKey(input)
	if err != nil {
		err = fmt.Errorf("[PUBKEY][POP]%v", err)
		return
	}

	err = utils.Write(cfg.Output, alg.GetPublicKey()) // since asymmetric keys uses PEM encoding
	if err != nil {
		err = fmt.Errorf("[PUBKEY][OUT]%v", err)
	}
	return
}
