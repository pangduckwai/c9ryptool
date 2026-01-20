package main

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func split(
	cfg *cfgs.Config,
) (err error) {
	input, err := utils.Read(cfg.Input, cfg.Buffer, cfg.Verbose)
	if err != nil {
		err = fmt.Errorf("[SPLIT][INP]%v", err)
		return
	}

	lgth := cfg.SaltLen
	if lgth < 0 {
		lgth = len(input) + lgth // counting backward
	}

	err = utils.Write(cfg.Output, input[:lgth])
	if err != nil {
		err = fmt.Errorf("[SPLIT][OUT0] %v", err)
		return
	}

	err = utils.Write(cfg.Key, input[lgth:])
	if err != nil {
		err = fmt.Errorf("[SPLIT][OUT1] %v", err)
	}
	return
}
