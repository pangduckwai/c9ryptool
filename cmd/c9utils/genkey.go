package main

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/utils"
)

func genkey(
	cfg *cfgs.Config,
	alg encrypts.Algorithm,
	ecd encodes.Encoding,
) (err error) {
	err = alg.PopulateKey(nil)
	if err != nil {
		err = fmt.Errorf("[GENKEY][POP]%v", err)
		return
	}

	if ecd == nil || !alg.Type() { // since asymmetric keys uses PEM encoding
		err = utils.Write(cfg.Output, alg.GetKey())
	} else {
		err = utils.Write(cfg.Output, []byte(ecd.Encode(alg.GetKey())))
	}
	if err != nil {
		err = fmt.Errorf("[GENKEY][KEY]%v", err)
		return
	}

	if !alg.Type() && cfg.Key != "" {
		if aslg, ok := alg.(encrypts.AsymAlgorithm); ok {
			err = utils.Write(cfg.Key, aslg.GetPublicKey())
			if err != nil {
				err = fmt.Errorf("[GENKEY][PUB]%v", err)
			}
		} else {
			err = fmt.Errorf("[GENKEY][PUB] casting '%v' to asymmetric algorithm failed", alg.Name())
		}
	}
	return
}
