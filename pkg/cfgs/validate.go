package cfgs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
	"sea9.org/go/c9ryptool/pkg/hashes"
	"sea9.org/go/c9ryptool/pkg/utils"
)

// Validate validate parameters.
// - Input : not given means input from stdin, file not exist is an error
// - Output : not given means output to stdout, file exist is an error
// - Key : mutally exclusive with 'Passwd' (key from passphrase), file not exist is an error unless 'Genkey' (gen new key) is specified
// - Passwd : mutally exclusive with 'Genkey' (gen new key), generate encryption key from a passphrase which is input interactively
// - Algr : encryption algorithm name
func Validate(cfg *Config) (err error) {
	errs := make([]error, 0)

	if cfg.Input != "" {
		if _, err = os.Stat(cfg.Input); errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("input file '%v' does not exist", cfg.Input))
		} else if err != nil {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		}
	}

	if cfg.Output != "" {
		if _, err = os.Stat(cfg.Output); err == nil {
			errs = append(errs, fmt.Errorf("output file '%v' already exists", cfg.Output))
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		}
	}

	switch cfg.Command() {
	case CMD_ENCRYPT:
		if cfg.IsList() {
			break
		}
		if cfg.Tag != "" {
			err = fmt.Errorf("[VLDT] unsupported option '--tag'")
		}
		fallthrough
	case CMD_DECRYPT:
		if cfg.IsList() {
			break
		}

		if cfg.Passwd != "" && cfg.Genkey {
			err = fmt.Errorf("[VLDT] incompatable options '-g' and '-p'") // > c9ryptool e|d -p -g -i README.md
			return
		}

		if cfg.Key != "" {
			if cfg.Passwd != "" {
				err = fmt.Errorf("[VLDT] incompatable options '-k' and '-p'")
				return
			}
			if _, err = os.Stat(cfg.Key); errors.Is(err, os.ErrNotExist) {
				if !cfg.Genkey {
					errs = append(errs, fmt.Errorf("key file '%v' does not exist", cfg.Key))
				}
			} else if err != nil {
				err = fmt.Errorf("[VLDT] %v", err)
				return
			} else if cfg.Genkey {
				errs = append(errs, fmt.Errorf("key file '%v' already exists", cfg.Key))
			}
		} else if cfg.Passwd == "" {
			errs = append(errs, fmt.Errorf("encryption key filename missing")) // > go run ./cmd/c9ryptool e|d {-g} -i README.md
		}

		if cfg.Command() == CMD_DECRYPT && cfg.Genkey {
			errs = append(errs, fmt.Errorf("cannot generate new key for decryption")) // > c9ryptool d -g {-k key.txt} -i README.md
		}

		var typ int
		if cfg.Passwd != "" || cfg.Iv != "" || cfg.Tag != "" || cfg.Aad != "" {
			// must be symmetric algorithm if:
			// 1. encryption key is generated from a passphrase
			// 2. IV is given
			typ = 1
		}

		if err = encrypts.Validate(cfg.Algr, typ); err != nil {
			errs = append(errs, err)
		}

	case CMD_ENCODE:
		fallthrough
	case CMD_DECODE:
		if cfg.IsList() {
			break
		}
		if err = encodes.Validate(cfg.Encd); err != nil {
			errs = append(errs, err)
		}

	case CMD_DISPLAY:
		if cfg.Encd != "" {
			err = encodes.Validate(cfg.Encd)
		}

	case CMD_HASHING:
		if cfg.IsList() {
			break
		}
		if err = hashes.Validate(cfg.Hash); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		var buf strings.Builder
		fmt.Fprintf(&buf, "[\n - %v", errs[0])
		for _, err := range errs[1:] {
			fmt.Fprintf(&buf, "\n - %v", err)
		}
		err = fmt.Errorf("[VLDT]%v\n]", buf.String())
	}
	return
}

func cmdMatch(inp string) (idx int, mth string, err error) {
	indices, str, typ := utils.BestMatch(inp, COMMANDS, false)
	switch len(indices) {
	case 0:
		idx = -1
	case 1:
		idx = indices[0]
		mth = str
	default:
		ms := make([]string, 0)
		for x := range indices {
			ms = append(ms, COMMANDS[indices[x]])
		}
		if typ == 1 {
			idx = -3
		} else {
			idx = -2
		}
		err = fmt.Errorf("'%v' ambiguously matched to %v", inp, ms)
	}
	return
}
