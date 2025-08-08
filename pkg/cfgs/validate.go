package cfgs

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sea9.org/go/cryptool/pkg/algs"
)

// Validate validate parameters.
// - Input : not given means input from stdin, file not exist is an error
// - Output : not given means output to stdout, file exist is an error
// - Key : mutally exclusive with 'Passwd' (key from passphrase), file not exist is an error unless 'Genkey' (gen new key) is specified
// - Passwd : mutally exclusive with 'Genkey' (gen new key), generate encryption key from a passphrase which is input interactively
// - Algr : encryption algorithm name
func Validate(cfg *Config) (err error) {
	var typ int
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

	if cfg.Passwd && cfg.Genkey {
		err = fmt.Errorf("[VLDT] incompatable options '-g' and '-p'") // > cryptool e|d -p -g -i README.md
		return
	}

	if cfg.Key != "" {
		if cfg.Passwd {
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
	} else if !cfg.Passwd {
		errs = append(errs, fmt.Errorf("encryption key filename missing")) // > go run ./cmd/cryptool e|d {-g} -i README.md
	}

	if cfg.Command == 1 && cfg.Genkey {
		errs = append(errs, fmt.Errorf("cannot generate new key for decryption")) // > cryptool d -g {-k key.txt} -i README.md
	}

	if cfg.Passwd {
		typ = 1 // must be symmetric algorithm if encryption key is generated from a passphrase
	}

	if err = algs.Validate(cfg.Algr, typ); err != nil {
		errs = append(errs, err)
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
