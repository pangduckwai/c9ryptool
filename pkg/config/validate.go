package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sea9.org/go/cryptool/pkg/algorithm"
	"sea9.org/go/cryptool/pkg/algorithm/sym"
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
			return
		}
	}

	if cfg.Output != "" {
		if _, err = os.Stat(cfg.Output); err == nil {
			errs = append(errs, fmt.Errorf("output file '%v' already exists", cfg.Output))
		} else if !errors.Is(err, os.ErrNotExist) {
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
			return
		} else if cfg.Genkey {
			errs = append(errs, fmt.Errorf("key file '%v' already exists", cfg.Key))
		}
	} else if !cfg.Passwd {
		errs = append(errs, fmt.Errorf("encryption key filename missing")) // > go run ./cmd/cryptool e|d {-g} -i README.md
	}

	if cfg.Command == 1 {
		if cfg.Genkey {
			errs = append(errs, fmt.Errorf("cannot generate new key for decryption")) // > cryptool d -g {-k key.txt} -i README.md
		} else if cfg.Passwd && cfg.Salt == "" {
			var okay bool
			if okay, err = sym.SaltFileExists(cfg.SaltFile); !okay || err != nil {
				errs = append(errs, fmt.Errorf("password salt file missing for decryption")) // > cryptool d -p -i README.md (when salt.txt not exists)
			}
		}
	}

	if cfg.Passwd {
		typ = 1 // must be symmetric algorithm if encryption key is generated from a passphrase
	}

	if err = algorithm.Validate(cfg.Algr, typ); err != nil {
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
