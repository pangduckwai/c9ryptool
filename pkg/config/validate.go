package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sea9.org/go/cryptool/pkg/algorithm"
)

// Validate validate parameters.
// - Input : not given means input from stdin, file not exist is an error
// - Output : not given means output to stdout, file exist is an error
// - Key : mutally exclusive with 'key from passphrase', file not exist is an error unless 'gen new key' is specified
func Validate(cfg *Config) (err error) {
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

	if cfg.Key != "" {
		if cfg.Passwd {
			err = fmt.Errorf("[VLDT] incompatable options")
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
		errs = append(errs, fmt.Errorf("encryption key filename missing"))
	}

	if err = algorithm.Validate(cfg.Algr); err != nil {
		errs = append(errs, err)
	}

	if cfg.Command == 1 && cfg.Genkey {
		errs = append(errs, fmt.Errorf("cannot generate new key for decryption"))
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
