package cfgs

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"sea9.org/go/cryptool/pkg/encodes"
	"sea9.org/go/cryptool/pkg/encrypts"
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
		fallthrough
	case CMD_YAMLENC:
		if cfg.IsList() {
			break
		}
		if cfg.Tag != "" {
			err = fmt.Errorf("[VLDT] unsupported option '--tag'")
		}
		fallthrough
	case CMD_DECRYPT:
		fallthrough
	case CMD_YAMLDEC:
		if cfg.IsList() {
			break
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

		if cfg.Command() == CMD_DECRYPT && cfg.Genkey {
			errs = append(errs, fmt.Errorf("cannot generate new key for decryption")) // > cryptool d -g {-k key.txt} -i README.md
		}

		var typ int
		if cfg.Passwd || cfg.Iv != "" || cfg.Tag != "" || cfg.Aad != "" {
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

func cmdMatch(inp string) (int, string, error) {
	fltr := make([]int, 0)
	li := len(inp)

	for i, cmd := range COMMANDS {
		lc := len(cmd)
		if li == lc {
			if inp == cmd {
				fltr = append(fltr, i)
			}
		} else if li < lc {
			if strings.Contains(cmd, inp) {
				fltr = append(fltr, i)
			}
		}
	}

	lf := len(fltr)
	if lf == 1 {
		return fltr[0], COMMANDS[fltr[0]], nil
	} else if lf > 1 {
		ms := make([]string, 0)
		for x := range fltr {
			ms = append(ms, COMMANDS[fltr[x]])
		}
		return -3, "", fmt.Errorf("'%v' ambiguously matched to %v", inp, ms)
	} else {
		var pstr string
		for _, r := range inp {
			pstr = fmt.Sprintf("%v.*%c", pstr, r)
		}
		var pttn = regexp.MustCompile(fmt.Sprintf("%v.*", pstr))

		for i, cmd := range COMMANDS {
			if pttn.MatchString(cmd) {
				fltr = append(fltr, i)
			}
		}
		lf = len(fltr)
		if lf == 1 {
			return fltr[0], COMMANDS[fltr[0]], nil
		} else if lf > 1 {
			ms := make([]string, 0)
			for x := range fltr {
				ms = append(ms, COMMANDS[fltr[x]])
			}
			return -2, "", fmt.Errorf("\"%v\" ambiguously matched to %v", inp, ms)
		}
		return -1, "", nil
	}
}
