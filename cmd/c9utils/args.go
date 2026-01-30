package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/encrypts"
)

const CMD_VERSION = 1
const CMD_GENKEY = 2
const CMD_PUBKEY = 3
const CMD_SPLIT = 4

var COMMANDS = []string{
	"help",    // 0
	"version", // 1
	"genkey",  // 2
	"pubkey",  // 3
	"split",   // 4
}

var ENVIVARS = []string{
	"C9_BUFFER",
	"C9_VERBOSE",
	"C9_ALGORITHM",
	"C9_ENCODING",
}

func usage() string {
	return "Usage:\n c9utils\n" +
		"  [version]\n\n" +
		"  [genkey]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   [-o FILE | --out0=FILE]\n" +
		"   {-p FILE | --out1=FILE}\n" +
		"   {-n ENC | --encoding=ENC}\n" +
		"   {-l | --list}\n\n" +
		"  [pubkey]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   [-i FILE | --in=FILE]\n" +
		"   [-o FILE | --out=FILE]\n" +
		"   {-l | --list}\n\n" +
		"  [split]\n" +
		"   [-i FILE | --in=FILE]\n" +
		"   [-o FILE | --out0=FILE]\n" +
		"   [-p FILE | --out1=FILE]\n" +
		"   [-l LEN | --len=LEN]\n\n" +
		"  all commands\n" +
		"   {-b SIZE | --buffer=SIZE}\n" +
		"   {-v | --verbose}"
}

// parse parse command line arguments to populate a Config object
func parse(args []string) (cfg *cfgs.Config, err error) {
	if len(args) < 2 {
		err = fmt.Errorf("[CONF] Command missing")
		return
	}

	cfg = &cfgs.Config{
		Buffer:  cfgs.BUFFER,
		Verbose: false,
		Algr:    encrypts.Default(),
	}

	idx, _, err := cfgs.CommandMatch(COMMANDS, args[1])
	if err != nil {
		err = fmt.Errorf("[CONF] %v", err)
		return
	} else if idx < 0 {
		err = fmt.Errorf("[CONF] Invalid command '%v'", args[1])
		return
	}
	cfg.SetCommand(idx)

	var val, lgh int
	for _, enm := range ENVIVARS {
		env := os.Getenv(enm)
		if env != "" {
			switch enm {
			case "C9_BUFFER":
				val, err = strconv.Atoi(env)
				if err != nil {
					err = fmt.Errorf("[CONF] Invalid buffer size value in '%v'", enm)
					return
				}
				cfg.Buffer = val
			case "C9_VERBOSE":
				cfg.Verbose, err = strconv.ParseBool(env)
				if err != nil {
					err = fmt.Errorf("[CONF] Invalid verbose value in '%v'", enm)
					return
				}
			case "C9_ALGORITHM":
				cfg.Algr = env
			case "C9_ENCODING":
				cfg.Encd = env
			}
		}
	}

	for i := 2; i < len(args); i++ {
		lgh = 7
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
		case args[i] == "-l":
			if cfg.Command() == CMD_SPLIT {
				i++
				if i >= len(args) {
					err = fmt.Errorf("[CONF] Missing split length argument")
					return
				} else {
					val, err = strconv.Atoi(args[i])
					if err == nil {
						cfg.SaltLen = val // borrow salt length as split length
					}
				}
				continue
			}
			fallthrough
		case args[i] == "--list":
			cfg.SetList()
			i = len(args)
		case strings.HasPrefix(args[i], "--len="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing split length")
				return
			} else {
				val, err = strconv.Atoi(args[i][6:])
				if err == nil {
					cfg.SaltLen = val
				}
			}
		case args[i] == "-b":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing buffer size argument")
				return
			} else {
				val, err = strconv.Atoi(args[i])
				if err == nil {
					cfg.Buffer = val
				}
			}
		case strings.HasPrefix(args[i], "--buffer="):
			if len(args[i]) <= 9 {
				err = fmt.Errorf("[CONF] Missing buffer size")
				return
			} else {
				val, err = strconv.Atoi(args[i][9:])
				if err == nil {
					cfg.Buffer = val
				}
			}
		case args[i] == "-a":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing algorithm argument")
				return
			} else {
				cfg.Algr = args[i]
			}
		case strings.HasPrefix(args[i], "--algorithm="):
			if len(args[i]) <= 12 {
				err = fmt.Errorf("[CONF] Missing algorithm")
				return
			} else {
				cfg.Algr = args[i][12:]
			}
		case args[i] == "-n":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing encoding argument")
				return
			} else {
				cfg.Encd = args[i]
			}
		case strings.HasPrefix(args[i], "--encoding="):
			if len(args[i]) <= 11 {
				err = fmt.Errorf("[CONF] Missing encoding")
				return
			} else {
				cfg.Encd = args[i][11:]
			}
		case args[i] == "-i":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing input filename argument")
				return
			} else {
				cfg.Input = args[i]
			}
		case strings.HasPrefix(args[i], "--in="):
			if len(args[i]) <= 5 {
				err = fmt.Errorf("[CONF] Missing input filename")
				return
			} else {
				cfg.Input = args[i][5:]
			}
		case args[i] == "-o":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing output filename argument")
				return
			} else {
				cfg.Output = args[i]
			}
		case strings.HasPrefix(args[i], "--out="):
			lgh = 6
			fallthrough
		case strings.HasPrefix(args[i], "--out0="):
			if len(args[i]) <= lgh {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				cfg.Output = args[i][lgh:]
			}
		case args[i] == "-p":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing output filename argument")
				return
			} else {
				cfg.Key = args[i] // borrow cfg.Key as the name of the 2nd output file
			}
		case strings.HasPrefix(args[i], "--out1="):
			if len(args[i]) <= 7 {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				cfg.Key = args[i][7:]
			}
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}

	return
}

func validate(cfg *cfgs.Config) (err error) {
	errs := make([]error, 0)

	var algTyp bool
	if cfg.Command() != CMD_SPLIT {
		if algTyp, err = encrypts.Validate(cfg.Algr, 0); err != nil {
			errs = append(errs, err)
		}
		if cfg.Encd != "" {
			if err = encodes.Validate(cfg.Encd); err != nil {
				errs = append(errs, err)
			}
		}
	}

	switch cfg.Command() {
	case CMD_GENKEY:
		if cfg.IsList() {
			break
		}
		if cfg.Output == "" {
			errs = append(errs, fmt.Errorf("[VLDT] missing output key filename"))
		}
		if !algTyp && cfg.Encd != "" {
			errs = append(errs, fmt.Errorf("[VLDT] asymmetric keys must be PEM encoded, cannot use '%v'", cfg.Encd))
		}
	case CMD_PUBKEY:
		if cfg.IsList() {
			break
		}
		if cfg.Input == "" {
			errs = append(errs, fmt.Errorf("[VLDT] missing input key filename"))
		}
		if cfg.Output == "" {
			errs = append(errs, fmt.Errorf("[VLDT] missing output public key filename"))
		}
		if algTyp {
			errs = append(errs, fmt.Errorf("[VLDT] extracting public key not supported for %v", cfg.Algr))
		}
		if cfg.Encd != "" {
			errs = append(errs, fmt.Errorf("[VLDT] asymmetric keys must be PEM encoded"))
		}
	case CMD_SPLIT:
		if cfg.SaltLen == 0 {
			errs = append(errs, fmt.Errorf("[VLDT] missing split length"))
		}
		if cfg.Output == "" {
			errs = append(errs, fmt.Errorf("[VLDT] missing 1st output filename"))
		}
		if cfg.Key == "" {
			errs = append(errs, fmt.Errorf("[VLDT] missing 2nd output filename"))
		}
	}

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
		} else {
			err = nil
		}
	}

	if cfg.Command() != CMD_PUBKEY && !algTyp {
		if cfg.Key != "" {
			if _, err = os.Stat(cfg.Key); err == nil {
				errs = append(errs, fmt.Errorf("output file '%v' already exists", cfg.Key))
			} else if !errors.Is(err, os.ErrNotExist) {
				err = fmt.Errorf("[VLDT] %v", err)
				return
			} else {
				err = nil
			}
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
