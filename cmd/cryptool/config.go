package main

import (
	"fmt"
	"strings"
)

type Config struct {
	Command uint8  // 1 - encode; 2 - decode
	Input   string // nil - stdin
	Output  string // nil - stdout
	Key     string // secret key file path
	Verbose bool
}

func usage() string {
	return "Usage:\n cryptool [encrypt | decrypt | version | help]\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-k FILE | --key=FILE}\n" +
		"   {-v | --verbose}"
}

func help() string {
	return "Usage: cryptool [commands] {options}\n" +
		" * commands:\n" +
		"    encrypt - encrypt input using the provided secret key\n" +
		"    decrypt - decrypt encrypted file back to the original form\n" +
		"    version - display current version of 'basesf'\n" +
		"    help    - display this message\n\n" +
		" * options:\n" +
		"    -i FILE, --in=FILE\n" +
		"       name of the input file, omitting means input from stdin\n" +
		"    -o FILE, --out=FILE\n" +
		"       name of the output file, omitting means output to stdout\n" +
		"    -k FILE, --key=FILE\n" +
		"       name of the key file\n" +
		"    -v, --verbose\n" +
		"       display detail operation messages during processing\n\n" +
		"  NOTE: type a period (.) then press <enter> in a new line to finish\n" +
		"        when inputting interactively from stdin"
}

func parse(args []string) (cfg *Config, err error) {
	if len(args) < 2 {
		err = &Err{1, "Command missing"}
		return
	}

	cfg = &Config{
		Verbose: false,
	}

	switch args[1][0:1] {
	case "e":
		cfg.Command = 0
	case "d":
		cfg.Command = 1
	case "h":
		cfg.Command = 2
	case "v":
		cfg.Command = 3
	default:
		err = &Err{1, fmt.Sprintf("Invalid command '%v'", args[1])}
		return
	}

	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
		case args[i] == "-i":
			i++
			if i >= len(args) {
				return nil, &Err{2, "Missing input filename argument"}
			} else {
				cfg.Input = args[i]
			}
		case strings.HasPrefix(args[i], "--in="):
			if len(args[i]) <= 5 {
				return nil, &Err{2, "Missing input filename"}
			} else {
				cfg.Input = args[i][5:]
			}
		case args[i] == "-o":
			i++
			if i >= len(args) {
				return nil, &Err{3, "Missing output filename argument"}
			} else {
				cfg.Output = args[i]
			}
		case strings.HasPrefix(args[i], "--out="):
			if len(args[i]) <= 6 {
				return nil, &Err{3, "Missing out filename"}
			} else {
				cfg.Output = args[i][6:]
			}
		case args[i] == "-k":
			i++
			if i >= len(args) {
				return nil, &Err{4, "Missing key filename argument"}
			} else {
				cfg.Key = args[i]
			}
		case strings.HasPrefix(args[i], "--key="):
			if len(args[i]) <= 6 {
				return nil, &Err{4, "Missing key filename"}
			} else {
				cfg.Key = args[i][6:]
			}
		default:
			return nil, &Err{0, fmt.Sprintf("Invalid option '%v'", args[i])}
		}
	}

	return
}
