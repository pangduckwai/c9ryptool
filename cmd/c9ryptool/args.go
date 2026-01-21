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
	"sea9.org/go/c9ryptool/pkg/encrypts/sym"
	"sea9.org/go/c9ryptool/pkg/hashes"
)

const FORMAT_YAML = "yaml"
const FORMAT_JSON = "json"
const PWD_INTERACTIVE = "{[INTERACTIVE]}"

const CMD_HELP = 0
const CMD_VERSION = 1
const CMD_ENCRYPT = 2
const CMD_DECRYPT = 3
const CMD_ENCODE = 4
const CMD_DECODE = 5
const CMD_HASHING = 6
const CMD_DISPLAY = 7

var COMMANDS = []string{
	"help",    // 0
	"version", // 1
	"encrypt", // 2
	"decrypt", // 3
	"encode",  // 4
	"decode",  // 5
	"hash",    // 6
	"display", // 7
}

func usage() string {
	return "Usage:\n c9ryptool\n" +
		"  [version | help]\n\n" +
		"  [encrypt | decrypt]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   {-k FILE | --key=FILE}\n" +
		"   {--iv=IV}\n" +
		"   {--tag=TAG}\n" +
		"   {--aad=AAD}\n" +
		"   {-g | --generate}\n" +
		"   {-p | --password}\n" +
		"   {--password=PASS}\n" +
		"   {--salt=LEN}\n" +
		"   {-l | --list}\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-f FORMAT | --format=FORMAT}\n" +
		"   {-n ENC | --encoding=ENC}\n" +
		"   {--encode-in=ENC}\n" +
		"   {--encode-out=ENC}\n" +
		"   {--encode-key=ENC}\n\n" +
		"  [encode | decode]\n" +
		"   {-l | --list}\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-n ENC | --encoding=ENC}\n\n" +
		"  [hash]\n" +
		"   {-l | --list}\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-h ALGR | --hashing=ALGR}\n\n" +
		"  [display]\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-n ENC | --encoding=ENC}\n\n" +
		"  all commands\n" +
		"   {-b SIZE | --buffer=SIZE}\n" +
		"   {-v | --verbose}"
}

func help() string {
	return fmt.Sprintf("Usage: c9ryptool [commands] {options}\n"+
		" # misc.\n"+
		" . version - display current version of 'c9ryptool'\n"+
		" . help    - display this message\n\n"+
		" # encryption\n"+
		" . encrypt - encrypt input using the provided encryption key\n"+
		" . decrypt - decrypt encrypted input back to the original form\n"+
		"   * options:\n"+
		"    -a ALGR, --algorithm=ALGR\n"+
		"       encryption algorithm to use, default: '%v'\n"+
		"    -k FILE, --key=FILE\n"+
		"       path of the file containing the encryption key\n"+
		"    --iv=IV\n"+
		"       path of the file containing the initialization vector, if omitted:\n"+
		"        1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding\n"+
		"        2. decryption - read from the begining of the ciphertext after base64 decoding\n"+
		"    --tag=TAG\n"+
		"       path of the file containing the message authentication tag\n"+
		"    --aad=AAD\n"+
		"       path of the file containing the additional authenticated data\n"+
		"    -g, --generate\n"+
		"       generate a new encrytpion key\n"+
		"    -p, --password\n"+
		"       indicate a password, for encryption key generation, is input interactively\n"+
		"    --password=PASS\n"+
		"       input the key-generating password via the command line\n"+
		"    --salt=LEN\n"+
		"       length of salt to use for generating keys from password, default: %v\n"+
		"    -l, --list\n"+
		"       list the supported algorithms or encoding schemes\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"    -f FORMAT, --format=FORMAT\n"+
		"       format of the input file, default is none:\n"+
		"        1. 'none' - no format, the entire input is treated as a stream of bytes\n"+
		"        2. 'yaml' - encrypt/decrypt field values in the given YAML file while preserving the file structure\n"+
		"        3. 'json' - to be added\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       overall encoding scheme to use for output and symmetric key (encryption), and input and symmetric key (decryption)\n"+
		"    --encode-in=ENC\n"+
		"       encoding scheme of encryption/decryption input\n"+
		"        1. encoding scheme to decode field values before decryption when input format is 'yaml'/'json', default: %v\n"+
		"        2. encoding scheme to decode the entire input when input format is 'none', default: none\n"+
		"        3. encoding scheme to decode AAD, IV and TAG values when given\n"+
		"    --encode-out=ENC\n"+
		"       encoding scheme of encryption/decryption output\n"+
		"        1. encoding scheme to encode field values after encryption when output format is 'yaml'/'json', default: %v\n"+
		"        2. encoding scheme to encode the entire output when input file format is 'none', default: none\n"+
		"    --encode-key=ENC\n"+
		"       encoding scheme of the symmetric key (when option -k / --key is specified), default: none\n\n"+
		" # encoding\n"+
		" . encode - convert the given input into the specified encoding\n"+
		" . decode - convert the given input back from the specified encoding\n"+
		"   * options:\n"+
		"    -l, --list\n"+
		"       list the supported algorithms or encoding schemes\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       encoding scheme to use, default: '%v'\n\n"+
		" # hash - hash input using the specified algorithm\n"+
		"   * options:\n"+
		"    -l, --list\n"+
		"       list the supported algorithms or encoding schemes\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"    -h ALGR, --hashing=ALGR\n"+
		"       hashing algorithm to use, default: '%v'\n\n"+
		" # display - display content of the given input as hex, and as characters if printable\n"+
		"   * options:\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       encoding scheme to use, default: do not decode\n\n"+
		" # common options:\n"+
		"    -b SIZE, --buffer=SIZE\n"+
		"       size of the read buffer in # of bytes, default: %vKB\n"+
		"    -v, --verbose\n"+
		"       display detail operation messages during processing\n\n"+
		" NOTE 1: a prompt will appear for typing in the password when password-\n"+
		"         generated key is used\n\n"+
		" NOTE 2: type a period (.) then press <enter> in a new line to finish\n"+
		"         when inputting interactively from stdin",
		encrypts.Default(),
		sym.SALTLEN,
		encodes.Default(),
		encodes.Default(),
		encodes.Default(),
		hashes.Default(),
		cfgs.BUFFER/1024,
	)
}

// parse parse command line arguments to populate a Config object
func parse(args []string) (cfg *cfgs.Config, err error) {
	if len(args) < 2 {
		err = fmt.Errorf("[CONF] Command missing")
		return
	}

	cfg = &cfgs.Config{
		Buffer:  cfgs.BUFFER,
		Passwd:  "",
		SaltLen: sym.SALTLEN,
		Verbose: false,
	}

	encd := func(val string) {
		switch cfg.Command() {
		case CMD_ENCRYPT:
			cfg.Enco = val
			cfg.Enck = val
		case CMD_DECRYPT:
			cfg.Encd = val
			cfg.Enck = val
		default:
			cfg.Encd = val
		}
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

	var val int
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
		case args[i] == "-l" || args[i] == "--list":
			cfg.SetList()
			i = len(args)
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
		case args[i] == "-k":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing key filename argument")
				return
			} else {
				cfg.Key = args[i]
			}
		case strings.HasPrefix(args[i], "--key="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing key filename")
				return
			} else {
				cfg.Key = args[i][6:]
			}
		case strings.HasPrefix(args[i], "--iv="):
			if len(args[i]) <= 5 {
				err = fmt.Errorf("[CONF] Missing IV value")
				return
			} else {
				cfg.Iv = args[i][5:]
			}
		case strings.HasPrefix(args[i], "--tag="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing TAG value")
				return
			} else {
				cfg.Tag = args[i][6:]
			}
		case strings.HasPrefix(args[i], "--aad="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing AAD value")
				return
			} else {
				cfg.Aad = args[i][6:]
			}
		case strings.HasPrefix(args[i], "--salt="):
			if len(args[i]) <= 7 {
				err = fmt.Errorf("[CONF] Missing salt value")
				return
			} else {
				val, err = strconv.Atoi(args[i][7:])
				if err == nil {
					cfg.SaltLen = val
				}
			}
		case args[i] == "-g" || args[i] == "--generate":
			cfg.Genkey = true
		case args[i] == "-p" || args[i] == "--password":
			cfg.Passwd = PWD_INTERACTIVE
		case strings.HasPrefix(args[i], "--password="):
			if len(args[i]) <= 11 {
				err = fmt.Errorf("[CONF] Missing password value")
				return
			} else {
				cfg.Passwd = args[i][11:]
			}
		case args[i] == "-n":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing encoding argument")
				return
			} else {
				encd(args[i])
			}
		case strings.HasPrefix(args[i], "--encoding="):
			if len(args[i]) <= 11 {
				err = fmt.Errorf("[CONF] Missing encoding")
				return
			} else {
				encd(args[i][11:])
			}
		case strings.HasPrefix(args[i], "--encode-in="):
			if len(args[i]) <= 12 {
				err = fmt.Errorf("[CONF] Missing input encoding")
				return
			} else {
				cfg.Encd = args[i][12:]
			}
		case strings.HasPrefix(args[i], "--encode-out="):
			if len(args[i]) <= 13 {
				err = fmt.Errorf("[CONF] Missing output encoding")
				return
			} else {
				cfg.Enco = args[i][13:]
			}
		case strings.HasPrefix(args[i], "--encode-key="):
			if len(args[i]) <= 13 {
				err = fmt.Errorf("[CONF] Missing key encoding")
				return
			} else {
				cfg.Enck = args[i][13:]
			}
		case args[i] == "-h":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing algorithm argument")
				return
			} else {
				cfg.Hash = args[i]
			}
		case strings.HasPrefix(args[i], "--hashing="):
			if len(args[i]) <= 10 {
				err = fmt.Errorf("[CONF] Missing algorithm")
				return
			} else {
				cfg.Hash = args[i][10:]
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
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				cfg.Output = args[i][6:]
			}
		case args[i] == "-f":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing input file format argument")
				return
			} else {
				cfg.Format = args[i]
			}
		case strings.HasPrefix(args[i], "--format="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing input file format")
				return
			} else {
				cfg.Format = args[i][9:]
			}
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}

	switch cfg.Command() {
	case CMD_ENCRYPT:
		if cfg.Algr == "" {
			cfg.Algr = encrypts.Default()
		}
		if cfg.Format != "" && cfg.Format != "none" {
			if cfg.Enco == "" {
				cfg.Enco = encodes.Default()
			}
		}
	case CMD_DECRYPT:
		if cfg.Algr == "" {
			cfg.Algr = encrypts.Default()
		}
		if cfg.Format != "" && cfg.Format != "none" {
			if cfg.Encd == "" {
				cfg.Encd = encodes.Default()
			}
		}
	case CMD_ENCODE:
		fallthrough
	case CMD_DECODE:
		if cfg.Encd == "" {
			cfg.Encd = encodes.Default()
		}
	case CMD_HASHING:
		if cfg.Hash == "" {
			cfg.Hash = hashes.Default()
		}
	}

	return
}

// validate validate parameters.
// - Input : not given means input from stdin, file not exist is an error
// - Output : not given means output to stdout, file exist is an error
// - Key : mutally exclusive with 'Passwd' (key from passphrase), file not exist is an error unless 'Genkey' (gen new key) is specified
// - Passwd : mutally exclusive with 'Genkey' (gen new key), generate encryption key from a passphrase which is input interactively
// - Algr : encryption algorithm name
func validate(cfg *cfgs.Config) (err error) {
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
			return
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

		if _, err = encrypts.Validate(cfg.Algr, typ); err != nil {
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
