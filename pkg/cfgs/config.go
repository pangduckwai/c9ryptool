package cfgs

import (
	"fmt"
	"strconv"
	"strings"

	"sea9.org/go/cryptool/pkg/encodes"
	"sea9.org/go/cryptool/pkg/encrypts"
	"sea9.org/go/cryptool/pkg/encrypts/sym"
	"sea9.org/go/cryptool/pkg/hashes"
)

const bUFFER = 1048576 // 1024x1024

const MASK_LIST = 128
const MASK_FLAG = 127

type Config struct {
	cmd     uint8  // 0 - encrypt; 1 - decrypt
	Algr    string // encryption algorithms
	Encd    string // encoding schemes
	Hash    string // hashing algorithm
	Input   string // input file path, nil - stdin
	Output  string // output file path, nil - stdout
	Key     string // secret key file path
	Iv      string // initialization vector file path, nil - auto-gen
	Tag     string // message authentication tag file path
	Aad     string // additional authenticated data
	Genkey  bool   // generate key enabled
	Passwd  bool   // interactively input password
	SaltLen int    // length of salt to use for generating keys from password
	Buffer  int    // buffer size
	Verbose bool
}

func (cfg *Config) IsList() bool {
	return cfg.cmd&MASK_LIST > 0
}

func (cfg *Config) Command() uint8 {
	return cfg.cmd & MASK_FLAG
}

func Usage() string {
	return "Usage:\n c9ryptool\n" +
		"  [version | help]\n\n" +
		"  [encrypt | decrypt | yamlenc | yamldec]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   {-k FILE | --key=FILE}\n" +
		"   {--iv=IV }\n" +
		"   {--tag=TAG }\n" +
		"   {--aad=AAD }\n" +
		"   {-g | --generate}\n" +
		"   {-p | --password}\n" +
		"   {--salt=LEN}\n" +
		"   {-n ENC | --encoding=ENC}\n\n" +
		"  [encode | decode]\n" +
		"   {-n ENC | --encoding=ENC}\n\n" +
		"  [hash]\n" +
		"   {-h ALGR | --hashing=ALGR}\n\n" +
		"  all commands\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-l | --list}\n" +
		"   {-b SIZE | --buffer=SIZE}\n" +
		"   {-v | --verbose}"
}

func Help() string {
	return fmt.Sprintf("Usage: c9ryptool [commands] {options}\n"+
		" # misc.\n"+
		" . version - display current version of 'c9ryptool'\n"+
		" . help    - display this message\n\n"+
		" # encryption\n"+
		" . encrypt - encrypt input using the provided encryption key\n"+
		" . decrypt - decrypt encrypted input back to the original form\n"+
		" . yamlenc - encrypt values in the given YAML file while preserving the file structure\n"+
		" . yamldec - decrypt values in the given YAML file\n"+
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
		"    --salt=LEN\n"+
		"       length of salt to use for generating keys from password, default: %v\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       encoding scheme to use, only applies to yaml encryption/decryption, default: '%v'\n\n"+
		" # encoding\n"+
		" . encode - convert the given input into the specified encoding\n"+
		" . decode - convert the given input back from the specified encoding\n"+
		"   * options:\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       encoding scheme to use, default: '%v'\n\n"+
		" # hashing\n"+
		" . hash - hash input using the specified algorithm\n"+
		"   * options:\n"+
		"    -h ALGR, --hashing=ALGR\n"+
		"       hashing algorithm to use, default: '%v'\n\n"+
		" # common options:\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"    -l, --list\n"+
		"       list the supported algorithms or encoding schemes\n"+
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
		hashes.Default(),
		bUFFER/1024,
	)
}

const CMD_HELP = 0
const CMD_VERSION = 1
const CMD_ENCRYPT = 2
const CMD_DECRYPT = 3
const CMD_ENCODE = 4
const CMD_DECODE = 5
const CMD_HASHING = 6
const CMD_YAMLENC = 7
const CMD_YAMLDEC = 8

var COMMANDS = []string{
	"help",
	"version",
	"encrypt",
	"decrypt",
	"encode",
	"decode",
	"hash",
	"yamlenc",
	"yamldec",
}

func Parse(args []string) (cfg *Config, err error) {
	if len(args) < 2 {
		err = fmt.Errorf("[CONF] Command missing")
		return
	}

	cfg = &Config{
		Buffer:  bUFFER,
		Passwd:  false,
		SaltLen: sym.SALTLEN,
		Verbose: false,
	}

	idx, _, err := cmdMatch(args[1])
	if err != nil {
		err = fmt.Errorf("[CONF] %v", err)
		return
	} else if idx < 0 {
		err = fmt.Errorf("[CONF] Invalid command '%v'", args[1])
		return
	}
	cfg.cmd = uint8(idx)

	switch cfg.cmd {
	case CMD_YAMLENC:
		fallthrough
	case CMD_YAMLDEC:
		cfg.Encd = encodes.Default()
		fallthrough
	case CMD_ENCRYPT:
		fallthrough
	case CMD_DECRYPT:
		cfg.Algr = encrypts.Default()
	case CMD_ENCODE:
		fallthrough
	case CMD_DECODE:
		cfg.Encd = encodes.Default()
	case CMD_HASHING:
		cfg.Hash = hashes.Default()
	}

	var val int
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
		case args[i] == "-l" || args[i] == "--list":
			cfg.cmd |= MASK_LIST
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
			cfg.Passwd = true
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
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}

	return
}
