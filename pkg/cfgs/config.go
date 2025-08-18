package cfgs

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"sea9.org/go/cryptool/pkg/encrypts"
	"sea9.org/go/cryptool/pkg/encrypts/sym"
)

const bUFFER = 1048576 // 1024x1024

const MASK_LIST = 128
const MASK_FLAG = 127

type Config struct {
	cmd     uint8  // 0 - encrypt; 1 - decrypt
	Algr    string // algorithms / encoding schemes
	Input   string // input file path, nil - stdin
	Output  string // output file path, nil - stdout
	Key     string // secret key file path
	Iv      []byte // initialization vector, nil - auto-gen
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

func Version() string {
	return "v0.6.1 b2025081815"
}

func Desc() string {
	return fmt.Sprintf("c9rypTool (version %v)", Version())
}

func Usage() string {
	return "Usage:\n c9ryptool\n" +
		"  [version | help]\n\n" +
		"  [encrypt | decrypt]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   {-k FILE | --key=FILE}\n" +
		"   {--iv=IV | --iv-b64=IV-B64 | --iv-hex=IV-HEX}\n" +
		"   {-g | --generate}\n" +
		"   {-p | --password}\n" +
		"   {--salt=LEN}\n\n" +
		"  [encode | decode]\n" +
		"   {-n ENC | --encoding=ENC}\n\n" +
		"  all commands\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-b SIZE | --buffer=SIZE}\n" +
		"   {-v | --verbose}"
}

func Help() string {
	return fmt.Sprintf("Usage: c9ryptool [commands] {options}\n"+
		" * commands\n"+
		" . version    - display current version of 'cryptool'\n"+
		" . help       - display this message\n\n"+
		" * commands\n"+
		" . encrypt - encrypt input using the provided encryption key\n"+
		" . decrypt - decrypt encrypted input back to the original form\n"+
		"    * options:\n"+
		"    -a ALGR, --algorithm=ALGR\n"+
		"       encryption algorithm to use, default: '%v'\n"+
		"    -k FILE, --key=FILE\n"+
		"       path of the file containing the encryption key\n"+
		"        - key files are not decoded when read, nor encoded when written\n"+
		"    --iv=IV\n"+
		"       initialization vector as 'base256 enocded' string, if omitted:\n"+
		"        1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding\n"+
		"        2. decryption - read from the begining of the ciphertext after base64 decoding\n"+
		"    --iv-b64=IV-B64\n"+
		"       initialization vector as base64 encoded string, if omitted:\n"+
		"        1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding\n"+
		"        2. decryption - read from the begining of the ciphertext after base64 decoding\n"+
		"    --iv-hex=IV-HEX\n"+
		"       initialization vector as hex encoded string, if omitted:\n"+
		"        1. encryption - auto-generate and concat at the begining the ciphertext before base64 encoding\n"+
		"        2. decryption - read from the begining of the ciphertext after base64 decoding\n"+
		"    -g, --generate\n"+
		"       generate a new encrytpion key\n"+
		"    -p, --password\n"+
		"       indicate a password, for encryption key generation, is input interactively\n"+
		"    --salt=LEN\n"+
		"       length of salt to use for generating keys from password, default: %v\n\n"+
		" * commands\n"+
		" . encode - convert the given input into the specified encoding\n"+
		" . decode - convert the given input back from the specified encoding\n"+
		"    * options:\n"+
		"    -n ENC, --encoding=ENC\n"+
		"       encoding scheme to use, default: 'base64'\n\n"+
		" * all commands\n"+
		"    * options:\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"        1. for encryption, the input plaintext is not decoded\n"+
		"        2. for decryption, the input ciphertext is base64 decoded\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"        1. for encryption, the output ciphertext is base64 encoded\n"+
		"        2. for decryption, the output plaintext is not encoded\n"+
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
		bUFFER/1024,
	)
}

var COMMANDS = []string{
	"encrypt",
	"decrypt",
	"encode",
	"decode",
	"hash",
	"help",
	"version",
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
	case 0:
		fallthrough
	case 1:
		cfg.Algr = encrypts.Default()
	case 2:
		fallthrough
	case 3:
		cfg.Algr = "TEMP" // TODO TEMP!!!!!!!!
	}

	var val int
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
		case args[i] == "-l" || args[i] == "--list":
			cfg.cmd |= MASK_LIST
			break
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
				cfg.Iv = []byte(args[i][5:])
			}
		case strings.HasPrefix(args[i], "--iv-b64="):
			if len(args[i]) <= 9 {
				err = fmt.Errorf("[CONF] Missing IV value")
				return
			} else {
				cfg.Iv, err = base64.StdEncoding.DecodeString(args[i][9:])
				if err != nil {
					err = fmt.Errorf("[CONF] %v", err)
				}
			}
		case strings.HasPrefix(args[i], "--iv-hex="):
			if len(args[i]) <= 9 {
				err = fmt.Errorf("[CONF] Missing IV value")
				return
			} else {
				cfg.Iv, err = hex.DecodeString(args[i][9:])
				if err != nil {
					err = fmt.Errorf("[CONF] %v", err)
				}
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
				cfg.Algr = args[i]
			}
		case strings.HasPrefix(args[i], "--encoding="):
			if len(args[i]) <= 11 {
				err = fmt.Errorf("[CONF] Missing encoding")
				return
			} else {
				cfg.Algr = args[i][11:]
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
