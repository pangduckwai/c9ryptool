package config

import (
	"fmt"
	"strconv"
	"strings"

	"sea9.org/go/cryptool/pkg/algorithm"
)

const bUFFER = 1048576 // 1024x1024

type Config struct {
	Command  uint8  // 1 - encrypt; 2 - decrypt
	Algr     string // encryption algorithm
	Input    string // nil - stdin
	Output   string // nil - stdout
	Key      string // secret key file path
	Genkey   bool   // generate key enabled
	Passwd   bool   // interactively input password
	Buffer   int    // buffer size
	Salt     string // base64 encoded salt for key generation from password
	SaltFile string // path of the file containing the salt to be used to generate key from password
	Verbose  bool
}

func Version() string {
	return "v0.4.1 b2025080112"
}

func Desc() string {
	return fmt.Sprintf("[en/de]CRYPTool (version %v)", Version())
}

func Usage() string {
	return "Usage:\n cryptool [encrypt | decrypt | version | help]\n" +
		"   {-a ALGR | --algorithm=ALGR}\n" +
		"   {-i FILE | --in=FILE}\n" +
		"   {-o FILE | --out=FILE}\n" +
		"   {-k FILE | --key=FILE}\n" +
		"   {-b SIZE | --buffer=SIZE}\n" +
		"   {--salt=SALT}\n" +
		"   {--salt-file=FILE}\n" +
		"   {-g | --generate}\n" +
		"   {-p | --password}\n" +
		"   {-v | --verbose}"
}

func Help() string {
	return fmt.Sprintf("Usage: cryptool [commands] {options}\n"+
		" * commands:\n"+
		"    encrypt - encrypt input using the provided encryption key\n"+
		"    decrypt - decrypt encrypted input back to the original form\n"+
		"    version - display current version of 'cryptool'\n"+
		"    help    - display this message\n\n"+
		" * options:\n"+
		"    -a ALGR, --algorithm=ALGR\n"+
		"       encryption algorithm to use, default '%v', supports %v\n"+
		"    -i FILE, --in=FILE\n"+
		"       path of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       path of the output file, omitting means output to stdout\n"+
		"    -k FILE, --key=FILE\n"+
		"       path of the file containing the encryption key\n"+
		"    -b SIZE, --buffer=SIZE\n"+
		"       size of the read buffer in # of bytes, default: %vKB\n"+
		"    --salt=SALT\n"+
		"       base64 encoded salt value to be used to generate encryption key from password\n"+
		"    --salt-file=FILE\n"+
		"       path of the file containing the salt to be used to generate key from password, default: 'salt.txt'\n"+
		"    -g, --generate\n"+
		"       generate a new encrytpion key\n"+
		"    -p, --password\n"+
		"       indicate a password, for encryption key generation, is input interactively\n"+
		"    -v, --verbose\n"+
		"       display detail operation messages during processing\n\n"+
		"  NOTE 1: a prompt will appear for typing in the password when password-\n"+
		"        generated key is used\n\n"+
		"  NOTE 2: type a period (.) then press <enter> in a new line to finish\n"+
		"        when inputting interactively from stdin",
		algorithm.Default(),
		algorithm.List(),
		bUFFER/1024)
}

func Parse(args []string) (cfg *Config, err error) {
	if len(args) < 2 {
		err = fmt.Errorf("[CONF] Command missing")
		return
	}

	cfg = &Config{
		Algr:     algorithm.Default(),
		Buffer:   bUFFER,
		Passwd:   false,
		SaltFile: "salt.txt",
		Verbose:  false,
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
		err = fmt.Errorf("[CONF] Invalid command '%v'", args[1])
		return
	}

	var val int
	for i := 2; i < len(args); i++ {
		switch {
		case args[i] == "-v" || args[i] == "--verbose":
			cfg.Verbose = true
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
		case strings.HasPrefix(args[i], "--salt="):
			if len(args[i]) <= 7 {
				err = fmt.Errorf("[CONF] Missing salt value")
				return
			} else {
				cfg.Salt = args[i][7:]
			}
		case strings.HasPrefix(args[i], "--salt-file="):
			if len(args[i]) <= 12 {
				err = fmt.Errorf("[CONF] Missing salt filename")
				return
			} else {
				cfg.SaltFile = args[i][12:]
			}
		case args[i] == "-g" || args[i] == "--generate":
			cfg.Genkey = true
		case args[i] == "-p" || args[i] == "--password":
			cfg.Passwd = true
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}

	return
}
