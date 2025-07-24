package config

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/scrypt"
)

type Config struct {
	Command uint8  // 1 - encode; 2 - decode
	Input   string // nil - stdin
	Output  string // nil - stdout
	Key     string // secret key file path
	Algr    string // encryption algorithm
	Passwd  bool   // interactively input password
	Verbose bool
}

func Version() string {
	return "0.1.0"
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
		"   {-p | --password}\n" +
		"   {-v | --verbose}"
}

func Help() string {
	return fmt.Sprintf("Usage: cryptool [commands] {options}\n"+
		" * commands:\n"+
		"    encrypt - encrypt input using the provided secret key\n"+
		"    decrypt - decrypt encrypted file back to the original form\n"+
		"    version - display current version of 'basesf'\n"+
		"    help    - display this message\n\n"+
		" * options:\n"+
		"    -a ALGR, --algorithm=ALGR\n"+
		"       encryption algorithm to use, default %v, supports %v\n"+
		"    -i FILE, --in=FILE\n"+
		"       name of the input file, omitting means input from stdin\n"+
		"    -o FILE, --out=FILE\n"+
		"       name of the output file, omitting means output to stdout\n"+
		"    -k FILE, --key=FILE\n"+
		"       name of the key file\n"+
		"    -p, --password\n"+
		"       indicate a password is input interactively\n"+
		"    -v, --verbose\n"+
		"       display detail operation messages during processing\n\n"+
		"  NOTE: type a period (.) then press <enter> in a new line to finish\n"+
		"        when inputting interactively from stdin", ALGORITHMS[1], ALGORITHMS)
}

func Parse(args []string) (cfg *Config, err error) {
	if len(args) < 2 {
		err = fmt.Errorf("[CONF] Command missing")
		return
	}

	cfg = &Config{
		Algr:    ALGORITHMS[1],
		Passwd:  false,
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
		err = fmt.Errorf("[CONF] Invalid command '%v'", args[1])
		return
	}

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
		case args[i] == "-p" || args[i] == "--password":
			cfg.Passwd = true
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}

	return
}

// Validate validate inputs
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
		if _, err = os.Stat(cfg.Key); errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("key file '%v' does not exist", cfg.Key))
		} else if err != nil {
			return
		}
	} else if !cfg.Passwd {
		errs = append(errs, fmt.Errorf("encryption key missing"))
	}

	if err = validateAlg(cfg.Algr); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		var buf strings.Builder
		fmt.Fprintf(&buf, "[\n - %v", errs[0])
		for _, err := range errs[1:] {
			fmt.Fprintf(&buf, "\n - %v", err)
		}
		err = fmt.Errorf("%v\n]", buf.String())
	}
	return
}

const SALT = "salt.txt"
const N = 65536
const R = 16
const P = 1

func GetKeyFromPwd(pwd []byte, keyLen, saltLen int) (
	key []byte,
	err error,
) {
	var sfile *os.File
	var salt []byte
	if _, err = os.Stat(SALT); errors.Is(err, os.ErrNotExist) {
		// salt file not exists
		salt = make([]byte, saltLen)
		_, err = rand.Read(salt)
		if err != nil {
			return
		}
		sfile, err = os.Create(SALT)
		if err != nil {
			return
		}
		wtr := bufio.NewWriter(sfile)
		defer sfile.Close()
		fmt.Fprint(wtr, base64.StdEncoding.EncodeToString(salt))
		wtr.Flush()
	} else if err != nil {
		return
	} else {
		// salt file found
		var sstr []byte
		sstr, err = os.ReadFile(SALT)
		if err != nil {
			return
		}
		salt, err = base64.StdEncoding.DecodeString(string(sstr))
		if err != nil {
			return
		}
	}
	key, err = scrypt.Key(pwd, salt, N, R, P, keyLen)
	return
}
