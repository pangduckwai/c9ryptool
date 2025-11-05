package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"sea9.org/go/cryptool/pkg/utils"
)

func usage() string {
	return "Usage:\n c9split\n" +
		"   [-i FILE | --in=FILE]\n" +
		"   {-o FILE | --out0=FILE}\n" +
		"   {-p FILE | --out1=FILE}\n" +
		"   [-l LEN | --len=LEN]"
}

// parse Parse command line arguments.
// returns:
// - lgth: +ve - length of file out0, -ve - length of file out1
func parse(args []string) (
	in, out0, out1 string,
	lgth int,
	err error,
) {
	if len(args) < 3 {
		err = fmt.Errorf("[CONF] %v", usage())
		return
	}

	for i := 1; i < len(args); i++ {
		switch {
		case args[i] == "-i":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing input filename argument")
				return
			} else {
				in = args[i]
			}
		case strings.HasPrefix(args[i], "--in="):
			if len(args[i]) <= 5 {
				err = fmt.Errorf("[CONF] Missing input filename")
				return
			} else {
				in = args[i][5:]
			}
		case args[i] == "-o":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing output filename argument")
				return
			} else {
				out0 = args[i]
			}
		case strings.HasPrefix(args[i], "--out0="):
			if len(args[i]) <= 7 {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				out0 = args[i][7:]
			}
		case args[i] == "-p":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing output filename argument")
				return
			} else {
				out1 = args[i]
			}
		case strings.HasPrefix(args[i], "--out1="):
			if len(args[i]) <= 7 {
				err = fmt.Errorf("[CONF] Missing output filename")
				return
			} else {
				out1 = args[i][7:]
			}
		case args[i] == "-l":
			i++
			if i >= len(args) {
				err = fmt.Errorf("[CONF] Missing split length argument")
				return
			} else {
				lgth, err = strconv.Atoi(args[i])
				if err != nil {
					err = fmt.Errorf("[CONF] Invalid value '%v'", args[i])
				}
			}
		case strings.HasPrefix(args[i], "--len="):
			if len(args[i]) <= 6 {
				err = fmt.Errorf("[CONF] Missing split length")
				return
			} else {
				lgth, err = strconv.Atoi(args[i][6:])
				if err != nil {
					err = fmt.Errorf("[CONF] Invalid value '%v'", args[i][6:])
				}
			}
		default:
			err = fmt.Errorf("[CONF] Invalid option '%v'", args[i])
			return
		}
	}
	return
}

func validate(
	in, out0, out1 string,
	lgth int,
) (err error) {
	if in != "" {
		if _, err = os.Stat(in); errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] input file '%v' does not exist", in)
			return
		} else if err != nil {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		}
	}

	if out0 != "" {
		if _, err = os.Stat(out0); err == nil {
			err = fmt.Errorf("[VLDT] output file '%v' already exists", out0)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		} else {
			err = nil
		}
	}

	if out1 != "" {
		if _, err = os.Stat(out1); err == nil {
			err = fmt.Errorf("[VLDT] output file '%v' already exists", out1)
			return
		} else if !errors.Is(err, os.ErrNotExist) {
			err = fmt.Errorf("[VLDT] %v", err)
			return
		} else {
			err = nil
		}
	}

	if lgth == 0 {
		err = fmt.Errorf("[VLDT] length cannot be zero")
	}

	return
}

func main() {
	in, out0, out1, lgth, err := parse(os.Args)
	if err != nil {
		log.Fatalf("[SPLIT]%v", err)
	}
	err = validate(in, out0, out1, lgth)
	if err != nil {
		log.Fatalf("[SPLIT]%v", err)
	}

	input, err := utils.Read(in, 1048576, false)
	if err != nil {
		err = fmt.Errorf("[SPLIT][INP]%v", err)
		return
	}

	if lgth < 0 {
		lgth = len(input) + lgth
	}

	err = utils.Write(out0, input[:lgth])
	if err != nil {
		log.Fatalf("[SPLIT][OUT0] %v", err)
	}

	err = utils.Write(out1, input[lgth:])
	if err != nil {
		log.Fatalf("[SPLIT][OUT1] %v", err)
	}

	fmt.Printf("[SPLIT] finished splitting %v (%v)\n", in, lgth)
}
