package cfgs

import (
	"fmt"

	"sea9.org/go/c9ryptool/pkg/utils"
)

func Version() string {
	return "v1.5.1 2026012112"
}

const BUFFER = 1048576 // 1024x1024

const MASK_LIST = 128
const MASK_FLAG = 127

type Config struct {
	cmd     uint8  // 0 - encrypt; 1 - decrypt
	Algr    string // encryption algorithms
	Encd    string // encoding schemes
	Enco    string // encoding schemes for outputs
	Enck    string // encoding schemes for symmetric keys
	Hash    string // hashing algorithm
	Input   string // input file path, nil - stdin
	Output  string // output file path, nil - stdout
	Format  string // specify input file format
	Key     string // secret key file path
	Iv      string // initialization vector file path, nil - auto-gen
	Tag     string // message authentication tag file path
	Aad     string // additional authenticated data
	Genkey  bool   // generate key enabled
	Passwd  string // key-generating password
	SaltLen int    // length of salt to use for generating keys from password
	Buffer  int    // buffer size
	Verbose bool
}

func (cfg *Config) IsList() bool {
	return cfg.cmd&MASK_LIST > 0
}

func (cfg *Config) SetList() {
	cfg.cmd |= MASK_LIST
}

func (cfg *Config) Command() uint8 {
	return cfg.cmd & MASK_FLAG
}

func (cfg *Config) SetCommand(cmd int) {
	cfg.cmd |= uint8(cmd)
}

// CommandMatch match the given string against a list of commands
func CommandMatch(
	list []string, // list of commands to match
	cmd string, // command to be matched
) (
	idx int, mth string, err error,
) {
	indices, str, typ := utils.BestMatch(cmd, list, false)
	switch len(indices) {
	case 0:
		idx = -1
	case 1:
		idx = indices[0]
		mth = str
	default:
		ms := make([]string, 0)
		for x := range indices {
			ms = append(ms, list[indices[x]])
		}
		if typ == 1 {
			idx = -3
		} else {
			idx = -2
		}
		err = fmt.Errorf("'%v' ambiguously matched to %v", cmd, ms)
	}
	return
}
