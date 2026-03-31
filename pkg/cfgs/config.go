package cfgs

import (
	"fmt"

	"github.com/pangduckwai/sea9go/pkg/strings/match"
)

func Version() string {
	return "v2.1.0 2026033110"
}

const BUFFER = 1048576 // 1024x1024

const MASK_LIST = 128
const MASK_FLAG = 127

type Config struct {
	cmds    []string // command list
	cmd     uint8    // e.g. 0 - encrypt; 1 - decrypt
	Algr    string   // encryption algorithm name
	Encd    string   // encoding schemes name
	Encv    string   // encoding schemes name for IV
	Enct    string   // encoding schemes name for TAG
	Enca    string   // encoding schemes name for AAD
	Enco    string   // encoding schemes name for outputs
	Enck    string   // encoding schemes name for symmetric keys
	Hash    string   // hashing algorithm name
	Input   string   // input file path, nil - stdin
	Output  string   // output file path, nil - stdout
	Format  string   // input file format
	Key     string   // secret key file path
	Iv      string   // initialization vector file path, nil - auto-gen
	Tag     string   // message authentication tag file path
	Aad     string   // additional authenticated data file path
	Genkey  bool     // generate key enabled
	Passwd  string   // key-generating password
	SaltLen int      // length of salt to use for generating keys from password
	Zip     string   // compression algorithm name
	Buffer  int      // buffer size
	Verbose bool
}

func New(comands []string) *Config {
	return &Config{
		cmds:    comands,
		Buffer:  BUFFER,
		Passwd:  "",
		Verbose: false,
	}
}

func (cfg *Config) IsList() bool {
	return cfg.cmd&MASK_LIST > 0
}

func (cfg *Config) SetList() {
	cfg.cmd |= MASK_LIST
}

func (cfg *Config) Cmd() uint8 {
	return cfg.cmd & MASK_FLAG
}

func (cfg *Config) SetCmd(cmd int) {
	cfg.cmd |= uint8(cmd)
}

func (cfg *Config) Command() string {
	return cfg.cmds[cfg.Cmd()]
}

// CommandMatch match the given string against a list of commands
func (cfg *Config) CommandMatch(
	inp string, // command to be matched
) (
	idx int, mth string, err error,
) {
	indices, str, typ := match.BestMatch(inp, cfg.cmds, false)
	switch len(indices) {
	case 0:
		idx = -1
	case 1:
		idx = indices[0]
		mth = str
		cfg.SetCmd(idx)
	default:
		ms := make([]string, 0)
		for x := range indices {
			ms = append(ms, cfg.cmds[indices[x]])
		}
		if typ == 1 {
			idx = -3
		} else {
			idx = -2
		}
		err = fmt.Errorf("'%v' ambiguously matched to %v", inp, ms)
	}
	return
}

func (c *Config) String() string {
	vbrs := ""
	if c.Verbose {
		vbrs = " (verbose)"
	}

	strs := make([]string, 0)
	inp, out := "stdin", "stdout"

	if c.Algr != "" {
		key, iv, tag, aad := ", no key specified", "", "", ""
		enck, enci, enco, encv, enct, enca := "", "", "", "", "", ""
		if c.Enck != "" {
			enck = fmt.Sprintf(" (%v encoding)", c.Enck)
		}
		if c.Passwd != "" {
			key = fmt.Sprintf("; key from passphrase, salt-len %v", c.SaltLen)
		} else if c.Genkey {
			key = fmt.Sprintf("; generate new key%v", enck)
		} else if c.Key != "" {
			key = fmt.Sprintf("; key from %v%v", c.Key, enck)
		}
		frmt := ""
		if c.Format != "" {
			frmt = fmt.Sprintf(" %v", c.Format)
		}
		strs = append(strs, fmt.Sprintf("%v(%v)%v using '%v'%v%v", c.Command(), c.Cmd(), frmt, c.Algr, key, vbrs))

		if c.Encv != "" {
			encv = fmt.Sprintf(" (%v)", c.Encv)
		}
		if c.Iv != "" {
			iv = fmt.Sprintf(" | IV: %v%v", c.Iv, encv)
		}
		if c.Enct != "" {
			enct = fmt.Sprintf(" (%v)", c.Enct)
		}
		if c.Tag != "" {
			tag = fmt.Sprintf(" | Tag: %v%v", c.Tag, enct)
		}
		if c.Enca != "" {
			enca = fmt.Sprintf(" (%v)", c.Enca)
		}
		if c.Aad != "" {
			aad = fmt.Sprintf(" | AAD: %v%v", c.Aad, enca)
		}
		if c.Input != "" {
			inp = c.Input
		}
		if c.Encd != "" {
			enci = fmt.Sprintf(" (%v)", c.Encd)
		}
		strs = append(strs, fmt.Sprintf("\n - input: %v%v%v%v%v", inp, enci, iv, tag, aad))

		if c.Output != "" {
			out = c.Output
		}
		if c.Enco != "" {
			enco = fmt.Sprintf(" (%v)", c.Enco)
		}
		strs = append(strs, fmt.Sprintf("\n - output: %v%v", out, enco))

		if c.Zip != "" {
			strs = append(strs, fmt.Sprintf("\n - compression with %v", c.Zip))
		}
	} else if c.Hash != "" {
		strs = append(strs, fmt.Sprintf("%v(%v) using '%v'%v", c.Command(), c.Cmd(), c.Hash, vbrs))
		if c.Input != "" {
			inp = c.Input
		}
		strs = append(strs, fmt.Sprintf("\n - input: %v", inp))
		if c.Output != "" {
			out = c.Output
		}
		strs = append(strs, fmt.Sprintf("\n - output: %v", out))
	} else if c.Encd != "" {
		strs = append(strs, fmt.Sprintf("%v(%v) using '%v'%v", c.Command(), c.Cmd(), c.Encd, vbrs))
		if c.Input != "" {
			inp = c.Input
		}
		strs = append(strs, fmt.Sprintf("\n - input: %v", inp))
		if c.Output != "" {
			out = c.Output
		}
		strs = append(strs, fmt.Sprintf("\n - output: %v", out))
	}

	str := strs[0]
	for _, s := range strs[1:] {
		str = fmt.Sprintf("%v%v", str, s)
	}
	return str
}
