package cfgs

import (
	"fmt"
	"testing"
)

func TestBitwise(t *testing.T) {
	fmt.Println()
	var a0 uint8 = 0
	var a1 uint8 = 1
	var a2 uint8 = 2
	var a3 uint8 = 3
	a0 |= MASK_LIST
	a2 |= MASK_LIST
	fmt.Printf("TestBitwise() 0: %3v - %v %v\n", a0, a0&MASK_FLAG, a0&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 1: %3v - %v %v\n", a1, a1&MASK_FLAG, a1&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 2: %3v - %v %v\n", a2, a2&MASK_FLAG, a2&MASK_LIST > 0)
	fmt.Printf("TestBitwise() 3: %3v - %v %v\n", a3, a3&MASK_FLAG, a3&MASK_LIST > 0)
}

func TestCommand(t *testing.T) {
	cfg := New(nil)
	fmt.Printf("TestCommand() 0: %x\n", cfg.cmd)
	cfg.SetList()
	fmt.Printf("TestCommand() 1: %x\n", cfg.cmd)
	cfg.SetCmd(3)
	fmt.Printf("TestCommand() 2: %x\n", cfg.cmd)
}

var cmds []string = []string{
	"help",    // 0
	"version", // 1
	"encrypt", // 2
	"decrypt", // 3
	"encode",  // 4
	"decode",  // 5
	"hash",    // 6
	"display", // 7
	"archive", // 8
}

func TestDisplayEncrypt(t *testing.T) {
	cfg := &Config{
		cmds:    cmds,
		cmd:     3,
		Algr:    "AES-128-GCM",
		Format:  "", //yaml
		Encd:    "base64",
		Input:   "./input.b64",
		Enco:    "base64url",
		Output:  "",
		Enck:    "base64",
		Key:     "./key.b64",
		Genkey:  false,
		Passwd:  "", //{INTERACTIVE}
		SaltLen: 16,
		Encv:    "base64",
		Iv:      "./iv.b64",
		Enct:    "base64",
		Tag:     "./tag.b64",
		Enca:    "base64",
		Aad:     "./aad.b64",
		Zip:     "gzip",
		Buffer:  4096,
		Verbose: true,
	}
	fmt.Printf("TestDisplayEncrypt()\n%v\n", cfg)
}

func TestDisplayHashing(t *testing.T) {
	cfg := &Config{
		cmds:   cmds,
		cmd:    6,
		Hash:   "sha1",
		Input:  "",
		Output: "./output.txt",
	}
	fmt.Printf("TestDisplayHashing()\n%v\n", cfg)
}

func TestDisplayEncoding(t *testing.T) {
	cfg := &Config{
		cmds:   cmds,
		cmd:    8,
		Hash:   "gzip",
		Input:  "",
		Output: "",
	}
	fmt.Printf("TestDisplayEncoding()\n%v\n", cfg)
}

// func TestMatch(t *testing.T) {
// 	fmt.Println()
// 	input := "dco"
// 	for _, c := range input {
// 		fmt.Printf("TestMatch() rune:%c\n", c)
// 	}

// 	var pttn = regexp.MustCompile(".*d.*c.*o.*")
// 	for i, cmd := range COMMANDS {
// 		fmt.Printf("TestMatch() %v - %7v matches:%v\n", i, cmd, pttn.MatchString(cmd))
// 	}
// }

// func TestMatchs(t *testing.T) {
// 	fmt.Println()
// 	inputs := []string{
// 		"help", "hlp", "elp", "hl", "hp", // #0
// 		"version", "v", "si", "er", // #5
// 		"encrypt", "encr", "ncry", "nrp", "ny", // #9
// 		"decrypt", "decr", "ecry", "drp", "dry", "dyp", // #14
// 		"encode", "enco", "nco", "ncd", "nd", "no", // #20
// 		"decode", "deco", "eco", "dco", "dd", "do", // #26
// 		"hash", "hsh", "ash", "hs", "hh", "ha", // #32
// 		"yamlenc", "yan", "yn", // #38
// 		"yamldec", "yad", "yd", // #41
// 		"display", "dsp", "dpy", "di", "ds", "is", // #44
// 		"dp", "dy", "enc", "dec", "ery", "ecd", // fail
// 		"nc", "ec", "ed", "dc", "de", "ya", // fail
// 		"h", "a", "s", "l", "y", // fail
// 	}

// 	h := 50
// 	e := -1
// 	f := 0
// 	for i, input := range inputs {
// 		indices, str, typ := utils.BestMatch(input, COMMANDS, false)
// 		switch len(indices) {
// 		case 0:
// 			fmt.Printf("TestMatchs() %2v - in:%-9v no match found\n", i, fmt.Sprintf("\"%v\"", input))
// 		case 1:
// 			t := "regex"
// 			switch typ {
// 			case 1:
// 				t = "partial"
// 			case 2:
// 				t = "exact"
// 			}
// 			fmt.Printf("TestMatchs() %2v - in:%-9v out:%-9v (%v)\n", i, fmt.Sprintf("\"%v\"", input), fmt.Sprintf("\"%v\"", str), t)
// 		default:
// 			f++
// 			if e < 0 {
// 				e = i
// 			}
// 			mths := make([]string, 0)
// 			for _, idx := range indices {
// 				mths = append(mths, COMMANDS[idx])
// 			}
// 			fmt.Printf("TestMatchs() %2v - in:%-9v err: ambiguously matched %v\n", i, fmt.Sprintf("\"%v\"", input), mths)
// 		}
// 	}
// 	if e != h {
// 		t.Fatalf("Test 1 to %v should be successful, while the rest should fail, found starts to fail at %v", h, e)
// 	} else if f != len(inputs)-h {
// 		t.Fatalf("Expecting %v fails, got %v", len(inputs)-h, f)
// 	}
// }
