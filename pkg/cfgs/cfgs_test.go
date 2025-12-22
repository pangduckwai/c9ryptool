package cfgs

import (
	"fmt"
	"regexp"
	"testing"

	"sea9.org/go/c9ryptool/pkg/utils"
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

func TestMatch(t *testing.T) {
	fmt.Println()
	input := "dco"
	for _, c := range input {
		fmt.Printf("TestMatch() rune:%c\n", c)
	}

	var pttn = regexp.MustCompile(".*d.*c.*o.*")
	for i, cmd := range COMMANDS {
		fmt.Printf("TestMatch() %v - %7v matches:%v\n", i, cmd, pttn.MatchString(cmd))
	}
}

func TestMatchs(t *testing.T) {
	fmt.Println()
	inputs := []string{
		"help", "hlp", "elp", "hl", "hp", // #0
		"version", "v", "si", "er", // #5
		"encrypt", "encr", "ncry", "nrp", "ny", // #9
		"decrypt", "decr", "ecry", "drp", "dry", "dyp", // #14
		"encode", "enco", "nco", "ncd", "nd", "no", // #20
		"decode", "deco", "eco", "dco", "dd", "do", // #26
		"hash", "hsh", "ash", "hs", "hh", "ha", // #32
		"yamlenc", "yan", "yn", // #38
		"yamldec", "yad", "yd", // #41
		"display", "dsp", "dpy", "di", "ds", "is", // #44
		"dp", "dy", "enc", "dec", "ery", "ecd", // fail
		"nc", "ec", "ed", "dc", "de", "ya", // fail
		"h", "a", "s", "l", "y", // fail
	}

	h := 50
	e := -1
	f := 0
	for i, input := range inputs {
		indices, str, typ := utils.BestMatch(input, COMMANDS, false)
		switch len(indices) {
		case 0:
			fmt.Printf("TestMatchs() %2v - in:%-9v no match found\n", i, fmt.Sprintf("\"%v\"", input))
		case 1:
			t := "regex"
			switch typ {
			case 1:
				t = "partial"
			case 2:
				t = "exact"
			}
			fmt.Printf("TestMatchs() %2v - in:%-9v out:%-9v (%v)\n", i, fmt.Sprintf("\"%v\"", input), fmt.Sprintf("\"%v\"", str), t)
		default:
			f++
			if e < 0 {
				e = i
			}
			mths := make([]string, 0)
			for _, idx := range indices {
				mths = append(mths, COMMANDS[idx])
			}
			fmt.Printf("TestMatchs() %2v - in:%-9v err: ambiguously matched %v\n", i, fmt.Sprintf("\"%v\"", input), mths)
		}
	}
	if e != h {
		t.Fatalf("Test 1 to %v should be successful, while the rest should fail, found starts to fail at %v", h, e)
	} else if f != len(inputs)-h {
		t.Fatalf("Expecting %v fails, got %v", len(inputs)-h, f)
	}
}
