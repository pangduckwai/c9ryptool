package cfgs

import (
	"fmt"
	"regexp"
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
		"encr", "decr", "enco", "deco", "h", "v",
		"ncr", "ecry", "nco", "eco", "l", "si",
		"ny", "dy", "nd", "no", "dd", "do", "dco",
		"nc", "ec", "er", "ed", "dc",
	}

	for i, input := range inputs {
		idx, rst, err := cmdMatch(input)
		if err != nil {
			fmt.Printf("TestMatchs() %2v - in:%-7v err:%v\n", i, input, err)
		} else {
			fmt.Printf("TestMatchs() %2v - in:%-7v out:%-7v (%2v)\n", i, input, rst, idx)
		}
	}
}
