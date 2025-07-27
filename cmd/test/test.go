package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
)

func main() {
	fmt.Println("Test command line input...")
	rdr := bufio.NewReader(os.Stdin)
	fmt.Print(" enter input: ")
	inp, err := rdr.ReadString('\n')
	if err != nil {
		log.Fatalf("[TEST]%v", err)
	}
	fmt.Printf("Your input is '%v' (%v)\n", inp[:len(inp)-1], len(inp))
}
