package main

import (
	"errors"
	"fmt"
	"log"
	"os"
)

func Version() string {
	return "0.1.0"
}

func app() string {
	return fmt.Sprintf("[en/de]CRYPTool (version %v)", Version())
}

func validate(cfg *Config) {
	if cfg.Input != "" {
		if _, err := os.Stat(cfg.Input); errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Input file '%v' does not exist\n", cfg.Input)
		} else if err != nil {
			log.Fatal(err)
		}
	}

	if cfg.Output != "" {
		if _, err := os.Stat(cfg.Output); err == nil {
			log.Fatalf("Output file '%v' already exists\n", cfg.Output)
		} else if !errors.Is(err, os.ErrNotExist) {
			log.Fatal(err)
		}
	}

	if cfg.Key != "" {
		if _, err := os.Stat(cfg.Key); errors.Is(err, os.ErrNotExist) {
			log.Fatalf("Key file '%v' does not exist\n", cfg.Key)
		} else if err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatal("Key file missing")
	}
}

func main() {
	cfg, err := parse(os.Args)
	if err != nil {
		if errr, ok := err.(*Err); !ok || errr.Code > 1 {
			log.Fatal(err)
		}
		log.Fatalf("%v\n%v\n%v\n", err, app(), usage())
	}

	switch cfg.Command {
	case 0:
		validate(cfg)
		// TODO HERE
	case 1:
		validate(cfg)
		// TODO HERE
	case 2:
		fmt.Printf("%v\n%v\n", app(), help())
	case 3:
		fmt.Println(app())
	}

	if err != nil {
		log.Fatal(err)
	}
}

type Err struct {
	Code uint8
	Msg  string
}

func (e *Err) Error() string {
	return fmt.Sprintf("[%4v] %v", e.Code, e.Msg)
}
