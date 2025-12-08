package hashs

import (
	"bufio"
	"fmt"
	"sort"
)

type Hashing interface {
	// Name algorithm name.
	Name() string

	// Hash hash the given input and return the result.
	Hash(*bufio.Reader, *bufio.Writer) error
}

var hASHINGS = map[string]Hashing{
	"md5":    nil,
	"sha1":   nil,
	"sha256": nil,
}

func Default() string {
	return "sha256"
}

func List() (list []string) {
	list = make([]string, 0)
	for k := range hASHINGS {
		list = append(list, k)
	}
	sort.Strings(list)
	return
}

func Get(algr string) Hashing {
	return hASHINGS[algr]
}

// Validate validate the given algorithm name.
func Validate(algr string) (err error) {
	if _, okay := hASHINGS[algr]; !okay {
		err = fmt.Errorf("[ENCD] unsupported hashing algorithm '%v'", algr)
	}
	return
}
