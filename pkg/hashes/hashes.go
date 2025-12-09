package hashes

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"

	"sea9.org/go/c9ryptool/pkg/utils"
)

var hASHINGS = map[string]hash.Hash{
	"md5":    md5.New(),
	"sha1":   sha1.New(),
	"sha256": sha256.New(),
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

func Get(algr string) hash.Hash {
	return hASHINGS[algr]
}

// Validate validate the given algorithm name. TODO HERE!!! change to use parsing similar to encryption algorithm names
func Validate(algr string) (err error) {
	if _, okay := hASHINGS[algr]; !okay {
		err = fmt.Errorf("[HASH] unsupported hashing algorithm '%v'", algr)
	}
	return
}

func Hash(h hash.Hash, rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
	size := rdr.Size()
	isStdout := wtr == nil

	err = utils.BufferedRead(rdr, size, func(cnt int, buf []byte) {
		_, err = h.Write(buf)
	})
	if err != nil {
		return
	}

	hsh := hex.EncodeToString(h.Sum(nil))
	if !isStdout {
		fmt.Fprint(wtr, hsh)
		wtr.Flush()
	} else {
		fmt.Println(hsh)
	}
	return
}
