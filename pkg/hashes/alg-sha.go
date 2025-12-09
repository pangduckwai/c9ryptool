package hashes

import "bufio"

type Sha1 int

func (h Sha1) Name() string {
	return "SHA-1"
}

func (h Sha1) Hash(rdr *bufio.Reader, wtr *bufio.Writer) (err error) {
}
