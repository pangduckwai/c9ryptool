package encodes

import (
	"bufio"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/pangduckwai/sea9go/pkg/inout"
	"github.com/pangduckwai/sea9go/pkg/strings/match"
	"sea9.org/go/c9ryptool/pkg/cfgs"
)

// Encoding encoding scheme
type Encoding interface {
	// Name algorithm name.
	Name() string

	// Type type of encoding. '0' is encoding, >0 is compression, <0 is decompression
	Type() int

	// Padding fill the input with the specific padding.
	Padding([]byte) []byte

	// Multiple return the multiple of number of characters processed in each encoding / decoding invocation.
	Multiple() (int, int)

	// EncodeToString encode the given input and returns the encoded result.
	EncodeToString([]byte) string

	// Encode read the given input and write the encoded result to the given output.
	Encode(io.Reader, io.Writer) error

	// DecodeString decode the given input and returns the decoded result.
	DecodeString(string) ([]byte, error)

	// Decode read the given input and write the decoded result to the given output.
	Decode(io.Reader, io.Writer) error
}

var eNCODINGS = map[string]Encoding{
	//"direct": nil,
	"base64":       Base64(11),
	"base64url":    Base64Url(13),
	"rawbase64url": RawBase64Url(15),
	"hex":          Hex(17),
	"gzip":         Gzip(19),
	"gunzip":       Gzip(-19),
	"zlib":         Zlib(21),
	"unzlib":       Zlib(-21),
	"flate":        Flate(23),
	"inflate":      Flate(-23),
}

func Default() string {
	return "rawbase64url"
}

func List() (list []string) {
	list = make([]string, 0)
	lst := make([]Encoding, 0)
	for k := range eNCODINGS {
		l := len(lst)
		s, _ := strconv.Atoi(fmt.Sprintf("%v", eNCODINGS[k]))
		if s < 0 {
			s = -s + 1
		}

		idx := sort.Search(l, func(i int) bool {
			t, _ := strconv.Atoi(fmt.Sprintf("%v", lst[i]))
			if t < 0 {
				t = -t + 1
			}
			return t >= s
		})

		if idx >= l {
			lst = append(lst, eNCODINGS[k])
			list = append(list, k)
		} else {
			lst = append(lst[:idx+1], lst[idx:]...)
			lst[idx] = eNCODINGS[k]
			list = append(list[:idx+1], list[idx:]...)
			list[idx] = k
		}
	}
	return
}

func Get(scheme string) Encoding {
	return eNCODINGS[scheme]
}

// Validate validate the given scheme name.
// typ: -1 - compression/decompression; 0 - don't care; 1 - encoding
// returns t: 0 is encoding, >0 is compression, <0 is decompression
func Validate(inp string, typ int) (t int, err error) {
	scheme := Parse(inp)
	if scheme == "" {
		err = fmt.Errorf("[ENCD] invalid encoding scheme name pattern '%v'", inp)
	} else {
		s, k := eNCODINGS[scheme]
		t = s.Type()
		if !k {
			err = fmt.Errorf("[ENCD] unsupported encoding scheme '%v'", scheme)
		} else if typ < 0 && t == 0 {
			err = fmt.Errorf("[ENCD] %v is not a compression algorithm as expected", s.Name())
		} else if typ > 0 && t != 0 {
			err = fmt.Errorf("[ENCD] %v is not an encoding scheme as expected", s.Name())
		}
	}
	return
}

// Parse return the actual encoding scheme name
func Parse(inp string) (name string) {
	algrs := make([]string, len(eNCODINGS))
	i := 0
	for n := range eNCODINGS {
		algrs[i] = n
		i++
	}

	indices, str, _ := match.BestMatch(inp, algrs, true)
	if len(indices) == 1 {
		name = str
	}
	return
}

func encode(n Encoding, r io.Reader, w io.Writer) (err error) {
	rdr, ok := r.(*bufio.Reader)
	if !ok {
		rdr = bufio.NewReaderSize(r, cfgs.BUFFER)
	}

	wtr, ok := w.(*bufio.Writer)
	if !ok {
		wtr = bufio.NewWriter(w)
	}

	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	enc, _ := n.Multiple()

	encode := func(inp []byte, ln int, flush bool) (err error) {
		if ln > 0 {
			encoded := n.EncodeToString(inp)
			_, err = fmt.Fprint(wtr, encoded)
			if err != nil {
				return
			}
		}
		if flush {
			err = wtr.Flush()
		}
		return
	}

	err = inout.BufferedRead(rdr, size, func(cnt int, inp []byte) (err error) {
		if enc > 1 {
			lgh += cnt
			dat = append(dat, inp...)

			lgh -= lgh % enc // num of characters to encode each time is multiple of 3
			err = encode(dat[:lgh], lgh, false)

			if len(dat) > lgh {
				dat = dat[lgh:]
				lgh = len(dat)
			} else {
				dat = dat[:0]
				lgh = 0
			}
		} else {
			err = encode(inp[:cnt], cnt, false)
		}

		return err
	})
	if err != nil {
		return
	}

	err = encode(dat, lgh, true)
	return
}

func decode(n Encoding, r io.Reader, w io.Writer) (err error) {
	rdr, ok := r.(*bufio.Reader)
	if !ok {
		rdr = bufio.NewReaderSize(r, cfgs.BUFFER)
	}

	wtr, ok := w.(*bufio.Writer)
	if !ok {
		wtr = bufio.NewWriter(w)
	}

	size := rdr.Size()
	lgh := 0
	dat := make([]byte, 0, size*2)
	_, dec := n.Multiple()

	decode := func(inp []byte, ln int, flush bool) (err error) {
		if ln > 0 {
			inp = n.Padding(inp)
			var decoded []byte
			decoded, err = n.DecodeString(string(inp))
			if err != nil {
				return
			}
			_, err = wtr.Write(decoded)
			if err != nil {
				return
			}
		}
		if flush {
			err = wtr.Flush()
		}
		return
	}

	err = inout.BufferedRead(rdr, size, func(cnt int, inp []byte) (err error) {
		if dec > 1 {
			lgh += cnt
			dat = append(dat, inp...)

			lgh -= lgh % dec // num of characters to decode each time is multiple of 4
			err = decode(dat[:lgh], lgh, false)

			if len(dat) > lgh {
				dat = dat[lgh:]
				lgh = len(dat)
			} else {
				dat = dat[:0]
				lgh = 0
			}
		} else {
			err = decode(inp[:cnt], cnt, false)
		}

		return err
	})
	if err != nil {
		return
	}

	err = decode(dat, lgh, true)
	return
}
