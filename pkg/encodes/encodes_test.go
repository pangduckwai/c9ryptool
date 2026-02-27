package encodes

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

type TestIfc interface {
	Process() bool
}

type TestTyp int

func (n TestTyp) Process() bool {
	if n > 0 {
		return true
	} else if n < 0 {
		return false
	}
	panic("Invalid value '0'")
}

func TestType(t *testing.T) {
	var o, p TestIfc = TestTyp(77), TestTyp(-8)

	fmt.Printf("TestType() 1: %v > 0 is %v\n", o, o.Process())
	fmt.Printf("TestType() 2: %v > 0 is %v\n", p, p.Process())
}

func TestList(t *testing.T) {
	var val int
	for i, k := range List() {
		switch typ := eNCODINGS[k].(type) {
		case Base64:
			val = int(typ)
		case Base64Url:
			val = int(typ)
		case RawBase64Url:
			val = int(typ)
		case Hex:
			val = int(typ)
		case Gzip:
			val = int(typ)
		}
		fmt.Printf("TestList() - %v %v %v\n", i, val, eNCODINGS[k].Name())
	}
}

func TestEncode(t *testing.T) {
	inp := []byte("Hello world!!!")
	ctrl := base64.StdEncoding.EncodeToString(inp)

	rdr := bytes.NewReader(inp)

	var out bytes.Buffer
	wtr := bufio.NewWriter(&out)

	encd := Get(Parse("base64"))
	err := encd.Encode(rdr, wtr)
	if err != nil {
		t.Fatal(err)
	}
	rslt := out.Bytes()

	if string(rslt) != ctrl {
		t.Fatalf("TestEncode() '%s' and '%v' mismatched", rslt, ctrl)
	}
}

func TestDecode(t *testing.T) {
	str := "SGVsbG8gd29ybGQhISE="
	inp := []byte(str)
	ctrl, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		t.Fatal(err)
	}

	rdr := bytes.NewReader(inp)

	var out bytes.Buffer
	wtr := bufio.NewWriter(&out)

	encd := Get(Parse("base64"))
	err = encd.Decode(rdr, wtr)
	if err != nil {
		t.Fatal(err)
	}
	rslt := out.Bytes()

	if string(rslt) != string(ctrl) {
		t.Fatalf("TestDecode() '%s' and '%s' mismatched", rslt, ctrl)
	}
}

// pipedEncoding piped encoding/decoding
// e0: in->w0
// e1: r0->w1  c0
// e2: r1->w2  c1
// e3: r2->out c2
func pipedEncoding(in io.Reader, out io.Writer, isEncode bool, encoders ...Encoding) (err error) {
	lgth := len(encoders)
	cs := make([]chan error, 0)
	rs := make([]io.Reader, 0)
	ws := make([]io.Writer, 0)

	for i := 1; i < lgth; i++ {
		r, w := io.Pipe()
		cs = append(cs, make(chan error))
		rs = append(rs, r)
		ws = append(ws, w)
	}
	last := len(cs) - 1

	for i := range encoders[1 : lgth-1] {
		go func() {
			var err error
			if isEncode {
				err = encoders[i+1].Encode(rs[i], ws[i+1])
			} else {
				err = encoders[lgth-2-i].Decode(rs[i], ws[i+1])
			}
			if err != nil {
				cs[i] <- err
			}
			cs[i] <- ws[i+1].(*io.PipeWriter).CloseWithError(nil)
		}()
	}
	go func() {
		if isEncode {
			cs[last] <- encoders[lgth-1].Encode(rs[last], out)
		} else {
			cs[last] <- encoders[0].Decode(rs[last], out)
		}
	}()

	for j, c := range cs[:last] {
		go func() {
			for e := range c {
				if e != nil {
					cs[last] <- fmt.Errorf("[PIPE] %v: %v", j, e)
				}
			}
		}()
	}

	if isEncode {
		err = encoders[0].Encode(in, ws[0])
	} else {
		err = encoders[lgth-1].Decode(in, ws[0])
	}
	if err != nil {
		return
	}
	err = ws[0].(*io.PipeWriter).CloseWithError(nil)
	if err != nil {
		return
	}

	err = <-cs[last]
	return
}

func TestPipeEncode(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	in := bytes.NewReader([]byte("HelloHowAreYou?I'mFineThankYouVeryMuch!"))

	err := pipedEncoding(
		in, out, true,
		[]Encoding{
			Get("hex"),
			Get("rawbase64url"),
			Get("gzip"),
			Get("base64"),
		}...,
	)
	if err != nil {
		t.Fatal(err)
	}

	rslt := buf.Bytes()
	fmt.Printf("TestPipeEncode() result: %s\n", rslt)
}

func TestPipeDecode(t *testing.T) {
	var buf bytes.Buffer
	out := bufio.NewWriter(&buf)
	in := bytes.NewReader([]byte("H4sIAAAAAAAA/xzHMQ7CMAxA0SsRU25ghg79VSV3iNcMCIfsjU+P1PGhH8E8GJt4HAujPsnjIlfBztdtY6B9kt7RKrv5jzgLWhfiLW7+xbp4tIJVwdok+8O1FWKTXdfrDwAA//8BAAD//60UA+1oAAAA"))

	err := pipedEncoding(
		in, out, false,
		[]Encoding{
			Get("hex"),
			Get("rawbase64url"),
			Get("gzip"),
			Get("base64"),
		}...,
	)
	if err != nil {
		t.Fatal(err)
	}

	rslt := buf.Bytes()
	fmt.Printf("TestPipeDecode() result: %s\n", rslt)
}
