package encodes

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"testing"
)

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

func TestPipe(t *testing.T) {
	str := "534756736247394962336442636d565a6233552f53536474526d6c755a56526f5957357257573931566d56796555313159326768"
	b64 := Get("base64")
	hex := Get("hex")

	ri, wi := io.Pipe()

	ro := bytes.NewReader([]byte(str))

	var buf bytes.Buffer
	wd := bufio.NewWriter(&buf)

	err := hex.Decode(ro, wi)
	if err != nil {
		t.Fatal(err)
	}

	err = b64.Decode(ri, wd)
	if err != nil {
		t.Fatal(err)
	}

	rslt := buf.Bytes()
	fmt.Printf("TestPipe() - '%s'\n", rslt)
}
