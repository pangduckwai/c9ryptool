package encodes

import (
	"bufio"
	"bytes"
	"encoding/base64"
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
