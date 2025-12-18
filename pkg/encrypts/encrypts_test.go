package encrypts

import (
	"fmt"
	"testing"
)

func display(i int, s string) {
	r := algrPattern.FindStringSubmatch(s)
	if len(r) > 2 {
		for i := 0; i < len(r); i++ {
			if r[i] == "" {
				r[i] = "."
			}
		}
		fmt.Printf("TestParse() %2v - %-5v %-17v (%v) %v -> '%v'\n", i, algrPattern.MatchString(s), r[0], len(r), r[1:], Parse(s))
	} else {
		fmt.Printf("TestParse() %2v x %-5v %-17v (0) %v -> '%v'\n", i, algrPattern.MatchString(s), s, r, Parse(s))
	}
}

func TestParse(t *testing.T) {
	display(0, "AES-192-CBC-HS512")
	display(1, "AES256-GCM")
	display(2, "A128CBC-HS256")
	display(3, "3DES-GCM")
	display(4, "3DES-64-GCM")
	display(5, "AES-256-GCM")
	display(6, "ChaCha20-Poly1305")
	display(7, "AES-256")
	display(8, "abcde-def")
	display(9, "abc3de-def")
	display(10, "A256CBC")
	display(11, "RSA-OAEP-256")
	display(12, "RSA-2048-PKCS1v15")
	display(13, "RSA-PKCS1v15")
	display(14, "SECP256K1-ECIES")
	display(15, "ECIES")
	display(16, "SECP256K1")
}

// func read() (
// 	dat []byte,
// 	err error,
// ) {
// 	inp, err := os.Open("../../rst.txt")

// 	rdr := bufio.NewReaderSize(inp, 1048576)

// 	cnt, off := 0, 0
// 	var err1 error
// 	buf := make([]byte, 0, 1048576)
// 	dat = make([]byte, 0, 1048576*2)
// 	for idx := 0; ; idx++ {
// 		// As described in the doc, handle read data first if n > 0 before handling error,
// 		// it is because the returned error could have been EOF
// 		if err1 == nil { // When loop for the last time, skip read
// 			cnt, err = rdr.Read(buf[:cap(buf)])
// 		}

// 		if err1 != nil {
// 			if err1 == io.EOF {
// 				err = nil
// 				break // Done
// 			} else {
// 				dat = nil
// 				err = fmt.Errorf("[READ] %v", err1)
// 				return
// 			}
// 		}

// 		dat = append(dat[:len(dat)-off], buf[:cnt]...)
// 		err1 = err
// 	}
// 	return
// }

// func write(
// 	dat []byte,
// ) (err error) {
// 	var out *os.File
// 	var wtr *bufio.Writer
// 	out, err = os.Create("val.txt")
// 	if err != nil {
// 		return
// 	}
// 	wtr = bufio.NewWriter(out)
// 	defer out.Close()
// 	fmt.Fprintf(wtr, "%s", dat)
// 	wtr.Flush()
// 	return
// }

// func TestDecodeKey(t *testing.T) {
// 	fmt.Printf("TestDecodeKey() %x\n", []byte("ft6fUWdlH2IEOfW4anqNMHvCmOWtYbMi")) // 667436665557646c483249454f665734616e714e4d4876436d4f577459624d69 79dd36f5d7dce3ddfd75e75bcfb7210f
// }

// // ed029dfc4939dedbz7chD4VCurG2fbKb7z1ChhNn98+q3GlmU1CydO2CcpfFK/katC5vBZ+yReR4W+/myfyGT4/oioBw3RT1b9gITZpe8JSCerA0cKC3B6npQe1QADYjm1Uu8BDefgu7G4zQjSg7SkLDUqIi/GK1aOITD9X1jCPNC/iOEVqew5sdI1nohWaZ1JcOi3llEMqD1pixpMZCe3pLD0F50PW5cZXxKw==
// func TestDecodeIV(t *testing.T) {
// 	fmt.Printf("TestDecodeIV() %x\n", []byte("ed029dfc4939dedb"))
// }

// func TestDecodeTx(t *testing.T) {
// 	val := []byte("z7chD4VCurG2fbKb7z1ChhNn98+q3GlmU1CydO2CcpfFK/katC5vBZ+yReR4W+/myfyGT4/oioBw3RT1b9gITZpe8JSCerA0cKC3B6npQe1QADYjm1Uu8BDefgu7G4zQjSg7SkLDUqIi/GK1aOITD9X1jCPNC/iOEVqew5sdI1nohWaZ1JcOi3llEMqD1pixpMZCe3pLD0F50PW5cZXxKw==")
// 	fmt.Printf("TestDecodeIV() %x\n", val)
// 	write(val)
// }

// func TestRead(t *testing.T) {
// 	val, err := read()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	fmt.Printf("TestRead() %s\n", val)
// }
