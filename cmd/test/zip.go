package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"

	"sea9.org/go/c9ryptool/pkg/utils"
)

func zipTest() (err error) {
	inp, err := os.Open("./README.md")
	if err != nil {
		return
	}
	defer inp.Close()
	rb := bufio.NewReaderSize(inp, 1024)

	out, err := os.Create("./arcv.zip")
	if err != nil {
		return
	}
	wz := zip.NewWriter(out)
	defer out.Close()

	w, err := wz.Create("arcv.md")
	if err != nil {
		return
	}

	count := 0
	err = utils.BufferedRead(
		rb,
		rb.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				count++
				fmt.Printf("%v\n", count)
				_, err = w.Write(inp[:cnt])
			}
			return
		},
	)
	if err != nil {
		return
	}
	err = wz.Close()

	return
}

func unzipTest() (err error) {
	inp, err := os.Open("./arcv.zip")
	if err != nil {
		return
	}
	defer inp.Close()

	count := 0
	dat := make([]byte, 0)
	rb := bufio.NewReaderSize(inp, 1024)
	err = utils.BufferedRead(
		rb,
		rb.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				count++
				fmt.Printf("%v\n", count)
				dat = append(dat, inp[:cnt]...)
			}
			return
		},
	)
	rz, err := zip.NewReader(bytes.NewReader(dat), int64(len(dat)))
	if err != nil {
		return
	}

	var out *os.File
	var r io.ReadCloser
	for _, f := range rz.File {
		r, err = f.Open()
		if err != nil {
			return
		}

		out, err = os.Create(f.Name)
		if err != nil {
			return
		}
		w := bufio.NewWriter(out)
		defer out.Close()

		_, err = io.Copy(w, r)
		if err != nil {
			return
		}
	}

	return
}
