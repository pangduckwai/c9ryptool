package main

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"

	"github.com/pangduckwai/sea9go/pkg/inout"
)

func zipTest() (err error) {
	inp, err := os.Open("./README.md")
	if err != nil {
		return
	}
	defer inp.Close()
	rb := bufio.NewReaderSize(inp, 1024)

	out, err := os.Create("./temp.gz")
	if err != nil {
		return
	}
	defer out.Close()
	wz := gzip.NewWriter(out)
	defer wz.Close()

	count := 0
	err = inout.BufferedRead(
		rb, rb.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				count++
				fmt.Printf("%v\n", count)
				_, err = wz.Write(inp[:cnt])
			}
			return
		},
	)
	if err != nil {
		return
	}
	err = wz.Flush()
	return
}

func unzipTest() (err error) {
	inp, err := os.Open("./temp.gz")
	if err != nil {
		return
	}
	defer inp.Close()
	rz, err := gzip.NewReader(inp)
	if err != nil {
		return
	}
	defer rz.Close()
	rb := bufio.NewReaderSize(rz, 1024)

	out, err := os.Create("./temp.md")
	if err != nil {
		return
	}
	defer out.Close()
	wb := bufio.NewWriter(out)

	count := 0
	err = inout.BufferedRead(
		rb, rb.Size(),
		func(cnt int, inp []byte) (err error) {
			if cnt > 0 {
				count++
				fmt.Printf("%v\n", count)
				_, err = wb.Write(inp[:cnt])
			}
			return
		},
	)
	if err != nil {
		return
	}
	err = wb.Flush()
	return
}
