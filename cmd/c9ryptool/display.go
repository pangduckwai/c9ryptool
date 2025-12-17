package main

import (
	"bufio"
	"fmt"
	"os"

	"sea9.org/go/c9ryptool/pkg/cfgs"
	"sea9.org/go/c9ryptool/pkg/encodes"
	"sea9.org/go/c9ryptool/pkg/utils"
)

const SIZE_VERIFY = 5
const SIZE_DISPLAY = 20

func __parsePem(val byte) bool {
	return val == 0x2d
}

func _parsePem(buf []byte, idx int) (rst bool, off int) {
	rst = true
	for _, val := range buf[idx : idx+SIZE_VERIFY] {
		if !__parsePem(val) {
			rst = false
			break
		}
	}
	if rst {
		off = idx + SIZE_VERIFY
	}
	return
}

func parsePem(buf []byte) (result []byte) {
	//000000000011111111112222222222
	//012345678901234567890123456789
	//-----BEGIN EC PRIVATE KEY-----
	//-----END EC PRIVATE KEY-----
	var i, j, l int
	indices := make([]int, 0)
	l = len(buf)
	for i = 0; i < l; i++ {
		if __parsePem(buf[i]) {
			okay, off := _parsePem(buf, i)
			if okay {
				indices = append(indices, i)
				i = off
				j++
			}
		}
	}

	// len("BEGIN PUBLIC KEY") => 16
	// len("END PUBLIC KEY") => 14
	if len(indices) == 4 && indices[0] >= 0 && indices[1] >= 16+indices[0]+SIZE_VERIFY && indices[2] >= 0 && indices[3] >= 14+indices[2]+SIZE_VERIFY {
		srt := indices[1] + SIZE_VERIFY
		end := indices[2] - 1
		result = make([]byte, 0)
		for _, val := range buf[srt:end] {
			if val == 10 || val == 13 {
				continue
			}
			result = append(result, val)
		}
	}
	return
}

func _display(buf []byte) {
	frm := fmt.Sprintf("%%-%vv  %%v\n", SIZE_DISPLAY*3-1)
	var ln0, ln1 string
	fmt.Printf("Number of bytes to display: %v\n", len(buf))
	for i, val := range buf {
		ln0 = fmt.Sprintf("%v:%02x", ln0, val)

		if val >= 32 && val < 127 {
			ln1 = fmt.Sprintf("%v%c", ln1, val)
		} else if val == 10 || val == 13 {
			ln1 = fmt.Sprintf("%v ", ln1)
		} else {
			ln1 = fmt.Sprintf("%v.", ln1)
		}

		if (i+1)%SIZE_DISPLAY == 0 {
			fmt.Printf("%v  %v\n", ln0[1:], ln1)
			ln0 = ""
			ln1 = ""
		}
	}
	if len(ln0) > 0 {
		fmt.Printf(frm, ln0[1:], ln1)
	} else {
		fmt.Println()
	}
}

func display(
	cfg *cfgs.Config,
	ecd encodes.Encoding,
) (err error) {
	buf := make([]byte, 0)

	inp := os.Stdin
	if cfg.Input != "" {
		inp, err = os.Open(cfg.Input)
		if err != nil {
			err = fmt.Errorf("[READ] %v", err)
			return
		}
		defer inp.Close()
	}
	rdr := bufio.NewReaderSize(inp, cfg.Buffer)
	if rdr.Size() != cfg.Buffer {
		if cfg.Verbose {
			fmt.Printf("Read buffer size %v mismatching with the specified size %v, changing buffer size...\n", rdr.Size(), cfg.Buffer)
		}
		cfg.Buffer = rdr.Size()
		rdr = bufio.NewReaderSize(inp, cfg.Buffer)
	}

	action := func(cnt int, buff []byte) error {
		buf = append(buf, buff...)
		return nil
	}

	err = utils.BufferedRead(rdr, cfg.Buffer, action)
	if err != nil {
		err = fmt.Errorf("[READ] %v", err)
		return
	}

	if ecd == nil {
		_display(buf)
	} else {
		pbuf := parsePem(buf)
		if pbuf != nil {
			buf = pbuf
		}
		out := make([]byte, 0)
		_, dec := ecd.Multiple()
		decode := func(inp []byte, ln int) (err error) {
			if ln > 0 {
				inp = ecd.Padding(inp)
				var decoded []byte
				decoded, err = ecd.Decode(string(inp))
				if err != nil {
					return
				}
				out = append(out, decoded...)
			}
			return
		}

		end := len(buf)
		lgh := min(cfg.Buffer, end)
		if dec > 1 {
			lgh -= lgh % dec
		}
		fmt.Printf("TEMP 0 END:%v LGH:%v\n", end, lgh)
		to := lgh
		for fm := 0; ; fm, to = fm+lgh, to+lgh {
			fmt.Printf("TEMP 1 %4v %4v %s\n", fm, to, buf[fm:to])
			err = decode(buf[fm:to], lgh)
			if err != nil {
				return
			}
			if to+lgh > end {
				break
			}
		}
		if end > to {
			fmt.Printf("TEMP 2 %4v %4v %s\n", to, end, buf[to:])
			err = decode(buf[to:], end-to)
			if err != nil {
				return
			}
		}
		_display(out)
	}

	return
}
