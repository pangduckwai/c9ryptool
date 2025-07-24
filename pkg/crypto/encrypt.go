package crypto

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"

	"sea9.org/go/cryptool/pkg/config"
)

const SALTLEN = 16

func Encrypt(cfg *config.Config) (err error) {
	var keyLen, ivLen int
	keyLen, ivLen, err = config.Algorithm(cfg.Algr)
	if err != nil {
		return
	}

	var key []byte
	if cfg.Passwd {
		var pwd string
		rdr := bufio.NewReader(os.Stdin)
		fmt.Printf("%v:\n", config.Desc())
		fmt.Print("Enter password: ")
		pwd, err = rdr.ReadString('\n')
		if err != nil {
			return
		}
		if len(pwd) <= 8 {
			err = fmt.Errorf("Minimum password length is 8 characters long")
			return
		}
		key, err = config.GetKeyFromPwd([]byte(pwd[:len(pwd)-1]), keyLen, SALTLEN)
		if err != nil {
			return
		}
	} else {
		var kend []byte
		kend, err = os.ReadFile(cfg.Key)
		if err != nil {
			return
		}
		key, err = base64.StdEncoding.DecodeString(string(kend))
		if err != nil {
			return
		}
	}

	var iv []byte

	return
}
