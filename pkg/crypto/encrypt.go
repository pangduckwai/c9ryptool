package crypto

import (
	"fmt"

	"sea9.org/go/cryptool/pkg/config"
)

const SALTLEN = 16

func Encrypt(
	cfg *config.Config,
	key []byte,
	ivLen int,
) (err error) {
	iv, err := Generate(ivLen)
	if err != nil {
		return
	}

	fmt.Printf("TEMP!!!\n%s\n%s\n", key, iv)
	return
}
