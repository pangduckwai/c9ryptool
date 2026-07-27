package asym

import (
	"encoding/pem"
	"fmt"

	"github.com/hotstar/ecies"
)

// ///////////////// //
// secp256k1 hotstar
type Secp256k1Hotstar struct {
	PrivateKey *ecies.PrivateKey
	PublicKey  *ecies.PublicKey
}

func (a *Secp256k1Hotstar) Name() string {
	return "ECIES-SECP256K1-HOTSTAR"
}

func (a *Secp256k1Hotstar) Type() bool {
	return false
}

func (a *Secp256k1Hotstar) KeyLength() int {
	return 256
}

func (a *Secp256k1Hotstar) GetKey() []byte {
	buf := ecies.SerializePrivateKey(a.PrivateKey)
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Hotstar) GetPublicKey() []byte {
	buf := ecies.SerializePublicKey(a.PublicKey)
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Hotstar) PopulateKey(key []byte) (err error) {
	if key == nil {
		a.PrivateKey, err = ecies.GenerateKey()
		if err != nil {
			return
		}
		a.PublicKey = a.PrivateKey.PublicKey
	} else {
		a.PublicKey, err = ecies.DeserializePublicKey(key)
		if err != nil { // is not a public key?
			fmt.Printf("popkey: %v\n", err)
			a.PrivateKey = ecies.DeserializePrivateKey(key)
			a.PublicKey = a.PrivateKey.PublicKey
		}
	}
	return
}

func (a *Secp256k1Hotstar) Encrypt(input ...[]byte) ([][]byte, error) {
	if a.PublicKey == nil {
		return nil, fmt.Errorf("key not ready")
	}

	cipher := ecies.NewECIES()
	rst, err := cipher.Encrypt(a.PublicKey, input[0])
	if err != nil {
		err = fmt.Errorf("[HOTSTAR] %v", err)
		return nil, err
	}
	rsts := make([][]byte, 0)
	rsts = append(rsts, rst)
	return rsts, nil
}

func (a *Secp256k1Hotstar) Decrypt(input ...[]byte) ([][]byte, error) {
	if a.PrivateKey == nil {
		if a.PublicKey != nil {
			return nil, fmt.Errorf("public key cannot be used for decryption")
		}
		return nil, fmt.Errorf("keys not ready")
	}

	cipher := ecies.NewECIES()
	rst, err := cipher.Decrypt(a.PrivateKey, input[0])
	if err != nil {
		err = fmt.Errorf("[HOTSTAR] %v", err)
		return nil, err
	}
	rsts := make([][]byte, 0)
	rsts = append(rsts, rst)
	return rsts, nil
}
