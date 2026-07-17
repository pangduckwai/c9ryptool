package asym

import (
	"encoding/pem"

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

// func main() {
// 	privateKeyString := ""
// 	encMessage := ""

// 	privateKey := ecies.DeserializePrivateKey(ecies.HexDecodeWithoutError(privateKeyString))
// 	cipher := ecies.NewECIES()
// 	palinMessage, _ := cipher.Decrypt(privateKey, ecies.HexDecodeWithoutError(encMessage))
// 	fmt.Println(string(palinMessage))
// }
