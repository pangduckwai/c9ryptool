package asym

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

var oid = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// marshal Marshal the given secp256k1.PrivateKey.
// openssl ec -in prv.pem -text -noout
// openssl ec -pubin -in pub.pem -text -noout
// openssl pkey -in prv.pem -pubout -out pub.pem
func marshal(inp *secp256k1.PrivateKey) (
	prv []byte,
	pub []byte,
	err error,
) {
	key := inp.ToECDSA()
	pkey := inp.PubKey()
	pubkeyBytes := pkey.SerializeUncompressed()

	// Private key
	privateKeyBytes := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	prv, err = asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKeyBytes),
		NamedCurveOID: oid,
		PublicKey: asn1.BitString{
			Bytes: pubkeyBytes,
		},
	})
	if err != nil {
		return
	}

	// Public key
	var pubkeyAlgr pkix.AlgorithmIdentifier
	pubkeyAlgr.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	paramBytes, err := asn1.Marshal(oid)
	if err != nil {
		return
	}
	pubkeyAlgr.Parameters.FullBytes = paramBytes
	pub, err = asn1.Marshal(pkixPublicKey{
		Algo: pubkeyAlgr,
		BitString: asn1.BitString{
			Bytes:     pubkeyBytes,
			BitLength: 8 * len(pubkeyBytes),
		},
	})
	return
}

// parse Parse given byte array to secp256k1.PrivateKey.
func parse(inp []byte) (
	prv *secp256k1.PrivateKey,
	err error,
) {
	blk, _ := pem.Decode(inp)
	var privKey ecPrivateKey
	_, err = asn1.Unmarshal(blk.Bytes, &privKey)
	if err != nil {
		return
	}
	prv = secp256k1.PrivKeyFromBytes(privKey.PrivateKey)
	return
}

// ///////// //
// SECP256K1
type Secp256k1 struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  *secp256k1.PublicKey
}

func (a *Secp256k1) Name() string {
	return "SECP256K1-ECIES"
}

func (a *Secp256k1) Type() bool {
	return false
}

func (a *Secp256k1) KeyLength() int {
	return 256
}

func (a *Secp256k1) Key() []byte {
	buf, _, err := marshal(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1) PopulateKey(key []byte) (err error) {
	a.PrivateKey, err = parse(key)
	if err != nil {
		// TODO try parse public key, if still fail
		return
	}
	a.PublicKey = a.PrivateKey.PubKey()
	return
}

func (a *Secp256k1) Encrypt(input ...[]byte) ([]byte, error) {
	fmt.Println("TEMP!!! Place holder")
	return nil, nil
}

func (a *Secp256k1) Decrypt(input ...[]byte) ([]byte, error) {
	fmt.Println("TEMP!!! Place holder")
	return nil, nil
}
