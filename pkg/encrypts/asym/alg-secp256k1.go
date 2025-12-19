package asym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
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
	// Public key
	pub, pubkeyBytes, err := marshalPub(inp.PubKey())
	if err != nil {
		return
	}

	// Private key
	key := inp.ToECDSA()
	privateKeyBytes := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	prv, err = asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKeyBytes),
		NamedCurveOID: oid,
		PublicKey: asn1.BitString{
			Bytes: pubkeyBytes,
		},
	})

	return
}

// marshalPub the given secp256k1.PublicKey.
func marshalPub(
	inp *secp256k1.PublicKey,
) (
	pub, pubkeyBytes []byte,
	err error,
) {
	pubkeyBytes = inp.SerializeUncompressed()

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
	var prvKey ecPrivateKey
	blk, _ := pem.Decode(inp)
	_, err = asn1.Unmarshal(blk.Bytes, &prvKey)
	if err != nil {
		return
	}
	prv = secp256k1.PrivKeyFromBytes(prvKey.PrivateKey)
	return
}

func parsePub(
	inp []byte,
) (
	pub *secp256k1.PublicKey,
	err error,
) {
	var pubKey pkixPublicKey
	blk, _ := pem.Decode(inp)
	_, err = asn1.Unmarshal(blk.Bytes, &pubKey)
	if err != nil {
		return
	}
	pub, err = secp256k1.ParsePubKey(pubKey.BitString.Bytes)
	return
}

func newGam(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// ///////// //
// SECP256K1
type Secp256k1 secp256k1.PrivateKey

func (a *Secp256k1) Name() string {
	return "SECP256K1-ECIES"
}

func (a *Secp256k1) Type() bool {
	return false
}

func (a *Secp256k1) KeyLength() int {
	return 256
}

func (a *Secp256k1) Marshal() []byte {
	buf, _, err := marshal((*secp256k1.PrivateKey)(a))
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
	k, err := parse(key)
	if err != nil {
		_, errr := parsePub(key)
		if errr == nil {
			return fmt.Errorf("is a public key")
		}
	}
	if err != nil {
		err = fmt.Errorf("not a private key: %v", err)
	}
	a = (*Secp256k1)(k)
	return
}

func (a *Secp256k1) Encrypt(input ...[]byte) (result []byte, err error) {
	ikey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return
	}
	ikeyByt := ikey.PubKey().SerializeCompressed()
	ikeyLen := len(ikeyByt)

	cek := sha256.Sum256(secp256k1.GenerateSharedSecret(ikey, (*secp256k1.PrivateKey)(a).PubKey()))
	gcm, err := newGam(cek[:])
	if err != nil {
		return
	}

	iv := make([]byte, gcm.NonceSize()) // Since a new ephemeral key is generated for every message ensuring the cek is not re-used, the nonce can be all zeros
	result = make([]byte, 4+ikeyLen)
	binary.LittleEndian.PutUint32(result, uint32(ikeyLen)) // record the length of the internal public key first
	copy(result[4:], ikeyByt)                              // follows with the actual internal public key bytes

	result = gcm.Seal(result, iv, input[0], ikeyByt)
	return
}

func (a *Secp256k1) Decrypt(input ...[]byte) ([]byte, error) {
	ikeyLen := binary.LittleEndian.Uint32(input[0][:4]) + 4
	ikeyPub, err := secp256k1.ParsePubKey(input[0][4:ikeyLen])
	if err != nil {
		return nil, err
	}

	cek := sha256.Sum256(secp256k1.GenerateSharedSecret((*secp256k1.PrivateKey)(a), ikeyPub))
	gcm, err := newGam(cek[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, gcm.NonceSize())
	return gcm.Open(nil, iv, input[0][ikeyLen:], input[0][4:ikeyLen])
}
