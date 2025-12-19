package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

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

func parse(
	inp []byte,
) (
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
