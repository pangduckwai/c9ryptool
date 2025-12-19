package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"

	ecies "github.com/ecies/go/v2"
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

func marshal(key *ecies.PrivateKey) (prv, pub []byte, err error) {
	pub, pubkeyBytes, err := marshalPub(key.PublicKey) // Public key
	if err != nil {
		return
	}
	privateKeyBytes := make([]byte, (key.Curve.Params().N.BitLen()+7)/8) // Private key
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

func marshalPub(inp *ecies.PublicKey) (pub, pubkeyBytes []byte, err error) {
	pubkeyBytes = inp.Bytes(false)

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

func parse(inp []byte) (prv *ecies.PrivateKey, err error) {
	blk, _ := pem.Decode(inp)
	var privKey ecPrivateKey
	_, err = asn1.Unmarshal(blk.Bytes, &privKey)
	if err != nil {
		return
	}
	prv = ecies.NewPrivateKeyFromBytes(privKey.PrivateKey)
	return
}

func parsePub(inp []byte) (pub *ecies.PublicKey, err error) {
	var pubKey pkixPublicKey
	blk, _ := pem.Decode(inp)
	_, err = asn1.Unmarshal(blk.Bytes, &pubKey)
	if err != nil {
		return
	}
	pub, err = ecies.NewPublicKeyFromBytes(pubKey.BitString.Bytes)
	return
}
