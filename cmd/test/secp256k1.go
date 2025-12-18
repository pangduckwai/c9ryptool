package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// openssl ec -in prv.pem -text -noout
// openssl ec -pubin -in pub.pem -text -noout
// openssl pkey -in prv.pem -pubout -out pub.pem

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

func marshal(
	inp *secp256k1.PrivateKey,
) (
	prv []byte,
	pub []byte,
	err error,
) {
	oid := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
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
