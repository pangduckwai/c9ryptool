package asym

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	ecies "github.com/ecies/go/v2"
)

func marshalPubEciesgo(inp *ecies.PublicKey) (pub, pubkeyBytes []byte, err error) {
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

func marshalEciesgo(key *ecies.PrivateKey) (prv, pub []byte, err error) {
	pub, pubkeyBytes, err := marshalPubEciesgo(key.PublicKey) // Public key
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

// ///////////////// //
// secp256k1 eciesgo
type Secp256k1Eciesgo struct {
	PrivateKey *ecies.PrivateKey
	PublicKey  *ecies.PublicKey
}

func (a *Secp256k1Eciesgo) Name() string {
	return "ECIES-SECP256K1-ECIESGO"
}

func (a *Secp256k1Eciesgo) Type() bool {
	return false
}

func (a *Secp256k1Eciesgo) KeyLength() int {
	return 256
}

func (a *Secp256k1Eciesgo) GetKey() []byte {
	buf, _, err := marshalEciesgo(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Eciesgo) GetPublicKey() []byte {
	buf, _, err := marshalPubEciesgo(a.PublicKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Eciesgo) PopulateKey(key []byte) (err error) {
	parse := func(inp []byte) (prv *ecies.PrivateKey, pub *ecies.PublicKey, err error) {
		var prvKey ecPrivateKey
		blk, _ := pem.Decode(inp)
		_, err = asn1.Unmarshal(blk.Bytes, &prvKey)
		if err != nil {
			return
		}
		prv = ecies.NewPrivateKeyFromBytes(prvKey.PrivateKey)
		pub, err = ecies.NewPublicKeyFromBytes(prvKey.PublicKey.Bytes)
		return
	}
	parsePub := func(inp []byte) (pub *ecies.PublicKey, err error) {
		var pubKey pkixPublicKey
		blk, _ := pem.Decode(inp)
		_, err = asn1.Unmarshal(blk.Bytes, &pubKey)
		if err != nil {
			return
		}
		pub, err = ecies.NewPublicKeyFromBytes(pubKey.BitString.Bytes)
		return
	}

	if key == nil {
		a.PrivateKey, err = ecies.GenerateKey()
		if err != nil {
			return
		}
		a.PublicKey = a.PrivateKey.PublicKey
	} else {
		a.PrivateKey, a.PublicKey, err = parse(key)
		if err != nil {
			a.PublicKey, err = parsePub(key)
			if err != nil {
				return
			}
		}
	}
	return
}

func (a *Secp256k1Eciesgo) Encrypt(input ...[]byte) ([][]byte, error) {
	if a.PublicKey == nil {
		return nil, fmt.Errorf("key not ready")
	}
	rst, err := ecies.Encrypt(a.PublicKey, input[0])
	if err != nil {
		return nil, err
	}
	rsts := make([][]byte, 0)
	rsts = append(rsts, rst)
	return rsts, nil
}

func (a *Secp256k1Eciesgo) Decrypt(input ...[]byte) ([][]byte, error) {
	if a.PrivateKey == nil {
		if a.PublicKey != nil {
			return nil, fmt.Errorf("public key cannot be used for decryption")
		}
		return nil, fmt.Errorf("keys not ready")
	}
	rst, err := ecies.Decrypt(a.PrivateKey, input[0])
	if err != nil {
		return nil, err
	}
	rsts := make([][]byte, 0)
	rsts = append(rsts, rst)
	return rsts, nil
}
