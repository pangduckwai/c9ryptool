package asym

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func marshalPubDecred(key *secp256k1.PublicKey) (pub, pubkeyBytes []byte, err error) {
	pubkeyBytes = key.SerializeUncompressed()
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

func marshalDecred(key *secp256k1.PrivateKey) (prv, pub []byte, err error) {
	pub, pubkeyBytes, err := marshalPubDecred(key.PubKey()) // Public key
	if err != nil {
		return
	}
	dsa := key.ToECDSA() // Private key
	privateKeyBytes := make([]byte, (dsa.Curve.Params().N.BitLen()+7)/8)
	prv, err = asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    dsa.D.FillBytes(privateKeyBytes),
		NamedCurveOID: oid,
		PublicKey: asn1.BitString{
			Bytes: pubkeyBytes,
		},
	})
	return
}

// Useful commands
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

var oid = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

func newGam(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

// /////////////// //
// secp256k1 decred
type Secp256k1Decred struct {
	PrivateKey *secp256k1.PrivateKey
	PublicKey  *secp256k1.PublicKey
}

func (a *Secp256k1Decred) Name() string {
	return "ECIES-SECP256K1-DECRED"
}

func (a *Secp256k1Decred) Type() bool {
	return false
}

func (a *Secp256k1Decred) KeyLength() int {
	return 256
}

func (a *Secp256k1Decred) GetKey() []byte {
	buf, _, err := marshalDecred(a.PrivateKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Decred) GetPublicKey() []byte {
	buf, _, err := marshalPubDecred(a.PublicKey)
	if err != nil {
		panic(err)
	}
	rst := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	})
	return rst
}

func (a *Secp256k1Decred) PopulateKey(key []byte) (err error) {
	parse := func(inp []byte) (prv *secp256k1.PrivateKey, pub *secp256k1.PublicKey, err error) {
		var prvKey ecPrivateKey
		blk, _ := pem.Decode(inp)
		_, err = asn1.Unmarshal(blk.Bytes, &prvKey)
		if err != nil {
			return
		}
		prv = secp256k1.PrivKeyFromBytes(prvKey.PrivateKey)
		pub, err = secp256k1.ParsePubKey(prvKey.PublicKey.Bytes)
		return
	}
	parsePub := func(inp []byte) (pub *secp256k1.PublicKey, err error) {
		var pubKey pkixPublicKey
		blk, _ := pem.Decode(inp)
		_, err = asn1.Unmarshal(blk.Bytes, &pubKey)
		if err != nil {
			return
		}
		pub, err = secp256k1.ParsePubKey(pubKey.BitString.Bytes)
		return
	}

	if key == nil {
		a.PrivateKey, err = secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
		if err != nil {
			return
		}
		a.PublicKey = a.PrivateKey.PubKey()
	} else {
		a.PrivateKey, a.PublicKey, err = parse(key)
		if err != nil {
			a.PublicKey, err = parsePub(key)
			if err == nil {
				return
			}
		}
	}
	return
}

func (a *Secp256k1Decred) Encrypt(input ...[]byte) (result []byte, err error) {
	if a.PublicKey == nil {
		return nil, fmt.Errorf("key not ready")
	}

	ikey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return
	}
	ikeyByt := ikey.PubKey().SerializeCompressed()
	ikeyLen := len(ikeyByt)

	cek := sha256.Sum256(secp256k1.GenerateSharedSecret(ikey, a.PublicKey))
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

func (a *Secp256k1Decred) Decrypt(input ...[]byte) ([]byte, error) {
	if a.PrivateKey == nil {
		if a.PublicKey != nil {
			return nil, fmt.Errorf("public key cannot be used for decryption")
		}
		return nil, fmt.Errorf("keys not ready")
	}

	ikeyLen := binary.LittleEndian.Uint32(input[0][:4]) + 4
	ikeyPub, err := secp256k1.ParsePubKey(input[0][4:ikeyLen])
	if err != nil {
		return nil, err
	}

	cek := sha256.Sum256(secp256k1.GenerateSharedSecret(a.PrivateKey, ikeyPub))
	gcm, err := newGam(cek[:])
	if err != nil {
		return nil, err
	}

	iv := make([]byte, gcm.NonceSize())
	return gcm.Open(nil, iv, input[0][ikeyLen:], input[0][4:ikeyLen])
}
