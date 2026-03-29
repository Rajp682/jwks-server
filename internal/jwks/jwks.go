package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"time"
)

// KeyPair holds an RSA private key with metadata read from the DB.
type KeyPair struct {
	KID    string
	Expiry time.Time
	Priv   *rsa.PrivateKey
}

// JWKS is the JSON Web Key Set response structure.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a single JSON Web Key (public RSA key).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// publicJWK builds a JWK from a KeyPair's public key components.
func publicJWK(kp KeyPair) JWK {
	pub := kp.Priv.PublicKey
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: kp.KID,
		N:   base64urlBigInt(pub.N),
		E:   base64urlBigInt(big.NewInt(int64(pub.E))),
	}
}

func base64urlBigInt(x *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(x.Bytes())
}
