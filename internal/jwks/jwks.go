package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"time"

	"github.com/google/uuid"
)

// KeyPair holds an RSA keypair with associated metadata.
type KeyPair struct {
	KID    string
	Expiry time.Time
	Priv   *rsa.PrivateKey
}

// KeyManager keeps one active and one expired keypair.
// In real systems, you'd rotate keys and keep multiple actives; this matches the assignment needs.
type KeyManager struct {
	mu      sync.RWMutex
	active  KeyPair
	expired KeyPair
}

// NewKeyManager creates one active key and one expired key.
// activeOffset: how far in the future the active key expires (e.g., 24h)
// expiredOffset: how far from now the expired key's expiry is (negative means in the past, e.g., -1h)
func NewKeyManager(activeOffset, expiredOffset time.Duration) (*KeyManager, error) {
	active, err := generateKeyPair(time.Now().Add(activeOffset))
	if err != nil {
		return nil, err
	}
	expired, err := generateKeyPair(time.Now().Add(expiredOffset))
	if err != nil {
		return nil, err
	}
	return &KeyManager{active: active, expired: expired}, nil
}

func generateKeyPair(exp time.Time) (KeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		KID:    uuid.NewString(),
		Expiry: exp,
		Priv:   priv,
	}, nil
}

func (km *KeyManager) Active() KeyPair {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.active
}

func (km *KeyManager) Expired() KeyPair {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.expired
}

// JWKS returns JWKS JSON bytes containing ONLY unexpired public keys.
func (km *KeyManager) JWKS(now time.Time) ([]byte, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make([]JWK, 0, 1)
	if now.Before(km.active.Expiry) {
		keys = append(keys, publicJWK(km.active))
	}

	out := JWKS{Keys: keys}
	return json.Marshal(out)
}

// ---- JWKS structs ----

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// publicJWK builds a minimal RSA public JWK.
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
