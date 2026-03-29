package jwks

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// server holds a reference to the DB and a clock function for testability.
type server struct {
	db  *DB
	now func() time.Time
}

// RegisterRoutes wires up the HTTP endpoints.
func RegisterRoutes(mux *http.ServeMux, db *DB) {
	s := &server{db: db, now: time.Now}

	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)
}

// handleJWKS serves all unexpired public keys as a JWKS JSON response.
func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	pairs, err := s.db.GetAllValidKeys(s.now())
	if err != nil {
		http.Error(w, "failed to read keys", http.StatusInternalServerError)
		return
	}

	keys := make([]JWK, 0, len(pairs))
	for _, kp := range pairs {
		keys = append(keys, publicJWK(kp))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(JWKS{Keys: keys})
}

// handleAuth issues a signed JWT. Uses an expired key if ?expired is in the query.
func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	now := s.now()

	// Determine whether to use an expired or valid key.
	_, issueExpired := r.URL.Query()["expired"]

	var (
		kp  *KeyPair
		err error
	)
	if issueExpired {
		kp, err = s.db.GetExpiredKey(now)
	} else {
		kp, err = s.db.GetValidKey(now)
	}
	if err != nil {
		http.Error(w, "no suitable key found", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iat": now.Unix(),
		"exp": kp.Expiry.Unix(),
		"iss": "jwks-server",
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kp.KID

	signed, err := tok.SignedString(kp.Priv)
	if err != nil {
		http.Error(w, "failed to sign jwt", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": strings.TrimSpace(signed),
	})
}
