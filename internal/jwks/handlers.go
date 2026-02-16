package jwks

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type server struct {
	km  *KeyManager
	now func() time.Time
}

func RegisterRoutes(mux *http.ServeMux, km *KeyManager) {
	s := &server{km: km, now: time.Now}

	mux.HandleFunc("/jwks", s.handleJWKS)
	mux.HandleFunc("/auth", s.handleAuth)

	// Optional: common well-known path for JWKS.
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
}

func (s *server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	b, err := s.km.JWKS(s.now())
	if err != nil {
		http.Error(w, "failed to build jwks", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// If "expired" query parameter is present (any value), use expired key and expired exp.
	issueExpired := false
	if _, ok := r.URL.Query()["expired"]; ok {
		issueExpired = true
	}

	var kp KeyPair
	if issueExpired {
		kp = s.km.Expired()
	} else {
		kp = s.km.Active()
	}

	now := s.now()

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

	// Return JSON to be unambiguous for clients.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	_ = json.NewEncoder(w).Encode(map[string]string{
		"token": strings.TrimSpace(signed),
	})
}
