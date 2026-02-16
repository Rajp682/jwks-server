package jwks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestServer(t *testing.T) (*KeyManager, *httptest.Server) {
	t.Helper()

	km, err := NewKeyManager(2*time.Hour, -2*time.Hour) // active valid; expired in past
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	mux := http.NewServeMux()
	RegisterRoutes(mux, km)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return km, ts
}

func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	km, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var out JWKS
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}

	if len(out.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(out.Keys))
	}

	active := km.Active()
	expired := km.Expired()

	if out.Keys[0].KID != active.KID {
		t.Fatalf("expected active kid %s, got %s", active.KID, out.Keys[0].KID)
	}
	if out.Keys[0].KID == expired.KID {
		t.Fatalf("expired key should not be in jwks")
	}
}

func TestAuthIssuesValidJWTWithKidHeader(t *testing.T) {
	km, ts := setupTestServer(t)
	active := km.Active()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	if body.Token == "" {
		t.Fatalf("expected token")
	}

	parsed, err := jwt.Parse(body.Token, func(token *jwt.Token) (any, error) {
		// Ensure kid is present and correct.
		kid, _ := token.Header["kid"].(string)
		if kid != active.KID {
			t.Fatalf("expected kid %s, got %s", active.KID, kid)
		}
		return &active.Priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		t.Fatalf("jwt parse/verify failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected valid token")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("expected map claims")
	}
	if int64(claims["exp"].(float64)) != active.Expiry.Unix() {
		t.Fatalf("expected exp %d, got %v", active.Expiry.Unix(), claims["exp"])
	}
}

func TestAuthExpiredQuerySignsWithExpiredKeyAndIsExpired(t *testing.T) {
	km, ts := setupTestServer(t)
	expired := km.Expired()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/auth?expired=true", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /auth?expired=true: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode auth response: %v", err)
	}
	if body.Token == "" {
		t.Fatalf("expected token")
	}

	// Verify signature WITHOUT failing on exp validation.
	parsed, err := jwt.Parse(body.Token, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != expired.KID {
			t.Fatalf("expected expired kid %s, got %s", expired.KID, kid)
		}
		return &expired.Priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())

	if err != nil {
		t.Fatalf("jwt parse (signature verify) failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected signature-valid token")
	}

	claims := parsed.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	if exp != expired.Expiry.Unix() {
		t.Fatalf("expected exp %d, got %d", expired.Expiry.Unix(), exp)
	}
	if exp >= time.Now().Unix() {
		t.Fatalf("expected expired exp in the past, got %d", exp)
	}

	// Confirm JWKS does NOT include this expired key.
	jwksResp, err := http.Get(ts.URL + "/jwks")
	if err != nil {
		t.Fatalf("GET /jwks: %v", err)
	}
	defer jwksResp.Body.Close()

	var out JWKS
	if err := json.NewDecoder(jwksResp.Body).Decode(&out); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	for _, k := range out.Keys {
		if k.KID == expired.KID {
			t.Fatalf("expired key should not be served in jwks")
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/auth")
	if err != nil {
		t.Fatalf("GET /auth: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}
