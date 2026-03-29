package jwks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setupTestDB(t *testing.T) *DB {
	t.Helper()
	f, err := os.CreateTemp("", "test-keys-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	db, err := OpenDB(f.Name())
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	if err := db.SeedKeys(); err != nil {
		t.Fatalf("SeedKeys: %v", err)
	}
	return db
}

func setupTestServer(t *testing.T) (*DB, *httptest.Server) {
	t.Helper()
	db := setupTestDB(t)

	mux := http.NewServeMux()
	RegisterRoutes(mux, db)

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return db, ts
}

func TestJWKSOnlyServesUnexpiredKeys(t *testing.T) {
	_, ts := setupTestServer(t)

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
		t.Fatalf("expected 1 unexpired key, got %d", len(out.Keys))
	}
}

func TestWellKnownJWKS(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("GET /.well-known/jwks.json: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestAuthIssuesValidJWT(t *testing.T) {
	db, ts := setupTestServer(t)

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
		t.Fatalf("decode: %v", err)
	}
	if body.Token == "" {
		t.Fatalf("expected token")
	}

	kp, err := db.GetValidKey(time.Now())
	if err != nil {
		t.Fatalf("GetValidKey: %v", err)
	}

	parsed, err := jwt.Parse(body.Token, func(token *jwt.Token) (any, error) {
		return &kp.Priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))

	if err != nil {
		t.Fatalf("jwt parse failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected valid token")
	}
}

func TestAuthExpiredReturnsExpiredJWT(t *testing.T) {
	db, ts := setupTestServer(t)

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
		t.Fatalf("decode: %v", err)
	}

	kp, err := db.GetExpiredKey(time.Now())
	if err != nil {
		t.Fatalf("GetExpiredKey: %v", err)
	}

	parsed, err := jwt.Parse(body.Token, func(token *jwt.Token) (any, error) {
		return &kp.Priv.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithoutClaimsValidation())

	if err != nil {
		t.Fatalf("jwt parse failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("expected valid token")
	}

	claims := parsed.Claims.(jwt.MapClaims)
	exp := int64(claims["exp"].(float64))
	if exp >= time.Now().Unix() {
		t.Fatalf("expected expired token")
	}
}

func TestMethodNotAllowedAuth(t *testing.T) {
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

func TestMethodNotAllowedJWKS(t *testing.T) {
	_, ts := setupTestServer(t)

	resp, err := http.Post(ts.URL+"/jwks", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /jwks: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

func TestDBSaveAndRetrieveKey(t *testing.T) {
	db := setupTestDB(t)

	kp, err := db.GetValidKey(time.Now())
	if err != nil {
		t.Fatalf("GetValidKey: %v", err)
	}
	if kp.Priv == nil {
		t.Fatal("expected non-nil private key")
	}
	if kp.Expiry.Before(time.Now()) {
		t.Fatalf("expected future expiry")
	}
}

func TestGetAllValidKeys(t *testing.T) {
	db := setupTestDB(t)

	keys, err := db.GetAllValidKeys(time.Now())
	if err != nil {
		t.Fatalf("GetAllValidKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 valid key, got %d", len(keys))
	}
}
