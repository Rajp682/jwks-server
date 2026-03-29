package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// DB wraps a SQLite database for key storage.
type DB struct {
	conn *sql.DB
}

// OpenDB opens (or creates) the SQLite database file and ensures the keys table exists.
func OpenDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Create the keys table if it doesn't already exist.
	_, err = conn.Exec(`CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`)
	if err != nil {
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &DB{conn: conn}, nil
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// SaveKey serializes the RSA private key to PKCS1 PEM format and inserts it into the DB.
func (db *DB) SaveKey(priv *rsa.PrivateKey, exp time.Time) (int64, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	// Parameterized query to prevent SQL injection.
	res, err := db.conn.Exec(
		`INSERT INTO keys(key, exp) VALUES (?, ?)`,
		pemBytes,
		exp.Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("insert key: %w", err)
	}
	return res.LastInsertId()
}

// dbKeyRow is a raw row read from the keys table.
type dbKeyRow struct {
	kid    int64
	keyPEM []byte
	exp    int64
}

// GetValidKey reads one unexpired key from the DB (exp > now).
func (db *DB) GetValidKey(now time.Time) (*KeyPair, error) {
	row := db.conn.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1`,
		now.Unix(),
	)
	return scanKeyPair(row)
}

// GetExpiredKey reads one expired key from the DB (exp <= now).
func (db *DB) GetExpiredKey(now time.Time) (*KeyPair, error) {
	row := db.conn.QueryRow(
		`SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1`,
		now.Unix(),
	)
	return scanKeyPair(row)
}

// GetAllValidKeys reads all unexpired keys from the DB.
func (db *DB) GetAllValidKeys(now time.Time) ([]KeyPair, error) {
	rows, err := db.conn.Query(
		`SELECT kid, key, exp FROM keys WHERE exp > ?`,
		now.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("query valid keys: %w", err)
	}
	defer rows.Close()

	var pairs []KeyPair
	for rows.Next() {
		var r dbKeyRow
		if err := rows.Scan(&r.kid, &r.keyPEM, &r.exp); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		kp, err := decodeKeyPair(r)
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, kp)
	}
	return pairs, rows.Err()
}

// SeedKeys generates one valid key (expires in 1h) and one expired key and saves both.
func (db *DB) SeedKeys() error {
	activePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate active key: %w", err)
	}
	if _, err := db.SaveKey(activePriv, time.Now().Add(1*time.Hour)); err != nil {
		return fmt.Errorf("save active key: %w", err)
	}

	expiredPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate expired key: %w", err)
	}
	if _, err := db.SaveKey(expiredPriv, time.Now().Add(-1*time.Hour)); err != nil {
		return fmt.Errorf("save expired key: %w", err)
	}

	return nil
}

// scanKeyPair scans a single *sql.Row into a KeyPair.
func scanKeyPair(row *sql.Row) (*KeyPair, error) {
	var r dbKeyRow
	if err := row.Scan(&r.kid, &r.keyPEM, &r.exp); err != nil {
		return nil, fmt.Errorf("scan key: %w", err)
	}
	kp, err := decodeKeyPair(r)
	if err != nil {
		return nil, err
	}
	return &kp, nil
}

// decodeKeyPair converts a raw DB row into a KeyPair by deserializing the PEM key.
func decodeKeyPair(r dbKeyRow) (KeyPair, error) {
	block, _ := pem.Decode(r.keyPEM)
	if block == nil {
		return KeyPair{}, fmt.Errorf("failed to decode PEM for kid %d", r.kid)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return KeyPair{}, fmt.Errorf("parse private key kid %d: %w", r.kid, err)
	}
	return KeyPair{
		KID:    fmt.Sprintf("%d", r.kid),
		Expiry: time.Unix(r.exp, 0),
		Priv:   priv,
	}, nil
}
