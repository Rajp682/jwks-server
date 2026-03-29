package main

import (
	"log"
	"net/http"
	"os"

	"github.com/Rajp682/jwks-server/internal/jwks"
)

func main() {
	// Open (or create) the SQLite database file.
	db, err := jwks.OpenDB("totally_not_my_privateKeys.db")
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer db.Close()

	// Seed the DB with one valid and one expired key on startup.
	if err := db.SeedKeys(); err != nil {
		log.Fatalf("failed to seed keys: %v", err)
	}

	mux := http.NewServeMux()
	jwks.RegisterRoutes(mux, db)

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
