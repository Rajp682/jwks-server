package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/yourname/jwks-server/internal/jwks"
)

func main() {
	// Active key expires in 24h; expired key expired 1h ago.
	km, err := jwks.NewKeyManager(24*time.Hour, -1*time.Hour)
	if err != nil {
		log.Fatalf("failed to init key manager: %v", err)
	}

	mux := http.NewServeMux()
	jwks.RegisterRoutes(mux, km)

	addr := ":8080"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}

	log.Printf("JWKS server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
