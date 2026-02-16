# JWKS Server (Educational)

A small JWKS server that:
- Generates RSA keypairs with `kid` and expiry
- Serves only **unexpired** public keys via JWKS
- Issues JWTs via `POST /auth`
- Issues expired JWTs when `?expired=true` is present

## Endpoints

### GET /jwks
Returns JWKS JSON with only unexpired keys.

Also available at:
- `GET /.well-known/jwks.json`

### POST /auth
Returns a signed JWT using the active key.

### POST /auth?expired=true
Returns a signed JWT using the expired key, with an expired `exp`.

## Run
```bash
go mod tidy
go run ./cmd/server
