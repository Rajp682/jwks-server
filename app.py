import os
import sqlite3
import uuid
import time
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
import jwt
import base64

app = Flask(__name__)

# --- Load AES encryption key from environment ---
AES_KEY = os.environ.get("NOT_MY_KEY", "").encode("utf-8")
if len(AES_KEY) != 32:
    raise ValueError("NOT_MY_KEY must be exactly 32 characters for AES-256")

DB_FILE = "totally_not_my_privateKeys.db"

# --- AES Encrypt / Decrypt helpers ---
def encrypt_private_key(pem_bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Pad to multiple of 16
    pad_len = 16 - (len(pem_bytes) % 16)
    pem_bytes += bytes([pad_len] * pad_len)
    encrypted = encryptor.update(pem_bytes) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode("utf-8")

def decrypt_private_key(encrypted_b64):
    raw = base64.b64decode(encrypted_b64)
    iv, encrypted = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    # Remove padding
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# --- Database setup ---
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()

    # Generate one valid key and one expired key
    _generate_and_store_key(expired=False)
    _generate_and_store_key(expired=True)
    conn.close()

def _generate_and_store_key(expired=False):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_pem = encrypt_private_key(pem)
    exp = int(time.time()) + (-3600 if expired else 3600)
    conn = get_db()
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (encrypted_pem, exp))
    conn.commit()
    conn.close()

# --- Rate limiter ---
request_counts = {}
RATE_LIMIT = 10  # requests per second

def is_rate_limited(ip):
    now = time.time()
    window_start = now - 1.0
    timestamps = request_counts.get(ip, [])
    timestamps = [t for t in timestamps if t > window_start]
    if len(timestamps) >= RATE_LIMIT:
        return True
    timestamps.append(now)
    request_counts[ip] = timestamps
    return False

# --- JWT helpers ---
def int_to_base64url(n):
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode("utf-8")

# --- Routes ---

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    conn = get_db()
    now = int(time.time())
    rows = conn.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,)).fetchall()
    conn.close()
    keys = []
    for row in rows:
        pem = decrypt_private_key(row["key"])
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        private_key = load_pem_private_key(pem, password=None, backend=default_backend())
        pub = private_key.public_key().public_numbers()
        keys.append({
            "kty": "RSA",
            "kid": str(row["kid"]),
            "use": "sig",
            "n": int_to_base64url(pub.n),
            "e": int_to_base64url(pub.e),
        })
    return jsonify({"keys": keys})


@app.route("/auth", methods=["POST"])
def auth():
    ip = request.remote_addr

    if is_rate_limited(ip):
        return jsonify({"error": "Too Many Requests"}), 429

    expired = request.args.get("expired", "false").lower() == "true"
    now = int(time.time())

    conn = get_db()
    if expired:
        row = conn.execute("SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (now,)).fetchone()
    else:
        row = conn.execute("SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (now,)).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "No suitable key found"}), 404

    pem = decrypt_private_key(row["key"])
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    private_key = load_pem_private_key(pem, password=None, backend=default_backend())

    payload = {
        "sub": "userABC",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.fromtimestamp(row["exp"], tz=timezone.utc),
    }
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": str(row["kid"])})

    # Log the request
    data = request.get_json(silent=True) or {}
    username = data.get("username")
    user_id = None
    if username:
        conn = get_db()
        user = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        if user:
            user_id = user["id"]

    conn = get_db()
    conn.execute(
        "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
        (ip, user_id)
    )
    conn.commit()
    conn.close()

    return jsonify({"token": token})


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data or "username" not in data or "email" not in data:
        return jsonify({"error": "username and email required"}), 400

    username = data["username"]
    email = data["email"]
    password = str(uuid.uuid4())

    ph = PasswordHasher()
    password_hash = ph.hash(password)

    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, password_hash, email)
        )
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists"}), 409

    return jsonify({"password": password}), 201


if __name__ == "__main__":
    init_db()
    app.run(port=8080, debug=True)
