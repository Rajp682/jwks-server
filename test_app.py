import os
os.environ["NOT_MY_KEY"] = "MySuperSecretKey1234567890ABCDEF"

import pytest
import json
from app import app, init_db, DB_FILE
import sqlite3

@pytest.fixture
def client():
    app.config["TESTING"] = True
    # Use a fresh test database
    global DB_FILE
    import app as app_module
    app_module.DB_FILE = "test.db"
    # Remove old test db if exists
    if os.path.exists("test.db"):
        os.remove("test.db")
    app_module.init_db()
    with app.test_client() as client:
        yield client
    if os.path.exists("test.db"):
        os.remove("test.db")

def test_register(client):
    res = client.post("/register",
        data=json.dumps({"username": "alice", "email": "alice@test.com"}),
        content_type="application/json")
    assert res.status_code == 201
    data = res.get_json()
    assert "password" in data
    assert len(data["password"]) > 0

def test_register_duplicate(client):
    client.post("/register",
        data=json.dumps({"username": "bob", "email": "bob@test.com"}),
        content_type="application/json")
    res = client.post("/register",
        data=json.dumps({"username": "bob", "email": "bob@test.com"}),
        content_type="application/json")
    assert res.status_code == 409

def test_register_missing_fields(client):
    res = client.post("/register",
        data=json.dumps({"username": "nomail"}),
        content_type="application/json")
    assert res.status_code == 400

def test_auth(client):
    res = client.post("/auth",
        data=json.dumps({"username": "alice"}),
        content_type="application/json")
    assert res.status_code == 200
    data = res.get_json()
    assert "token" in data

def test_auth_expired(client):
    res = client.post("/auth?expired=true",
        data=json.dumps({}),
        content_type="application/json")
    assert res.status_code == 200
    data = res.get_json()
    assert "token" in data

def test_jwks(client):
    res = client.get("/.well-known/jwks.json")
    assert res.status_code == 200
    data = res.get_json()
    assert "keys" in data
    assert len(data["keys"]) > 0

def test_auth_logs(client):
    client.post("/register",
        data=json.dumps({"username": "loguser", "email": "log@test.com"}),
        content_type="application/json")
    client.post("/auth",
        data=json.dumps({"username": "loguser"}),
        content_type="application/json")
    import app as app_module
    conn = sqlite3.connect(app_module.DB_FILE)
    logs = conn.execute("SELECT * FROM auth_logs").fetchall()
    conn.close()
    assert len(logs) > 0

def test_rate_limit(client):
    for _ in range(10):
        client.post("/auth",
            data=json.dumps({}),
            content_type="application/json")
    res = client.post("/auth",
        data=json.dumps({}),
        content_type="application/json")
    assert res.status_code == 429
