"""Testes do login em dois fatores e das sessões."""

import base64

import pytest
from fastapi.testclient import TestClient

from store import database
from store.auth import finish_login, start_login, AuthenticationError
from store.main import app
from store.security import init_or_verify_master_passphrase
from store.totp import generate_totp, verify_totp

PASSPHRASE = "frase-de-teste-grande-e-aleatoria"
USER = {"name": "Aluno Teste", "email": "aluno@example.com", "password": "SenhaDeTeste#2026"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test_store.db")
    database.init_db()
    init_or_verify_master_passphrase(PASSPHRASE)
    app.state.master_passphrase = PASSPHRASE
    with TestClient(app, client=("127.0.0.1", 54000)) as api:
        yield api
    app.state.master_passphrase = None


def register(client):
    resp = client.post("/register", json=USER)
    assert resp.status_code == 201
    return resp.json()["totp_secret"]


def password_login(client):
    resp = client.post("/login/password", json={
        "email": USER["email"], "password": USER["password"],
    })
    assert resp.status_code == 200
    return resp.json()["challenge"]


def totp_code(secret):
    import time
    return generate_totp(secret, int(time.time()) // 30)


def test_rfc6238_known_vector():
    secret = base64.b32encode(b"12345678901234567890").decode("ascii")
    assert generate_totp(secret, 59 // 30) == "287082"
    assert verify_totp(secret, "287082", None, now=59) == 1


def test_password_and_totp_login_profile_and_logout(client):
    secret = register(client)
    challenge = password_login(client)
    result = client.post("/login/totp", json={
        "challenge": challenge, "code": totp_code(secret),
    })
    assert result.status_code == 200
    access_token = result.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}
    profile = client.get("/me", headers=headers)
    assert profile.status_code == 200
    assert profile.json()["email"] == USER["email"]
    assert "password_hash" not in profile.json()
    assert client.post("/logout", headers=headers).status_code == 204
    assert client.get("/me", headers=headers).status_code == 401


def test_wrong_password_cannot_get_challenge(client):
    register(client)
    result = client.post("/login/password", json={
        "email": USER["email"], "password": "senha-incorreta",
    })
    assert result.status_code == 401


def test_totp_attempt_limit(client):
    secret = register(client)
    challenge = password_login(client)
    valid_code = totp_code(secret)
    wrong = "000000" if valid_code != "000000" else "999999"
    for _ in range(5):
        assert client.post("/login/totp", json={
            "challenge": challenge, "code": wrong,
        }).status_code == 401
    assert client.post("/login/totp", json={
        "challenge": challenge, "code": valid_code,
    }).status_code == 401


def test_totp_cannot_be_reused(client):
    secret = register(client)
    challenge1 = password_login(client)
    challenge2 = password_login(client)
    code = totp_code(secret)
    assert client.post("/login/totp", json={
        "challenge": challenge1, "code": code,
    }).status_code == 200
    assert client.post("/login/totp", json={
        "challenge": challenge2, "code": code,
    }).status_code == 401


def test_expired_challenge_and_unknown_session(client):
    register(client)
    challenge = password_login(client)
    with database.connect() as conn:
        conn.execute("UPDATE login_challenges SET expires_at = 0")
    assert client.post("/login/totp", json={
        "challenge": challenge, "code": "000000",
    }).status_code == 401
    assert client.get("/me", headers={
        "Authorization": "Bearer invalid-token",
    }).status_code == 401


def test_password_challenge_bound_to_observed_ip(client):
    register(client)
    challenge = start_login(USER["email"], USER["password"], "127.0.0.1")
    with pytest.raises(AuthenticationError):
        finish_login(challenge, "000000", "127.0.0.2", PASSPHRASE)


def test_expired_session_is_rejected(client):
    secret = register(client)
    challenge = password_login(client)
    result = client.post("/login/totp", json={
        "challenge": challenge, "code": totp_code(secret),
    })
    assert result.status_code == 200
    token = result.json()["access_token"]
    with database.connect() as conn:
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()
        assert stored["token_hash"] != token
        conn.execute("UPDATE sessions SET expires_at = 0")
    assert client.get("/me", headers={
        "Authorization": f"Bearer {token}",
    }).status_code == 401


def test_init_db_updates_existing_users_table(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "legacy.db")
    with database.connect() as conn:
        conn.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            totp_ciphertext BLOB NOT NULL,
            totp_salt BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )""")
    database.init_db()
    with database.connect() as conn:
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    assert "last_totp_step" in columns
