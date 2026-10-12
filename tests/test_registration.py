"""Testes do cadastro e do armazenamento seguro."""

import sqlite3

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from shared.crypto import decrypt_secret, encrypt_secret
from store import database
from store.main import app
from store.security import init_or_verify_master_passphrase, verify_password

PASSPHRASE = "frase-de-teste-grande-e-aleatoria"
USER = {"name": "Aluno Teste", "email": "aluno@example.com", "password": "SenhaDeTeste#2026"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test_store.db")
    database.init_db()
    init_or_verify_master_passphrase(PASSPHRASE)
    app.state.master_passphrase = PASSPHRASE
    with TestClient(app) as test_client:
        yield test_client
    app.state.master_passphrase = None


def test_register_hash_and_encrypted_totp(client):
    response = client.post("/register", json=USER)
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == USER["email"]
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert len(body["totp_secret"]) == 32
    assert "password" not in body

    with database.connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (USER["email"],)).fetchone()
    assert row is not None
    assert row["password_hash"].startswith("$argon2id$")
    assert row["password_hash"] != USER["password"]
    assert verify_password(row["password_hash"], USER["password"])
    assert body["totp_secret"].encode("utf-8") not in row["totp_ciphertext"]
    assert decrypt_secret(
        row["totp_salt"], row["totp_ciphertext"], PASSPHRASE, f"user:{USER['email']}"
    ) == body["totp_secret"]


def test_duplicate_email_is_rejected(client):
    assert client.post("/register", json=USER).status_code == 201
    result = client.post("/register", json={**USER, "email": "ALUNO@example.com"})
    assert result.status_code == 409


def test_short_password_is_rejected(client):
    result = client.post("/register", json={**USER, "password": "123"})
    assert result.status_code == 422


def test_tampered_ciphertext_is_rejected():
    salt, ciphertext = encrypt_secret("SEGREDO", PASSPHRASE, "user:teste@example.com")
    damaged = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with pytest.raises(InvalidTag):
        decrypt_secret(salt, damaged, PASSPHRASE, "user:teste@example.com")


def test_master_password_is_verified(client):
    init_or_verify_master_passphrase(PASSPHRASE)
    with pytest.raises(ValueError, match="Frase-mestra incorreta"):
        init_or_verify_master_passphrase("outra-frase-mestra-muito-longa")
