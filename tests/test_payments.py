"""Testes integrados: loja, gateway, valor, replay e localização."""

import base64
import json
import time

import pytest
from fastapi.testclient import TestClient

from gateway import database as gdb
from gateway.main import app as gateway_app
from gateway.validation import validate_and_process
from shared.crypto import open_seal, seal
from shared.geo import GeoError, lookup_ip, same_location
from shared.products import PRODUCTS
from store import database as sdb
from store import checkout as shopping
from store.main import app as store_app
from store.security import init_or_verify_master_passphrase
from store.totp import generate_totp

MASTER = "mestra-longa-dos-testes-2026"
SHARED = "frase-gateway-longa-dos-testes-2026"
USER = {"name": "Cliente Teste", "email": "teste@example.com", "password": "Senha123Segura!"}


@pytest.fixture
def servers(tmp_path, monkeypatch):
    monkeypatch.setattr(sdb, "DB_PATH", tmp_path / "store.db")
    monkeypatch.setattr(gdb, "DB_PATH", tmp_path / "gateway.db")
    sdb.init_db()
    gdb.init_db()
    init_or_verify_master_passphrase(MASTER)
    store_app.state.master_passphrase = MASTER
    store_app.state.payment_passphrase = SHARED
    gateway_app.state.payment_passphrase = SHARED
    with TestClient(gateway_app, client=("127.0.0.1", 55001)) as gateway:
        monkeypatch.setattr(shopping, "send_payment", lambda msg: gateway.post("/pay", json=msg).json())
        with TestClient(store_app, client=("127.0.0.1", 55000)) as store:
            yield store, gateway


def logged(servers):
    store, _ = servers
    r = store.post("/register", json=USER)
    assert r.status_code == 201
    secret = r.json()["totp_secret"]
    challenge = store.post("/login/password", json={"email": USER["email"], "password": USER["password"]})
    assert challenge.status_code == 200
    code = generate_totp(secret, int(time.time()) // 30)
    login = store.post("/login/totp", json={"challenge": challenge.json()["challenge"], "code": code})
    assert login.status_code == 200
    return {"Authorization": "Bearer " + login.json()["access_token"]}


def auth_message(amount=10000, item_price=5000, country="LOCAL", **extra):
    msg = {
        "order_id": "ORD-TEST12345", "user_id": 7,
        "items": [{"product_id": "P01", "quantity": 2, "unit_price_cents": item_price,
                   "unit_price": item_price / 100}],
        "amount_cents": amount, "amount": amount / 100, "currency": "BRL",
        "nonce": "nonce-" + __import__("secrets").token_urlsafe(20),
        "timestamp": int(time.time()),
        "client_ip": "127.0.0.1", "location": lookup_ip("127.0.0.1"),
        "auth": {"authenticated": True, "totp_verified": True, "verified_at": int(time.time()),
                 "user_id": 7, "client_ip": "127.0.0.1", "country": "LOCAL"},
    }
    msg.update(extra)
    return msg


def gateway_pay(gateway, msg):
    envelope = seal(msg, SHARED, "payment-request-v1")
    response = gateway.post("/pay", json=envelope)
    assert response.status_code == 200
    return open_seal(response.json(), SHARED, "payment-response-v1"), envelope


def test_full_purchase_and_location(servers):
    store, gateway = servers
    headers = logged(servers)
    products = store.get("/products", headers=headers).json()
    assert len(products) == len(PRODUCTS)
    assert store.get("/cart", headers=headers).json()["total_cents"] == 0
    assert store.put("/cart", json={"product_id": "P01", "quantity": 2}, headers=headers).status_code == 200
    assert store.put("/cart", json={"product_id": "P02", "quantity": 1}, headers=headers).status_code == 200
    assert store.get("/cart", headers=headers).json()["total_cents"] == 13500
    result = store.post("/checkout", json={}, headers=headers)
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["status"] == "APPROVED"
    assert data["total_cents"] == 13500 and data["total"] == 135.0
    assert data["location"]["source"] == "LOOPBACK"
    assert store.get("/cart", headers=headers).json()["items"] == []
    assert store.get("/orders", headers=headers).json()[0]["order_id"] == data["order_id"]
    with gdb.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM transactions WHERE status='APPROVED'").fetchone()[0] == 1


def test_replay_and_aead_tampering(servers):
    store, gateway = servers
    headers = logged(servers)
    store.put("/cart", json={"product_id": "P01", "quantity": 2}, headers=headers)
    order = store.post("/checkout", json={}, headers=headers).json()
    assert order["status"] == "APPROVED"
    with sdb.connect() as conn:
        envelope = json.loads(conn.execute("SELECT envelope_json FROM orders WHERE id=?",
                                           (order["order_id"],)).fetchone()["envelope_json"])
    replay = gateway.post("/pay", json=envelope)
    result = open_seal(replay.json(), SHARED, "payment-response-v1")
    assert result["status"] == "BLOCKED" and result["reason"] == "INVALID_NONCE"
    damaged = envelope.copy()
    ciphertext = bytearray(base64.b64decode(damaged["ciphertext"]))
    ciphertext[0] ^= 1
    damaged["ciphertext"] = base64.b64encode(ciphertext).decode()
    bad = gateway.post("/pay", json=damaged).json()
    assert bad["reason"] == "INVALID_AUTHENTICATION"


def test_location_spoofed_by_client_is_ignored(servers):
    store, _ = servers
    headers = logged(servers)
    store.put("/cart", json={"product_id": "P01", "quantity": 2}, headers=headers)
    response = store.post("/checkout", json={"location": {"country": "US"}, "amount": 1_000,
                                             "items": [{"product_id": "P01", "unit_price": 1000}]},
                          headers={**headers, "X-Forwarded-For": "8.8.8.8"})
    assert response.status_code == 200
    order = response.json()
    assert order["status"] == "APPROVED"
    assert order["total_cents"] == 10000
    assert order["location"]["country"] == "LOCAL"
    assert order["location"]["ip"] == "127.0.0.1"


@pytest.mark.parametrize("change,expected", [
    ({"amount_cents": 100000, "amount": 1000.0}, "INVALID_AMOUNT"),
    ({"amount": 1000.0}, "INVALID_AMOUNT"),
    ({"items": [{"product_id": "P01", "quantity": 2, "unit_price_cents": 100000,
                 "unit_price": 1000.0}]}, "INVALID_PRICE"),
    ({"currency": "USD"}, "INVALID_CURRENCY"),
    ({"auth": {"authenticated": False, "totp_verified": False}}, "UNAUTHENTICATED"),
    ({"location": {"ip": "127.0.0.1", "country": "US"}}, "INVALID_LOCATION"),
    ({"timestamp": 1}, "INVALID_TIMESTAMP"),
    ({"nonce": "short"}, "INVALID_NONCE"),
])
def test_gateway_business_rejections(servers, change, expected):
    _, gateway = servers
    result, _ = gateway_pay(gateway, auth_message(**change))
    assert result["status"] == "BLOCKED" and result["reason"] == expected


def test_gateway_checks_authenticated_totp(servers):
    _, gateway = servers
    msg = auth_message()
    msg["auth"]["totp_verified"] = False
    result, _ = gateway_pay(gateway, msg)
    assert result["reason"] == "INVALID_TOTP"


def test_gateway_does_not_accept_wrong_passphrase(servers):
    _, gateway = servers
    altered_key = seal(auth_message(), "senha-diferente-do-gateway", "payment-request-v1")
    response = gateway.post("/pay", json=altered_key).json()
    assert response["status"] == "BLOCKED"
    assert response["reason"] == "INVALID_AUTHENTICATION"


def test_cart_validation(servers):
    store, _ = servers
    headers = logged(servers)
    assert store.post("/checkout", json={}, headers=headers).status_code == 400
    assert store.put("/cart", json={"product_id": "P99", "quantity": 1}, headers=headers).status_code == 400
    assert store.put("/cart", json={"product_id": "P01", "quantity": 101}, headers=headers).status_code == 422
    store.put("/cart", json={"product_id": "P01", "quantity": 2}, headers=headers)
    store.put("/cart", json={"product_id": "P01", "quantity": 0}, headers=headers)
    assert store.get("/cart", headers=headers).json()["items"] == []


def test_access_without_session_is_forbidden(servers):
    store, _ = servers
    assert store.get("/products").status_code == 401
    assert store.get("/cart").status_code == 401
    assert store.post("/checkout", json={}).status_code == 401


def test_geo_context_country_change_denied(servers, monkeypatch):
    store, _ = servers
    headers = logged(servers)
    from store import auth
    original = auth.lookup_ip
    monkeypatch.setattr(auth, "lookup_ip", lambda ip: {**original(ip), "country": "US"})
    result = store.post("/login/password", json={"email": USER["email"], "password": USER["password"]})
    assert result.status_code == 401
    assert "país" in result.json()["detail"]


def test_ip2location_not_fake_for_public_without_db(monkeypatch, tmp_path):
    from shared import geo
    monkeypatch.setattr(geo, "DB_FILE", tmp_path / "not-installed.BIN")
    with pytest.raises(GeoError, match="IP2Location"):
        geo.lookup_ip("8.8.8.8")
    assert geo.lookup_ip("127.0.0.1")["source"] == "LOOPBACK"


def test_real_ip2location_adapter_with_sdk_stub(monkeypatch, tmp_path):
    """Exercita o adaptador da API oficial sem redistribuir o arquivo BIN licenciado."""
    import sys
    from types import SimpleNamespace
    from shared import geo
    fake_bin = tmp_path / "IP2LOCATION-LITE-DB11.BIN"
    fake_bin.write_bytes(b"apenas-placeholder-de-teste")
    monkeypatch.setattr(geo, "DB_FILE", fake_bin)

    class MockReader:
        def __init__(self, path):
            assert str(fake_bin) == path
        def get_all(self, ip):
            assert ip == "8.8.8.8"
            return SimpleNamespace(country_short="US", region="California", city="Mountain View",
                                   latitude=37.4, longitude=-122.1, asn="15169", as_name="Google")
    monkeypatch.setitem(sys.modules, "IP2Location", SimpleNamespace(IP2Location=MockReader))
    location = geo.lookup_ip("8.8.8.8")
    assert location["source"] == "IP2LOCATION"
    assert location["country"] == "US" and location["city"] == "Mountain View"
    assert location["asn"] == "15169" and location["organization"] == "Google"


def test_nonce_database_survives_restart(servers):
    _, gateway = servers
    envelope = seal(auth_message(), SHARED, "payment-request-v1")
    r1 = open_seal(gateway.post("/pay", json=envelope).json(), SHARED, "payment-response-v1")
    assert r1["status"] == "APPROVED"
    # Inicializar de novo não remove os nonces já utilizados.
    gdb.init_db()
    r2 = open_seal(gateway.post("/pay", json=envelope).json(), SHARED, "payment-response-v1")
    assert r2["reason"] == "INVALID_NONCE"


def test_old_timestamp_valid_nonce_is_blocked(servers):
    _, gateway = servers
    r, _ = gateway_pay(gateway, auth_message(timestamp=int(time.time()) - 999))
    assert r["reason"] == "INVALID_TIMESTAMP"
