"""Verificações independentes: AEAD, sessão, TOTP, pedido, IP e replay."""

import sqlite3
import time
from decimal import Decimal, InvalidOperation

from gateway import database
from shared.geo import GeoError, lookup_ip, same_location
from shared.products import PRODUCTS

WINDOW = 120  # segundos para tolerância de relógio
SESSION_TTL = 3600


class BlockPayment(Exception):
    pass


def _require(ok: bool, reason: str):
    if not ok:
        raise BlockPayment(reason)


def validate_and_process(message: dict) -> dict:
    now = int(time.time())
    order_id = message.get("order_id", "UNKNOWN")
    nonce = message.get("nonce")
    timestamp = message.get("timestamp")

    if not isinstance(timestamp, int) or isinstance(timestamp, bool) or abs(now - timestamp) > WINDOW:
        return {"order_id": order_id, "status": "BLOCKED", "reason": "INVALID_TIMESTAMP", "timestamp": now}
    if not isinstance(nonce, str) or len(nonce) < 16:
        return {"order_id": order_id, "status": "BLOCKED", "reason": "INVALID_NONCE", "timestamp": now}

    # INSERT atômico: evita replay até quando pedidos são recebidos simultaneamente.
    with database.connect() as conn:
        try:
            conn.execute("INSERT INTO used_nonces VALUES (?, ?)", (nonce, now))
        except sqlite3.IntegrityError:
            return {"order_id": order_id, "status": "BLOCKED", "reason": "INVALID_NONCE", "timestamp": now}

    status, reason = "APPROVED", None
    try:
        _require(isinstance(order_id, str) and order_id.startswith("ORD-"), "INVALID_ORDER")
        user_id = message.get("user_id")
        _require(type(user_id) is int and user_id > 0, "INVALID_USER")
        proof = message.get("auth")
        _require(isinstance(proof, dict) and proof.get("authenticated") is True,
                 "UNAUTHENTICATED")
        _require(proof.get("totp_verified") is True, "INVALID_TOTP")
        auth_time = proof.get("verified_at")
        _require(type(auth_time) is int and 0 <= now - auth_time <= SESSION_TTL,
                 "AUTH_EXPIRED")
        _require(proof.get("user_id") == user_id, "INVALID_USER")
        ip = message.get("client_ip")
        _require(type(ip) is str and ip == proof.get("client_ip"), "INVALID_CONTEXT")
        try:
            actual_geo = lookup_ip(ip)
        except GeoError:
            raise BlockPayment("GEOLOCATION_UNAVAILABLE")
        _require(isinstance(message.get("location"), dict)
                 and same_location(actual_geo, message["location"]), "INVALID_LOCATION")
        _require(proof.get("country") == actual_geo["country"], "INVALID_CONTEXT")

        _require(message.get("currency") == "BRL", "INVALID_CURRENCY")
        amount = message.get("amount_cents")
        _require(type(amount) is int and amount > 0, "INVALID_AMOUNT")
        try:
            _require(Decimal(str(message.get("amount"))) == Decimal(amount) / 100,
                     "INVALID_AMOUNT")
        except InvalidOperation:
            raise BlockPayment("INVALID_AMOUNT")
        items = message.get("items")
        _require(isinstance(items, list) and len(items) > 0, "INVALID_ORDER")
        total = 0
        for item in items:
            _require(isinstance(item, dict), "INVALID_ORDER")
            product_id = item.get("product_id")
            count = item.get("quantity")
            unit_price = item.get("unit_price_cents")
            _require(product_id in PRODUCTS and type(count) is int and 1 <= count <= 100,
                     "INVALID_ORDER")
            _require(type(unit_price) is int and unit_price == PRODUCTS[product_id]["price_cents"],
                     "INVALID_PRICE")
            try:
                _require(Decimal(str(item.get("unit_price"))) == Decimal(unit_price) / 100,
                         "INVALID_PRICE")
            except InvalidOperation:
                raise BlockPayment("INVALID_PRICE")
            total += count * unit_price
        _require(total == amount, "INVALID_AMOUNT")
    except BlockPayment as exc:
        status, reason = "BLOCKED", str(exc)
    except (TypeError, ValueError):
        status, reason = "BLOCKED", "INVALID_ORDER"

    with database.connect() as conn:
        conn.execute(
            "INSERT INTO transactions(order_id,nonce,amount_cents,status,reason,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (str(order_id), nonce, message.get("amount_cents") if type(message.get("amount_cents")) is int else None,
             status, reason, now)
        )

    response = {"order_id": order_id, "status": status, "timestamp": now,
                "nonce": nonce}
    if reason:
        response["reason"] = reason
    return response
