"""Catálogo, carrinho e integração autenticada com o gateway."""

import json
import secrets
import time

import httpx

from shared.crypto import open_seal, seal
from shared.geo import lookup_ip
from store import database
from store.auth import session_proof

GATEWAY_URL = "http://127.0.0.1:8001"


class CartError(ValueError):
    pass


def products() -> list[dict]:
    with database.connect() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM products ORDER BY id")]


def cart(user_id: int) -> dict:
    with database.connect() as conn:
        rows = conn.execute(
            """SELECT p.id AS product_id, p.name, p.price_cents AS unit_price_cents,
                      c.quantity FROM cart_items c JOIN products p ON p.id=c.product_id
               WHERE c.user_id=? ORDER BY p.id""", (user_id,)
        ).fetchall()
    items = [dict(r) for r in rows]
    return {"items": items, "total_cents": sum(
        item["quantity"] * item["unit_price_cents"] for item in items
    )}


def set_quantity(user_id: int, product_id: str, quantity: int) -> dict:
    if type(quantity) is not int or not 0 <= quantity <= 100:
        raise CartError("Quantidade deve estar entre 0 e 100.")
    with database.connect() as conn:
        row = conn.execute("SELECT id FROM products WHERE id=?", (product_id,)).fetchone()
        if row is None:
            raise CartError("Produto inexistente.")
        if quantity == 0:
            conn.execute("DELETE FROM cart_items WHERE user_id=? AND product_id=?",
                         (user_id, product_id))
        else:
            conn.execute(
                """INSERT INTO cart_items(user_id,product_id,quantity) VALUES (?,?,?)
                   ON CONFLICT(user_id,product_id) DO UPDATE SET quantity=excluded.quantity""",
                (user_id, product_id, quantity),
            )
    return cart(user_id)


def checkout(user_id: int, token: str, client_ip: str, payment_passphrase: str) -> dict:
    items_info = cart(user_id)
    if not items_info["items"]:
        raise CartError("O carrinho está vazio.")
    location = lookup_ip(client_ip)
    proof = session_proof(token, client_ip)
    if proof["user_id"] != user_id or proof["country"] != location["country"]:
        raise CartError("Contexto de acesso diferente da sessão autenticada.")

    order_id = "ORD-" + secrets.token_hex(8).upper()
    nonce = secrets.token_urlsafe(24)
    items = [{"product_id": it["product_id"], "quantity": it["quantity"],
              "unit_price_cents": it["unit_price_cents"],
              "unit_price": it["unit_price_cents"] / 100} for it in items_info["items"]]
    request_message = {
        "order_id": order_id, "user_id": user_id,
        "items": items, "amount_cents": items_info["total_cents"],
        "amount": items_info["total_cents"] / 100, "currency": "BRL",
        "nonce": nonce, "timestamp": int(time.time()),
        "client_ip": client_ip, "location": location, "auth": proof,
    }
    envelope = seal(request_message, payment_passphrase, "payment-request-v1")
    with database.connect() as conn:
        conn.execute(
            """INSERT INTO orders(id,user_id,total_cents,status,location_json,envelope_json,created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (order_id, user_id, items_info["total_cents"], "PENDING",
             json.dumps(location), json.dumps(envelope), int(time.time())),
        )
        conn.executemany(
            """INSERT INTO order_items(order_id,product_id,quantity,unit_price_cents)
               VALUES(?,?,?,?)""",
            [(order_id, it["product_id"], it["quantity"], it["unit_price_cents"])
             for it in items],
        )

    try:
        raw_result = send_payment(envelope)
        if "ciphertext" not in raw_result:
            raise CartError("Gateway rejeitou a autenticidade da mensagem.")
        result = open_seal(raw_result, payment_passphrase, "payment-response-v1")
        if result.get("order_id") != order_id or result.get("nonce") != nonce:
            raise CartError("Resposta do gateway não corresponde ao pedido.")
        if result.get("status") not in {"APPROVED", "BLOCKED"}:
            raise CartError("Status inesperado do gateway.")
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        result = {"status": "ERROR", "reason": "GATEWAY_UNAVAILABLE_OR_INVALID_RESPONSE"}

    with database.connect() as conn:
        conn.execute("UPDATE orders SET status=?, reason=? WHERE id=?",
                     (result["status"], result.get("reason"), order_id))
        if result["status"] == "APPROVED":
            conn.execute("DELETE FROM cart_items WHERE user_id=?", (user_id,))
    return order_detail(user_id, order_id)


def order_detail(user_id: int, order_id: str) -> dict:
    with database.connect() as conn:
        row = conn.execute(
            "SELECT * FROM orders WHERE id=? AND user_id=?", (order_id, user_id)
        ).fetchone()
        if not row:
            raise CartError("Pedido não encontrado.")
        items = conn.execute(
            """SELECT product_id,quantity,unit_price_cents FROM order_items
               WHERE order_id=?""", (order_id,)
        ).fetchall()
    listed_items = [dict(i) for i in items]
    for item in listed_items:
        item["unit_price"] = item["unit_price_cents"] / 100
    return {"order_id": row["id"], "user_id": user_id,
            "items": listed_items, "total_cents": row["total_cents"],
            "total": row["total_cents"] / 100, "currency": "BRL", "status": row["status"],
            "reason": row["reason"], "location": json.loads(row["location_json"])}


def orders(user_id: int) -> list[dict]:
    with database.connect() as conn:
        rows = conn.execute("SELECT id FROM orders WHERE user_id=? ORDER BY created_at DESC", (user_id,))
        ids = [r["id"] for r in rows]
    return [order_detail(user_id, order_id) for order_id in ids]


def send_payment(envelope: dict) -> dict:
    """Envio HTTP real, substituído por um transporte em memória nos testes."""
    with httpx.Client(timeout=10) as client:
        response = client.post(GATEWAY_URL + "/pay", json=envelope)
        response.raise_for_status()
        return response.json()
