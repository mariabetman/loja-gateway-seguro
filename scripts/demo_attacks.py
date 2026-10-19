"""Demonstra os quatro ataques com servidores já iniciados e usuário cadastrado.

Não altera o banco de dados manualmente: usa requisições reais e reutiliza
uma mensagem legítima que ficou registrada para auditoria da demonstração.
"""

import base64
from getpass import getpass
import json

import httpx

from client import api
from shared.crypto import open_seal
from store import database

GATEWAY = "http://127.0.0.1:8001/pay"


def report(name, actual, expected):
    passed = actual == expected
    print(f"{'OK' if passed else 'FALHOU'} {name}: {actual} (esperado: {expected})")
    return passed


def tamper_amount(envelope, order):
    """Usa dados/formato conhecidos para tentar mudar 100.0 para 1000, sem chave."""
    if order["total_cents"] != 10000:
        raise ValueError("A demonstração de alteração de valor exige um pedido de R$ 100,00.")
    prefix = {"order_id": order["order_id"], "user_id": order["user_id"],
              "items": order["items"], "amount_cents": order["total_cents"]}
    offset = len(json.dumps(prefix, ensure_ascii=False, separators=(",", ":")).encode()[:-1]
                 + b',"amount":')
    ciphertext = bytearray(base64.b64decode(envelope["ciphertext"]))
    # Os cinco bytes mantêm o tamanho do JSON: o espaço após 1000 é válido.
    # GCM usa CTR: aplicar a diferença XOR tenta trocar os bytes conhecidos.
    for index, (before, after) in enumerate(zip(b"100.0", b"1000 ")):
        ciphertext[offset + index] ^= before ^ after
    return {**envelope, "ciphertext": base64.b64encode(ciphertext).decode()}


def main():
    print("=== Demonstração de ataques (somente em ambiente de teste) ===")
    email = input("E-mail cadastrado: ").strip()
    password = getpass("Senha: ")
    payment_passphrase = getpass("Frase compartilhada loja-gateway (para ler resposta cifrada): ")
    passed = []

    # C. Código TOTP incorreto.
    code = input("Código TOTP CORRETO do aplicativo (6 dígitos): ").strip()
    first = api.login_password(email, password)
    bad_code = "000000" if code != "000000" else "999999"
    with api.http_client() as http:
        wrong = http.post("/login/totp", json={"challenge": first["challenge"], "code": bad_code})
    passed.append(report("C: TOTP inválido", wrong.status_code, 401))

    token = api.login_totp(first["challenge"], code)["access_token"]
    location = api.get_location(token)
    # Garante um pedido de exatamente R$ 100,00 para a demonstração.
    for item in api.cart(token)["items"]:
        api.set_quantity(token, item["product_id"], 0)
    api.set_quantity(token, "P01", 2)

    # D. Cliente tenta falsificar localização, valor e itens. O servidor ignora.
    with api.http_client() as http:
        response = http.post("/checkout", json={
            "location": {"country": "US", "region": "CA", "city": "Fake City"},
            "amount": 999999, "items": [{"product_id": "P01", "unit_price": 1}],
        }, headers={"Authorization": f"Bearer {token}", "X-Forwarded-For": "8.8.8.8"})
    response.raise_for_status()
    order = response.json()
    print("Compra válida:", order["order_id"], order["status"])
    print("Localização observada pela loja:", order["location"])
    if order["status"] != "APPROVED":
        raise ValueError("A compra de referência não foi aprovada; confira loja e gateway.")
    passed.append(report("D: localização falsa ignorada",
                         order["location"] == location and order["total_cents"] == 10000, True))

    with database.connect() as conn:
        recorded = conn.execute(
            "SELECT envelope_json FROM orders WHERE id=?", (order["order_id"],)
        ).fetchone()
    envelope = json.loads(recorded["envelope_json"])

    with httpx.Client(timeout=15) as http:
        # A. Replay da mensagem cifrada legítima já processada.
        replay = http.post(GATEWAY, json=envelope)
        replay.raise_for_status()
        replay_result = open_seal(replay.json(), payment_passphrase, "payment-response-v1")
        passed.append(report("A: replay", replay_result.get("reason"), "INVALID_NONCE"))

        # B. Tenta trocar o amount de 100.0 para 1000, mantendo a tag original.
        damaged = tamper_amount(envelope, order)
        print("B: tentativa de alterar amount de R$ 100,00 para R$ 1.000,00")
        tamper = http.post(GATEWAY, json=damaged)
        tamper.raise_for_status()
        passed.append(report("B: alteração do valor",
                             tamper.json().get("reason"), "INVALID_AUTHENTICATION"))

    api.logout(token)
    print(f"\nResultado: {sum(passed)}/{len(passed)} demonstrações aprovadas")
    if not all(passed):
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        main()
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        raise SystemExit(f"Erro ao executar demonstração: {exc}") from exc
