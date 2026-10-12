"""Criação do segredo TOTP e da URI para cadastrar um autenticador.

A validação dos códigos temporários será feita na etapa de login.
"""

import base64
import secrets
from urllib.parse import quote, urlencode

ISSUER = "LojaSegura"


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(email: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{email}", safe=":")
    query = urlencode({
        "secret": secret,
        "issuer": ISSUER,
        "algorithm": "SHA1",
        "digits": 6,
        "period": 30,
    })
    return f"otpauth://totp/{label}?{query}"
