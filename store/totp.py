"""TOTP (RFC 6238) com HMAC-SHA1, seis dígitos e intervalo de 30 segundos."""

import base64
import hashlib
import hmac
import secrets
import time
from urllib.parse import quote, urlencode

ISSUER = "LojaSegura"
TOTP_PERIOD = 30


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def provisioning_uri(email: str, secret: str) -> str:
    label = quote(f"{ISSUER}:{email}", safe=":")
    query = urlencode({
        "secret": secret,
        "issuer": ISSUER,
        "algorithm": "SHA1",
        "digits": 6,
        "period": TOTP_PERIOD,
    })
    return f"otpauth://totp/{label}?{query}"


def generate_totp(secret: str, step: int) -> str:
    """Calcula os seis dígitos do TOTP para um contador de tempo."""
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, step.to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret: str, code: str, last_used_step: int | None,
                now: int | None = None) -> int | None:
    """Devolve o contador validado ou None; não permite reutilizar um contador."""
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current_step = (int(time.time()) if now is None else now) // TOTP_PERIOD
    # Tolerância de 30 s para relógios levemente dessincronizados.
    for step in (current_step, current_step - 1, current_step + 1):
        if step < 0 or (last_used_step is not None and step <= last_used_step):
            continue
        if hmac.compare_digest(generate_totp(secret, step), code):
            return step
    return None
