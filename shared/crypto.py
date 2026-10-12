"""AES-256-GCM com chave e IV temporários derivados via Scrypt.

Cada cifragem cria um salt aleatório independente. A chave e o IV NÃO são
armazenados nem transmitidos. O salt pode viajar em claro; o conteúdo não.
A mensagem 'nonce' (antirreplay) é diferente do IV criptográfico.
"""

import base64
import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def _derive(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    material = Scrypt(salt=salt, length=44, n=2**15, r=8, p=1).derive(
        passphrase.encode("utf-8")
    )
    return material[:32], material[32:]


def encrypt_secret(plaintext: str, passphrase: str, context: str) -> tuple[bytes, bytes]:
    salt = secrets.token_bytes(16)
    key, iv = _derive(passphrase, salt)
    return salt, AESGCM(key).encrypt(iv, plaintext.encode(), context.encode())


def decrypt_secret(salt: bytes, ciphertext: bytes, passphrase: str, context: str) -> str:
    key, iv = _derive(passphrase, salt)
    return AESGCM(key).decrypt(iv, ciphertext, context.encode()).decode()


def seal(payload: dict, passphrase: str, purpose: str) -> dict:
    salt, ciphertext = encrypt_secret(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        passphrase, purpose,
    )
    return {"salt": base64.b64encode(salt).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode()}


def open_seal(envelope: dict, passphrase: str, purpose: str) -> dict:
    salt = base64.b64decode(envelope["salt"], validate=True)
    encrypted = base64.b64decode(envelope["ciphertext"], validate=True)
    if len(salt) != 16:
        raise ValueError("Salt inválido.")
    payload = json.loads(decrypt_secret(salt, encrypted, passphrase, purpose))
    if not isinstance(payload, dict):
        raise ValueError("Mensagem inválida.")
    return payload
