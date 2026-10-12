"""Cifragem de segredos persistidos na loja.

Derivamos chave AES e nonce/IV por Scrypt com um salt aleatório *novo*
para cada cifragem. Um mesmo salt nunca deve ser reutilizado para cifrar
outro conteúdo, pois reutilizar (chave, nonce) em AES-GCM é inseguro.
Este módulo NÃO define o protocolo futuro loja <-> gateway.
"""

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE = 16


def _derive_key_and_nonce(passphrase: str, salt: bytes) -> tuple[bytes, bytes]:
    kdf = Scrypt(salt=salt, length=44, n=2**15, r=8, p=1)
    material = kdf.derive(passphrase.encode("utf-8"))
    return material[:32], material[32:44]  # AES-256 + nonce GCM de 96 bits


def encrypt_secret(plaintext: str, passphrase: str, context: str) -> tuple[bytes, bytes]:
    """Retorna (salt público, conteúdo cifrado + tag GCM)."""
    salt = secrets.token_bytes(SALT_SIZE)
    key, nonce = _derive_key_and_nonce(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        context.encode("utf-8"),
    )
    return salt, ciphertext


def decrypt_secret(salt: bytes, ciphertext: bytes, passphrase: str, context: str) -> str:
    key, nonce = _derive_key_and_nonce(passphrase, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, context.encode("utf-8"))
    return plaintext.decode("utf-8")
