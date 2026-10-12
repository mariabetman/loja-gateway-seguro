"""Proteção de senhas e verificação da frase-mestra da loja."""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.exceptions import InvalidTag

from shared.crypto import decrypt_secret, encrypt_secret
from store import database

PASSWORD_HASHER = PasswordHasher()
MASTER_CHECK_VALUE = "LOJA-SEGURA-MASTER-CHECK-V1"  # Marcador público, não é uma chave.
MASTER_CHECK_CONTEXT = "server:master-check"


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return PASSWORD_HASHER.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def init_or_verify_master_passphrase(passphrase: str) -> None:
    """Impede reinicializar a loja com uma frase-mestra incompatível."""
    with database.connect() as conn:
        record = conn.execute(
            "SELECT check_salt, check_ciphertext FROM server_config WHERE id = 1"
        ).fetchone()
        if record is None:
            salt, ciphertext = encrypt_secret(
                MASTER_CHECK_VALUE, passphrase, MASTER_CHECK_CONTEXT
            )
            conn.execute(
                "INSERT INTO server_config(id, check_salt, check_ciphertext) VALUES (1, ?, ?)",
                (salt, ciphertext),
            )
            return

        try:
            actual = decrypt_secret(
                record["check_salt"], record["check_ciphertext"],
                passphrase, MASTER_CHECK_CONTEXT,
            )
        except InvalidTag as exc:
            raise ValueError("Frase-mestra incorreta para este banco de dados.") from exc
        if actual != MASTER_CHECK_VALUE:
            raise ValueError("Verificador da frase-mestra inválido.")
