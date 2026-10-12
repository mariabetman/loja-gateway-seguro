"""Regra de negócio do cadastro, independente do framework HTTP."""

import sqlite3

from shared.crypto import encrypt_secret
from store import database
from store.models import RegistrationIn, RegistrationOut
from store.security import hash_password
from store.totp import new_totp_secret, provisioning_uri


class DuplicateEmailError(Exception):
    pass


def register_user(data: RegistrationIn, master_passphrase: str) -> RegistrationOut:
    email = str(data.email).strip().lower()
    totp_secret = new_totp_secret()
    salt, ciphertext = encrypt_secret(totp_secret, master_passphrase, f"user:{email}")
    password_hash = hash_password(data.password)

    try:
        with database.connect() as conn:
            cur = conn.execute(
                """INSERT INTO users(name, email, password_hash, totp_salt, totp_ciphertext)
                   VALUES (?, ?, ?, ?, ?)""",
                (data.name, email, password_hash, salt, ciphertext),
            )
            user_id = cur.lastrowid
    except sqlite3.IntegrityError as exc:
        raise DuplicateEmailError("Este e-mail já está cadastrado.") from exc

    # Só nesta resposta de cadastro o segredo será exposto ao próprio usuário.
    return RegistrationOut(
        user_id=user_id,
        name=data.name,
        email=email,
        totp_secret=totp_secret,
        otpauth_uri=provisioning_uri(email, totp_secret),
    )
