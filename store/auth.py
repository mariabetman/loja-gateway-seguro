"""Cadastro, autenticação em dois fatores e sessões da loja."""

import hashlib
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidTag

from shared.crypto import decrypt_secret, encrypt_secret
from store import database
from store.models import RegistrationIn, RegistrationOut, UserOut
from store.security import hash_password, verify_password
from store.totp import new_totp_secret, provisioning_uri, verify_totp
from shared.geo import lookup_ip, GeoError

CHALLENGE_TTL = 300       # Cinco minutos para informar o TOTP.
SESSION_TTL = 3600        # Uma hora de sessão.
MAX_TOTP_ATTEMPTS = 5


class DuplicateEmailError(Exception):
    pass


class AuthenticationError(Exception):
    pass


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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

    return RegistrationOut(
        user_id=user_id, name=data.name, email=email,
        totp_secret=totp_secret, otpauth_uri=provisioning_uri(email, totp_secret),
    )


def start_login(email: str, password: str, client_ip: str) -> str:
    """Após validar a senha, emite um desafio temporário para o TOTP."""
    email = email.strip().lower()
    with database.connect() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (email,)
        ).fetchone()

    if user is None or not verify_password(user["password_hash"], password):
        raise AuthenticationError("Credenciais inválidas.")

    try:
        location = lookup_ip(client_ip)
    except GeoError as exc:
        raise AuthenticationError(str(exc)) from exc
    with database.connect() as conn:
        previous = conn.execute(
            "SELECT country FROM access_contexts WHERE user_id=?", (user["id"],)
        ).fetchone()
    if previous and previous["country"] != location["country"]:
        raise AuthenticationError("Alteração de país detectada: acesso bloqueado.")

    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with database.connect() as conn:
        conn.execute("DELETE FROM login_challenges WHERE expires_at <= ?", (now,))
        conn.execute(
            """INSERT INTO login_challenges
               (token_hash, user_id, client_ip, expires_at, attempts_left)
               VALUES (?, ?, ?, ?, ?)""",
            (_token_hash(token), user["id"], client_ip, now + CHALLENGE_TTL,
             MAX_TOTP_ATTEMPTS),
        )
    return token


def finish_login(challenge: str, code: str, client_ip: str,
                 master_passphrase: str) -> str:
    """Verifica o TOTP, consome o desafio e cria uma sessão opaca."""
    now = int(time.time())
    with database.connect() as conn:
        # Impede corridas entre tentativas concorrentes e reutilização do mesmo código.
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """SELECT c.user_id, c.client_ip, c.expires_at, c.attempts_left,
                      u.email, u.totp_salt, u.totp_ciphertext, u.last_totp_step
               FROM login_challenges AS c
               JOIN users AS u ON u.id = c.user_id
               WHERE c.token_hash = ?""",
            (_token_hash(challenge),),
        ).fetchone()

        if row is None or row["expires_at"] <= now or row["client_ip"] != client_ip:
            raise AuthenticationError("Desafio inválido ou expirado.")

        try:
            secret = decrypt_secret(
                row["totp_salt"], row["totp_ciphertext"],
                master_passphrase, f"user:{row['email']}",
            )
        except (InvalidTag, UnicodeDecodeError) as exc:
            raise AuthenticationError("Não foi possível verificar o TOTP.") from exc

        step = verify_totp(secret, code, row["last_totp_step"], now=now)
        if step is None:
            if row["attempts_left"] <= 1:
                conn.execute("DELETE FROM login_challenges WHERE token_hash = ?",
                             (_token_hash(challenge),))
            else:
                conn.execute(
                    """UPDATE login_challenges SET attempts_left = attempts_left - 1
                       WHERE token_hash = ?""",
                    (_token_hash(challenge),),
                )
            # Não lançar exceção dentro do 'with': isso desfaria a contagem de falhas.
            result = None
        else:
            conn.execute("UPDATE users SET last_totp_step = ? WHERE id = ?",
                         (step, row["user_id"]))
            conn.execute("DELETE FROM login_challenges WHERE token_hash = ?",
                         (_token_hash(challenge),))
            session_token = secrets.token_urlsafe(32)
            conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            location = lookup_ip(client_ip)
            conn.execute(
                """INSERT INTO sessions(
                    token_hash, user_id, client_ip, expires_at, verified_at, country
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (_token_hash(session_token), row["user_id"], client_ip,
                 now + SESSION_TTL, now, location["country"]),
            )
            conn.execute(
                """INSERT INTO access_contexts(user_id,country) VALUES (?,?)
                   ON CONFLICT(user_id) DO UPDATE SET country=excluded.country""",
                (row["user_id"], location["country"]),
            )
            result = session_token

    if result is None:
        raise AuthenticationError("Código TOTP inválido ou já utilizado.")
    return result


def current_user(access_token: str, client_ip: str) -> UserOut:
    now = int(time.time())
    with database.connect() as conn:
        row = conn.execute(
            """SELECT u.id, u.name, u.email
               FROM sessions AS s JOIN users AS u ON u.id = s.user_id
               WHERE s.token_hash = ? AND s.expires_at > ? AND s.client_ip = ?""",
            (_token_hash(access_token), now, client_ip),
        ).fetchone()
    if row is None:
        raise AuthenticationError("Sessão inválida ou expirada.")
    return UserOut(user_id=row["id"], name=row["name"], email=row["email"])


def logout(access_token: str) -> None:
    with database.connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(access_token),))


def session_proof(access_token: str, client_ip: str) -> dict:
    """Prova que a loja autenticou senha + TOTP na sessão atual."""
    current_user(access_token, client_ip)
    with database.connect() as conn:
        row = conn.execute(
            """SELECT user_id,verified_at,country FROM sessions
               WHERE token_hash=? AND client_ip=? AND expires_at>?""",
            (_token_hash(access_token), client_ip, int(time.time())),
        ).fetchone()
    if not row or not row["verified_at"]:
        raise AuthenticationError("Sessão sem segundo fator confirmado.")
    return {"user_id": row["user_id"], "authenticated": True,
            "totp_verified": True, "verified_at": row["verified_at"],
            "client_ip": client_ip, "country": row["country"]}
