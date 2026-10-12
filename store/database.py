"""Banco da loja. Preserva a tabela users do cadastro anterior."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "store.db"


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                totp_ciphertext BLOB NOT NULL,
                totp_salt BLOB NOT NULL,
                last_totp_step INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS server_config (
                id INTEGER PRIMARY KEY CHECK (id=1),
                check_ciphertext BLOB NOT NULL,
                check_salt BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_challenges (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                client_ip TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts_left INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                client_ip TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS access_contexts (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                country TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id TEXT PRIMARY KEY, name TEXT NOT NULL,
                price_cents INTEGER NOT NULL CHECK(price_cents>0)
            );
            CREATE TABLE IF NOT EXISTS cart_items (
                user_id INTEGER NOT NULL REFERENCES users(id),
                product_id TEXT NOT NULL REFERENCES products(id),
                quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 100),
                PRIMARY KEY(user_id,product_id)
            );
            CREATE TABLE IF NOT EXISTS orders (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id),
                total_cents INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                location_json TEXT NOT NULL,
                envelope_json TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS order_items (
                order_id TEXT NOT NULL REFERENCES orders(id),
                product_id TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price_cents INTEGER NOT NULL
            );
        """)
        user_columns = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
        if "last_totp_step" not in user_columns:
            conn.execute("ALTER TABLE users ADD COLUMN last_totp_step INTEGER")
        session_columns = {r["name"] for r in conn.execute("PRAGMA table_info(sessions)")}
        if "verified_at" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN verified_at INTEGER")
        if "country" not in session_columns:
            conn.execute("ALTER TABLE sessions ADD COLUMN country TEXT")

        from shared.products import PRODUCTS
        for product_id, item in PRODUCTS.items():
            conn.execute(
                "INSERT OR REPLACE INTO products(id,name,price_cents) VALUES (?,?,?)",
                (product_id, item["name"], item["price_cents"]),
            )
