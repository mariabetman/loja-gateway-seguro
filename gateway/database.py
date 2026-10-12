"""Estado independente do gateway, inclusive histórico de nonces."""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "data" / "gateway.db"


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS used_nonces (
                nonce TEXT PRIMARY KEY,
                first_seen INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transactions (
                order_id TEXT NOT NULL,
                nonce TEXT PRIMARY KEY,
                amount_cents INTEGER,
                status TEXT NOT NULL,
                reason TEXT,
                created_at INTEGER NOT NULL
            );
        """)
