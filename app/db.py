"""SQLite storage (standard library). Demo data is deleted after a few days."""
from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import threading
import time
from contextlib import contextmanager

def _default_path() -> str:
    """A private (0700) directory under the system temp dir; set DB_PATH for a persistent disk."""
    d = os.path.join(tempfile.gettempdir(), f"securepay-{os.getuid() if hasattr(os, 'getuid') else 'app'}")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return os.path.join(d, "app.sqlite3")


DB_PATH = os.getenv("DB_PATH") or _default_path()
RETENTION_DAYS = float(os.getenv("RETENTION_DAYS", "3"))
_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  password_hash TEXT NOT NULL, created REAL NOT NULL,
  totp_secret_enc TEXT, totp_pending_enc TEXT, totp_last_step INTEGER DEFAULT -1,
  failed_count INTEGER DEFAULT 0, locked_until REAL DEFAULT 0,
  webauthn_user_id BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS passkeys (
  id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, credential_id BLOB UNIQUE NOT NULL,
  public_key BLOB NOT NULL, sign_count INTEGER NOT NULL, created REAL NOT NULL, label TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL NOT NULL,
  last_seen REAL NOT NULL, state TEXT NOT NULL, required TEXT NOT NULL, satisfied TEXT NOT NULL,
  device_id TEXT, network TEXT, risk TEXT, attempts INTEGER DEFAULT 0, challenge BLOB
);
CREATE TABLE IF NOT EXISTS devices (
  user_id INTEGER NOT NULL, device_id TEXT NOT NULL, first_seen REAL NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS networks (
  user_id INTEGER NOT NULL, network TEXT NOT NULL, first_seen REAL NOT NULL,
  PRIMARY KEY (user_id, network)
);
CREATE TABLE IF NOT EXISTS logins (
  user_id INTEGER NOT NULL, ts REAL NOT NULL, hour REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS payments (
  id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, created REAL NOT NULL, payee TEXT NOT NULL,
  amount REAL NOT NULL, currency TEXT NOT NULL, status TEXT NOT NULL, required TEXT NOT NULL,
  satisfied TEXT NOT NULL, risk TEXT NOT NULL, reason TEXT NOT NULL, challenge BLOB,
  attempts INTEGER DEFAULT 0, exempt INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, user_id INTEGER, ts REAL NOT NULL, type TEXT NOT NULL,
  network TEXT, device TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY, value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rate (
  key TEXT NOT NULL, ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS rate_key ON rate(key, ts);
CREATE INDEX IF NOT EXISTS events_user ON events(user_id, ts);
CREATE INDEX IF NOT EXISTS payments_user ON payments(user_id, created);
"""


def connect() -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is None:
            _conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("PRAGMA foreign_keys=ON")
            _conn.executescript(SCHEMA)
        return _conn


@contextmanager
def tx():
    conn = connect()
    with _lock:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def q(sql: str, args=()):
    with _lock:
        return connect().execute(sql, args).fetchall()


def q1(sql: str, args=()):
    rows = q(sql, args)
    return rows[0] if rows else None


def run(sql: str, args=()):
    with _lock:
        return connect().execute(sql, args)


def log_event(user_id, type_: str, network: str = "", device: str = "", **detail) -> None:
    """Audit trail. Never pass secrets, codes, passwords or full IP addresses."""
    run("INSERT INTO events (user_id, ts, type, network, device, detail) VALUES (?,?,?,?,?,?)",
        (user_id, time.time(), type_, network, (device or "")[:8], json.dumps(detail)))


DEFAULT_SETTINGS = {"maintenance_banner": "", "registration_open": True, "payments_enabled": True,
                    "demo_signals_enabled": True}


def get_settings() -> dict:
    out = dict(DEFAULT_SETTINGS)
    for r in q("SELECT key, value FROM settings"):
        if r["key"] in out:
            out[r["key"]] = json.loads(r["value"])
    return out


def set_settings(changes: dict) -> dict:
    for k, v in changes.items():
        if k in DEFAULT_SETTINGS:
            run("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, json.dumps(v)))
    return get_settings()


def delete_user(uid: int) -> None:
    with tx() as c:
        for table in ("passkeys", "sessions", "devices", "networks", "logins", "payments"):
            c.execute(f"DELETE FROM {table} WHERE user_id = ?", (uid,))  # nosec B608 - fixed table names
        c.execute("DELETE FROM users WHERE id = ?", (uid,))


def prune(keep_emails: tuple = ()) -> None:
    """Delete demo accounts (and everything they own) older than the retention period."""
    cutoff = time.time() - RETENTION_DAYS * 86400
    with tx() as c:
        old = [r["id"] for r in c.execute("SELECT id, email FROM users WHERE created < ?", (cutoff,))
               if r["email"] not in keep_emails]
        for uid in old:
            for table in ("passkeys", "sessions", "devices", "networks", "logins", "payments", "events"):
                c.execute(f"DELETE FROM {table} WHERE user_id = ?", (uid,))  # nosec B608 - fixed table names
            c.execute("DELETE FROM users WHERE id = ?", (uid,))
        c.execute("DELETE FROM rate WHERE ts < ?", (time.time() - 3600,))
        c.execute("DELETE FROM sessions WHERE last_seen < ?", (time.time() - 86400,))


def reset_for_tests() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
        if DB_PATH != ":memory:" and os.path.exists(DB_PATH):
            os.remove(DB_PATH)
