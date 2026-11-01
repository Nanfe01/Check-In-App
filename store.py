"""Storage shared by the web app and the import script.

Uses Postgres when DATABASE_URL is set (recommended for hosting, e.g. a free Neon database),
otherwise a local SQLite file (handy for testing on your own computer).
All SQL below is written with ? placeholders and works on both.
"""
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_PG = DATABASE_URL.startswith(("postgres://", "postgresql://"))
DB_PATH = os.environ.get("DB_PATH", str(Path(__file__).parent / "checkin.db"))

SQLITE_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS registrants (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        email         TEXT NOT NULL DEFAULT '',
        token         TEXT NOT NULL UNIQUE,
        source        TEXT NOT NULL DEFAULT 'registered',
        checked_in    INTEGER NOT NULL DEFAULT 0,
        checked_in_at TEXT,
        checked_in_by TEXT,
        created_at    TEXT NOT NULL
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_registrants_email ON registrants(lower(email)) WHERE email != ''",
]
PG_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS registrants (
        id            BIGSERIAL PRIMARY KEY,
        name          TEXT NOT NULL,
        email         TEXT NOT NULL DEFAULT '',
        token         TEXT NOT NULL UNIQUE,
        source        TEXT NOT NULL DEFAULT 'registered',
        checked_in    INTEGER NOT NULL DEFAULT 0,
        checked_in_at TEXT,
        checked_in_by TEXT,
        created_at    TEXT NOT NULL
    )""",
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_registrants_email ON registrants (lower(email)) WHERE email <> ''",
]


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_token() -> str:
    # 12 random bytes -> 16 URL-safe characters (~96 bits). Not derived from any personal data.
    return secrets.token_urlsafe(12)


class Conn:
    """Thin wrapper so the rest of the code can use ? placeholders on either database."""

    def __init__(self, raw, pg: bool):
        self.raw, self.pg = raw, pg

    def execute(self, sql: str, params=()):
        if self.pg:
            sql = sql.replace("?", "%s")
        return self.raw.execute(sql, params)


_pool = None


def _get_pool():
    global _pool
    if _pool is None:
        from psycopg.rows import dict_row
        from psycopg_pool import ConnectionPool
        _pool = ConnectionPool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            open=True,
            check=ConnectionPool.check_connection,  # replace connections the host dropped while idle
            kwargs={"row_factory": dict_row, "prepare_threshold": None},  # safe behind pgbouncer poolers
        )
    return _pool


@contextmanager
def connect():
    if USE_PG:
        # Commits when the block ends normally, rolls back if it raises.
        with _get_pool().connection() as raw:
            yield Conn(raw, True)
    else:
        raw = sqlite3.connect(DB_PATH, timeout=15)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA journal_mode=WAL")
        try:
            yield Conn(raw, False)
            raw.commit()
        except Exception:
            raw.rollback()
            raise
        finally:
            raw.close()


def init_db() -> None:
    with connect() as conn:
        for stmt in (PG_SCHEMA if USE_PG else SQLITE_SCHEMA):
            conn.execute(stmt)


def backend_name() -> str:
    return "Postgres" if USE_PG else f"SQLite ({DB_PATH})"


def add_registrant(conn: Conn, name: str, email: str = "", source: str = "registered"):
    """Insert a registrant with a fresh token and return the row.
    Raises if the email is already registered."""
    token = new_token()
    conn.execute(
        "INSERT INTO registrants (name, email, token, source, created_at) VALUES (?,?,?,?,?)",
        (name.strip(), email.strip().lower(), token, source, utcnow()),
    )
    return conn.execute("SELECT * FROM registrants WHERE token=?", (token,)).fetchone()


def check_in(conn: Conn, column: str, value, by: str):
    """Atomically check someone in by 'token' or 'id'.

    The UPDATE only matches rows that are not yet checked in, so if two volunteers
    scan the same code at once, exactly one gets rowcount == 1.
    Returns (status, row) where status is 'ok', 'already' or 'invalid'.
    """
    assert column in ("token", "id")
    cur = conn.execute(
        f"UPDATE registrants SET checked_in=1, checked_in_at=?, checked_in_by=? "
        f"WHERE {column}=? AND checked_in=0",
        (utcnow(), by, value),
    )
    row = conn.execute(f"SELECT * FROM registrants WHERE {column}=?", (value,)).fetchone()
    if row is None:
        return "invalid", None
    return ("ok" if cur.rowcount == 1 else "already"), row
