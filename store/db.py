"""SQLite connection + versioned migration runner.

One DB, WAL mode, thread-safe access (a short-lived connection per call, which is
the simplest correct model for Flask's threaded server). Migrations are the .sql
files in migrations/, applied in filename order and tracked in schema_migrations.
"""
import glob
import os
import sqlite3
import threading

_db_path = None
_lock = threading.Lock()

MIGRATIONS_DIR = os.path.join(os.path.dirname(__file__), 'migrations')


def configure(path):
    global _db_path
    _db_path = path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    migrate()


def connect():
    if _db_path is None:
        raise RuntimeError('db.configure() not called')
    conn = sqlite3.connect(_db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=5000')
    return conn


def migrate():
    with _lock, connect() as conn:
        conn.execute(
            'CREATE TABLE IF NOT EXISTS schema_migrations '
            '(version TEXT PRIMARY KEY, applied_at TEXT DEFAULT CURRENT_TIMESTAMP)'
        )
        applied = {r['version'] for r in conn.execute('SELECT version FROM schema_migrations')}
        for path in sorted(glob.glob(os.path.join(MIGRATIONS_DIR, '*.sql'))):
            version = os.path.basename(path)
            if version in applied:
                continue
            with open(path) as f:
                conn.executescript(f.read())
            conn.execute('INSERT INTO schema_migrations(version) VALUES (?)', (version,))
            conn.commit()


# ─── tiny query helpers ───────────────────────────────────────────────
def query(sql, params=()):
    with connect() as conn:
        return [dict(r) for r in conn.execute(sql, params).fetchall()]


def query_one(sql, params=()):
    rows = query(sql, params)
    return rows[0] if rows else None


def execute(sql, params=()):
    with _lock, connect() as conn:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.lastrowid
