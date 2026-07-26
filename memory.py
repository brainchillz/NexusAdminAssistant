"""Persistent memory — the assistant's durable knowledge across sessions.

Two scopes (host_id NULL = global/estate-wide, else per-host):
  - global: the MISSION (who the assistant is), plus cross-host services,
    decisions, and facts ("NTP server runs on host Y", "web on VM-A / docker on
    VM-B"). Injected into EVERY conversation so the agent is estate-aware.
  - per-host: what's installed, decisions, and a changelog for one host.

Recall = SQLite FTS5 (the memories_fts triggers keep it in sync), with a LIKE
fallback. A vector backend can slot in behind search() later.
"""
import re
from datetime import datetime, timezone

from store import db

KINDS = ('mission', 'service', 'decision', 'fact', 'state', 'changelog')

DEFAULT_MISSION = (
    "I am the user's personal system and network administrator assistant for their "
    "homelab. My job: manage, install, configure, troubleshoot, and maintain their "
    "hosts and services — acting on the user's intent, remembering our decisions and "
    "the layout of their environment across sessions, reusing what already exists "
    "(e.g. shared services) instead of duplicating it, and asking before anything risky."
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _row(r):
    return {'id': r['id'], 'host_id': r['host_id'], 'kind': r['kind'],
            'title': r['title'], 'body': r['body'], 'created_at': r['created_at']}


# ─── CRUD ─────────────────────────────────────────────────────────────
def create(kind, title, body, host_id=None):
    if kind not in KINDS:
        kind = 'fact'
    return db.execute(
        'INSERT INTO memories(host_id, kind, title, body, created_at) VALUES(?,?,?,?,?)',
        (host_id, kind, title, body, _now()))


def update(mid, title=None, body=None, kind=None):
    cur = db.query_one('SELECT * FROM memories WHERE id=?', (mid,))
    if not cur:
        return
    db.execute('UPDATE memories SET title=?, body=?, kind=? WHERE id=?',
               (title if title is not None else cur['title'],
                body if body is not None else cur['body'],
                kind if kind in KINDS else cur['kind'], mid))


def delete(mid):
    db.execute('DELETE FROM memories WHERE id=?', (mid,))


def list_global(exclude_mission=False):
    rows = db.query('SELECT * FROM memories WHERE host_id IS NULL ORDER BY id DESC')
    out = [_row(r) for r in rows]
    if exclude_mission:
        out = [m for m in out if m['kind'] != 'mission']
    return out


def list_host(host_id):
    return [_row(r) for r in
            db.query('SELECT * FROM memories WHERE host_id=? ORDER BY id DESC', (host_id,))]


# ─── mission ──────────────────────────────────────────────────────────
def ensure_mission():
    if not db.query_one('SELECT id FROM memories WHERE kind="mission" AND host_id IS NULL LIMIT 1'):
        create('mission', 'Mission', DEFAULT_MISSION, None)


def get_mission():
    r = db.query_one('SELECT * FROM memories WHERE kind="mission" AND host_id IS NULL ORDER BY id LIMIT 1')
    return _row(r) if r else None


def set_mission(body):
    m = get_mission()
    if m:
        update(m['id'], body=body)
    else:
        create('mission', 'Mission', body, None)


# ─── search (FTS5 + LIKE fallback) ────────────────────────────────────
def _fts_query(q):
    toks = re.findall(r'\w+', q or '')
    return ' OR '.join(f'"{t}"' for t in toks)


def search(query, host_id=None, limit=8):
    """Search memories in scope (global always; the given host too). Returns rows
    ranked by FTS relevance, falling back to LIKE."""
    fq = _fts_query(query)
    rows = []
    if fq:
        try:
            rows = db.query(
                'SELECT m.* FROM memories_fts f JOIN memories m ON m.id=f.rowid '
                'WHERE memories_fts MATCH ? ORDER BY rank LIMIT ?', (fq, limit * 3))
        except Exception:  # noqa: BLE001 — malformed FTS expr
            rows = []
    if not rows:
        like = f'%{query}%'
        rows = db.query('SELECT * FROM memories WHERE title LIKE ? OR body LIKE ? '
                        'ORDER BY id DESC LIMIT ?', (like, like, limit * 3))
    out = []
    for r in rows:
        if r['host_id'] is None or host_id is None or r['host_id'] == host_id:
            out.append(_row(r))
    return out[:limit]


# ─── context assembly (injected into every run) ───────────────────────
def estate_context(hosts):
    """Mission + a map of hosts (with a one-line headline each) + cross-host
    global knowledge. `hosts` is the caller's scoped list of public host dicts."""
    parts = []
    m = get_mission()
    if m:
        parts.append('YOUR MISSION:\n' + m['body'])

    lines = []
    for h in hosts:
        head = db.query_one('SELECT title FROM memories WHERE host_id=? ORDER BY id DESC LIMIT 1',
                            (h['id'],))
        tag = f" [{','.join(h.get('tags', []))}]" if h.get('tags') else ''
        desc = f": {head['title']}" if head else ''
        lines.append(f"- {h['name']} ({h['address']}){tag}{desc}")
    if lines:
        parts.append('HOSTS YOU MANAGE:\n' + '\n'.join(lines))

    g = list_global(exclude_mission=True)
    if g:
        parts.append('ESTATE-WIDE KNOWLEDGE (shared services, cross-host decisions, facts — '
                     'check here before assuming something must be built new):\n' +
                     '\n'.join(f"- [{r['kind']}] {r['title']}: {r['body']}" for r in g[:40]))
    return '\n\n'.join(parts)


def host_context(host_id):
    rows = list_host(host_id)
    if not rows:
        return ''
    return ('MEMORY FOR THIS HOST (what we know / did here):\n' +
            '\n'.join(f"- [{r['kind']}] {r['title']}: {r['body']}" for r in rows[:40]))
