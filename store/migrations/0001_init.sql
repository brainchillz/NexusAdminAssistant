-- Nexus Admin Assistant — initial schema.
-- One SQLite DB for everything. Secret columns hold Fernet ciphertext.

CREATE TABLE users (
  id           TEXT PRIMARY KEY,
  username     TEXT NOT NULL UNIQUE,
  pw_hash      TEXT NOT NULL,
  role         TEXT NOT NULL DEFAULT 'operator',   -- admin | operator | viewer
  scope_tags   TEXT NOT NULL DEFAULT '[]',          -- JSON array; [] = unscoped
  must_change  INTEGER NOT NULL DEFAULT 0,
  created_at   TEXT NOT NULL
);

CREATE TABLE hosts (
  id                TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  address           TEXT NOT NULL,                  -- ip or hostname
  port              INTEGER NOT NULL DEFAULT 22,
  conn_type         TEXT NOT NULL DEFAULT 'ssh',    -- ssh | http | telnet
  username          TEXT DEFAULT '',
  password_enc      TEXT DEFAULT '',
  ssh_key_enc       TEXT DEFAULT '',
  token_enc         TEXT DEFAULT '',
  sudo_password_enc TEXT DEFAULT '',
  tags              TEXT NOT NULL DEFAULT '[]',     -- JSON array
  autonomy_level    TEXT NOT NULL DEFAULT 'default',-- lab | default | prod
  notes             TEXT DEFAULT '',
  created_at        TEXT NOT NULL,
  last_seen         TEXT DEFAULT ''
);

CREATE TABLE conversations (
  id          TEXT PRIMARY KEY,
  host_id     TEXT REFERENCES hosts(id) ON DELETE SET NULL,
  user_id     TEXT REFERENCES users(id) ON DELETE SET NULL,
  title       TEXT NOT NULL DEFAULT 'New conversation',
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE messages (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  conversation_id  TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  role             TEXT NOT NULL,                  -- system | user | assistant | tool
  content          TEXT NOT NULL DEFAULT '',
  tool_calls_json  TEXT DEFAULT '',                -- JSON of tool calls/results for this turn
  created_at       TEXT NOT NULL
);
CREATE INDEX idx_messages_conv ON messages(conversation_id, id);

CREATE TABLE memories (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id     TEXT REFERENCES hosts(id) ON DELETE CASCADE,
  kind        TEXT NOT NULL DEFAULT 'fact',        -- fact | decision | state | changelog
  title       TEXT NOT NULL,
  body        TEXT NOT NULL DEFAULT '',
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_memories_host ON memories(host_id);

-- FTS5 mirror for memory_search (Phase 3). Kept in sync by schema.py helpers.
CREATE VIRTUAL TABLE memories_fts USING fts5(
  title, body, content='memories', content_rowid='id'
);
CREATE TRIGGER memories_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
END;
CREATE TRIGGER memories_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, body) VALUES('delete', old.id, old.title, old.body);
END;
CREATE TRIGGER memories_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, title, body) VALUES('delete', old.id, old.title, old.body);
  INSERT INTO memories_fts(rowid, title, body) VALUES (new.id, new.title, new.body);
END;

CREATE TABLE skills (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL,
  params_json TEXT NOT NULL DEFAULT '{}',
  body        TEXT NOT NULL DEFAULT '',
  approved    INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
);

CREATE TABLE jobs (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  host_id      TEXT REFERENCES hosts(id) ON DELETE CASCADE,
  schedule     TEXT NOT NULL DEFAULT '',            -- cron expr or ISO one-shot
  instruction  TEXT NOT NULL DEFAULT '',
  enabled      INTEGER NOT NULL DEFAULT 1,
  last_run     TEXT DEFAULT '',
  last_status  TEXT DEFAULT '',
  last_report  TEXT DEFAULT '',
  created_at   TEXT NOT NULL
);

CREATE TABLE audit (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          TEXT NOT NULL,
  user_id     TEXT DEFAULT '',
  username    TEXT DEFAULT '',
  host_id     TEXT DEFAULT '',
  action      TEXT NOT NULL,
  detail      TEXT DEFAULT '',
  decision    TEXT DEFAULT ''                       -- approved | denied | auto | ''
);
CREATE INDEX idx_audit_ts ON audit(id);

-- Singleton settings row (LLM config etc.). id is always 1.
CREATE TABLE settings (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  data_json   TEXT NOT NULL DEFAULT '{}'
);
INSERT INTO settings(id, data_json) VALUES (1, '{}');
