-- Change journal: reversible file writes (before/after content, Fernet-encrypted)
-- plus non-reversible notes for risky commands, for per-host visibility + undo.
CREATE TABLE change_journal (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id         TEXT,
  ts              TEXT NOT NULL,
  user_id         TEXT DEFAULT '',
  username        TEXT DEFAULT '',
  conversation_id TEXT DEFAULT '',
  kind            TEXT NOT NULL,          -- write_file | command
  summary         TEXT DEFAULT '',        -- path or command text
  path            TEXT DEFAULT '',
  before_enc      TEXT DEFAULT '',        -- previous file content (encrypted; '' if new/none)
  after_enc       TEXT DEFAULT '',        -- new file content (encrypted)
  had_before      INTEGER DEFAULT 0,      -- did the file exist before this change?
  used_sudo       INTEGER DEFAULT 0,
  reversible      INTEGER DEFAULT 0,
  reverted        INTEGER DEFAULT 0,
  reverted_at     TEXT DEFAULT ''
);
CREATE INDEX idx_change_host ON change_journal(host_id, id);
