-- Phase 4: scheduled unattended jobs + deferred-approval queue.

-- Extend the jobs table (0001 created the base) with the unattended envelope.
ALTER TABLE jobs ADD COLUMN ceiling      TEXT NOT NULL DEFAULT 'caution';  -- safe|caution|risky|critical
ALTER TABLE jobs ADD COLUMN allow_json   TEXT NOT NULL DEFAULT '[]';       -- pre-approved command substrings
ALTER TABLE jobs ADD COLUMN tz           TEXT NOT NULL DEFAULT 'UTC';
ALTER TABLE jobs ADD COLUMN next_run     TEXT DEFAULT '';
ALTER TABLE jobs ADD COLUMN created_by   TEXT DEFAULT '';
ALTER TABLE jobs ADD COLUMN notify_url   TEXT DEFAULT '';                  -- optional per-job webhook
ALTER TABLE jobs ADD COLUMN kind         TEXT NOT NULL DEFAULT 'cron';     -- cron | once

-- Actions a job wanted to take but that fell outside its pre-authorized envelope.
CREATE TABLE deferred_actions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id      TEXT REFERENCES jobs(id) ON DELETE CASCADE,
  host_id     TEXT DEFAULT '',
  tool        TEXT NOT NULL,
  args_json   TEXT NOT NULL DEFAULT '{}',
  command     TEXT DEFAULT '',
  risk        TEXT DEFAULT '',
  reason      TEXT DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | denied
  created_at  TEXT NOT NULL,
  resolved_at TEXT DEFAULT ''
);
CREATE INDEX idx_deferred_status ON deferred_actions(status, id);
