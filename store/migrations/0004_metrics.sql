-- Phase 6: lightweight host health metrics (SSH-polled samples for trend/history).
CREATE TABLE host_metrics (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host_id    TEXT NOT NULL,
  ts         TEXT NOT NULL,
  reachable  INTEGER NOT NULL DEFAULT 0,
  cpu        INTEGER DEFAULT 0,   -- approx % (load/cores)
  mem        INTEGER DEFAULT 0,   -- %
  disk       INTEGER DEFAULT 0,   -- max mount %
  load1      REAL DEFAULT 0
);
CREATE INDEX idx_host_metrics ON host_metrics(host_id, id);
