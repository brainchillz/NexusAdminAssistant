-- Application & service checks: probe a service where it ANSWERS (a URL, a
-- VIP, a floating IP, a container's published port) while pinning it to the
-- inventory host where it actually LIVES. Those are different facts, and
-- conflating them is why "the website is down" doesn't tell you which box to
-- log into. The check's target answers "is it up?"; host_id answers "where do
-- I go to fix it?" — and it is what an autonomous troubleshooting run acts on.

CREATE TABLE service_checks (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL DEFAULT 'https',  -- http|https|tcp|dns|smb|ssh|ping|cert
  target        TEXT NOT NULL DEFAULT '',       -- url, host:port, ip, or hostname
  port          INTEGER DEFAULT 0,              -- 0 = per-kind default
  host_id       TEXT DEFAULT '',                -- inventory host the service runs ON
  enabled       INTEGER NOT NULL DEFAULT 1,
  interval_s    INTEGER NOT NULL DEFAULT 120,
  timeout_s     INTEGER NOT NULL DEFAULT 10,
  -- per-kind expectations (JSON): expect_status, expect_body, dns_expect,
  -- dns_type, verify_tls, cert_warn_days, smb_share, ...
  options_json  TEXT NOT NULL DEFAULT '{}',
  fail_threshold INTEGER NOT NULL DEFAULT 2,    -- consecutive failures before red

  -- autonomous troubleshooting: on red, run the agent unattended against the
  -- pinned host under a pre-authorized envelope (same model as scheduled jobs)
  auto_fix       INTEGER NOT NULL DEFAULT 0,
  auto_fix_ceiling TEXT NOT NULL DEFAULT 'caution',
  auto_fix_allow_json TEXT NOT NULL DEFAULT '[]',
  auto_fix_instruction TEXT NOT NULL DEFAULT '',
  auto_fix_cooldown_s INTEGER NOT NULL DEFAULT 1800,

  -- live state
  status        TEXT NOT NULL DEFAULT 'unknown', -- unknown|ok|warn|down
  last_check    TEXT NOT NULL DEFAULT '',
  last_ok       TEXT NOT NULL DEFAULT '',
  last_error    TEXT NOT NULL DEFAULT '',
  latency_ms    INTEGER NOT NULL DEFAULT 0,
  fail_count    INTEGER NOT NULL DEFAULT 0,
  last_auto_fix TEXT NOT NULL DEFAULT '',
  created_by    TEXT DEFAULT '',
  created_at    TEXT NOT NULL
);

CREATE INDEX idx_service_checks_host ON service_checks(host_id);

-- Result history, for "was it flapping before it died?" and the sparkline.
CREATE TABLE service_check_results (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  check_id   TEXT NOT NULL,
  ts         TEXT NOT NULL,
  status     TEXT NOT NULL,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  error      TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(check_id) REFERENCES service_checks(id) ON DELETE CASCADE
);

CREATE INDEX idx_scr_check_ts ON service_check_results(check_id, ts);
