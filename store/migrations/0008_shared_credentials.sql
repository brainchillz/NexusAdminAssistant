-- Shared credential store: named reusable SSH identities. A host may reference
-- one instead of (or as a fallback to) its own per-host key — matching fleets
-- where one admin key is authorized everywhere. Private key is Fernet ciphertext;
-- the derived public key is stored in the clear (it is public) so the UI can
-- show/copy/deploy it without ever decrypting the private half.

CREATE TABLE credentials (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  username     TEXT DEFAULT '',            -- default login user hint
  ssh_key_enc  TEXT NOT NULL,
  public_key   TEXT NOT NULL DEFAULT '',   -- openssh authorized_keys line
  created_at   TEXT NOT NULL
);

ALTER TABLE hosts ADD COLUMN credential_id TEXT DEFAULT '';
