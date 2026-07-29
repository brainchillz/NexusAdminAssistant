-- Per-host documentation (markdown) the agent can generate + the user can view.
ALTER TABLE hosts ADD COLUMN doc TEXT DEFAULT '';
ALTER TABLE hosts ADD COLUMN doc_updated TEXT DEFAULT '';
