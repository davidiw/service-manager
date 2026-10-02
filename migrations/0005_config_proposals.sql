-- Assistant-proposed machine-configuration changes (DECISIONS D29): a bounded addition to the
-- provider-connection overlay, verified by the server and approved by a human. Distinct from catalog
-- proposals (D24), which only ever produce a patch for a human to apply.
CREATE TABLE IF NOT EXISTS config_proposals (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  overlay_diff TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  decision_note TEXT,
  overlay_commit TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS config_proposals_content ON config_proposals(principal_id, content_hash);
CREATE INDEX IF NOT EXISTS config_proposals_status ON config_proposals(status, created_at);
