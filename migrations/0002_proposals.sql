-- Agent-authored catalog change proposals (DECISIONS D24). Never approved configuration: an accepted
-- proposal only produces a patch under the state directory for a human to commit.
CREATE TABLE IF NOT EXISTS proposals (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  service_id TEXT NOT NULL,
  is_new_service INTEGER NOT NULL DEFAULT 0,
  base_revision TEXT NOT NULL,
  base_file_hash TEXT,
  target_path TEXT NOT NULL,
  reason TEXT,
  changes TEXT NOT NULL,
  citations TEXT NOT NULL DEFAULT '[]',
  proposed_text TEXT NOT NULL,
  proposed_file_hash TEXT NOT NULL,
  diff TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  decided_at TEXT,
  decided_by TEXT,
  decision_note TEXT,
  patch_path TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS proposals_content ON proposals(principal_id, content_hash);
CREATE INDEX IF NOT EXISTS proposals_status ON proposals(status, created_at);
