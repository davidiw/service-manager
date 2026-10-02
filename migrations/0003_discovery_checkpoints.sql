-- Private, opaque continuation tokens for resumable provider discovery.  These are deliberately
-- separate from audit cursors: they are not exposed through any public storage listing API.
CREATE TABLE IF NOT EXISTS discovery_checkpoints (
  key TEXT PRIMARY KEY,
  cursor TEXT,
  version INTEGER NOT NULL,
  updated_at TEXT NOT NULL
);
