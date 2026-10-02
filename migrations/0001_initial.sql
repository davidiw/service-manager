-- Local Operations MCP initial schema. Timestamps are ISO-8601 UTC strings.
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  key_prefix TEXT NOT NULL,
  grants TEXT NOT NULL,            -- JSON list of capabilities
  created_at TEXT NOT NULL,
  revoked_at TEXT,
  rotated_from TEXT,
  last_used_at TEXT,
  note TEXT
);
CREATE INDEX IF NOT EXISTS principals_key_hash ON principals(key_hash);

CREATE TABLE IF NOT EXISTS reviewers (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS reviewer_sessions (
  id TEXT PRIMARY KEY,
  reviewer_id TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS review_settings (
  principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  mode TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  PRIMARY KEY (principal_id, capability)
);

CREATE TABLE IF NOT EXISTS review_overrides (
  id TEXT PRIMARY KEY,
  principal_id TEXT,                -- NULL = all principals
  capability TEXT,                  -- NULL = all capabilities
  mode TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS requests (
  id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  operation TEXT NOT NULL,
  reason TEXT,
  current_revision INTEGER NOT NULL DEFAULT 1,
  execution_status TEXT NOT NULL,
  response_status TEXT NOT NULL,
  phase TEXT,
  idempotency_key TEXT,
  idempotency_hash TEXT,
  review_request INTEGER NOT NULL,
  review_response INTEGER NOT NULL,
  review_mode TEXT NOT NULL,
  catalog_revision TEXT,
  target_key TEXT,
  plan_id TEXT,
  audience TEXT NOT NULL,           -- JSON list of principal ids allowed to read the released result
  public_error TEXT,
  private_error TEXT,
  cancel_requested_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  worker_token TEXT
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(execution_status, response_status);
CREATE UNIQUE INDEX IF NOT EXISTS requests_idem ON requests(principal_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS request_revisions (
  request_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  args TEXT NOT NULL,               -- canonical JSON
  args_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  note TEXT,
  PRIMARY KEY (request_id, revision)
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  args_hash TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  implementation_version TEXT NOT NULL,
  catalog_revision TEXT,
  plan_hash TEXT,
  approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  invalidated_at TEXT,
  invalidated_reason TEXT
);
CREATE INDEX IF NOT EXISTS approvals_request ON approvals(request_id);

CREATE TABLE IF NOT EXISTS results (
  request_id TEXT PRIMARY KEY,
  candidate TEXT,                   -- JSON, private until released
  candidate_bytes INTEGER,
  sanitization TEXT,                -- JSON report of removed items
  released TEXT,                    -- JSON projection
  redaction TEXT,                   -- JSON redaction record
  released_at TEXT,
  released_by TEXT,
  withheld_at TEXT,
  withheld_by TEXT,
  withhold_reason TEXT,
  evidence_ids TEXT NOT NULL DEFAULT '[]',
  truncated INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY,
  request_id TEXT,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  bytes INTEGER NOT NULL,
  path TEXT,                        -- private file relative to evidence dir
  summary TEXT,
  sanitization TEXT,
  released_to TEXT NOT NULL DEFAULT '[]',
  retention_hold INTEGER NOT NULL DEFAULT 0,
  provenance TEXT
);
CREATE INDEX IF NOT EXISTS evidence_request ON evidence(request_id);

CREATE TABLE IF NOT EXISTS scans (
  request_id TEXT PRIMARY KEY,
  provider_ids TEXT NOT NULL,
  scope TEXT NOT NULL,
  denominators TEXT,
  completed_scopes TEXT,
  unavailable TEXT,
  started_at TEXT,
  finished_at TEXT
);

CREATE TABLE IF NOT EXISTS observations (
  id TEXT PRIMARY KEY,
  scan_request_id TEXT,
  provider_id TEXT NOT NULL,
  resource_key TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  identity TEXT NOT NULL,
  attributes TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  evidence_id TEXT,
  match_service_id TEXT,
  match_binding_id TEXT,
  match_basis TEXT,
  match_confidence TEXT,
  released_to TEXT NOT NULL DEFAULT '[]',
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  missing_since TEXT,
  scope_key TEXT
);
CREATE INDEX IF NOT EXISTS observations_resource ON observations(provider_id, resource_key);
CREATE INDEX IF NOT EXISTS observations_service ON observations(match_service_id);

CREATE TABLE IF NOT EXISTS audit_events (
  event_key TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  source_id TEXT NOT NULL,
  account TEXT,
  region TEXT,
  event_id TEXT,
  occurred_at TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  actor TEXT,
  actor_type TEXT,
  session TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  resource_type TEXT,
  source_ip TEXT,
  user_agent TEXT,
  outcome TEXT,
  category TEXT,
  request_id TEXT,
  evidence_id TEXT,
  fields TEXT NOT NULL,
  released_to TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(source_id, occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_request ON audit_events(request_id);

CREATE TABLE IF NOT EXISTS audit_cursors (
  source_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  cursor TEXT,
  last_event_at TEXT,
  updated_at TEXT NOT NULL,
  note TEXT,
  PRIMARY KEY (source_id, scope)
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  request_id TEXT,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  body TEXT NOT NULL,
  evidence_ids TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  released_to TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS plans (
  plan_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  body TEXT NOT NULL,
  target_key TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_by_request_id TEXT,
  released_to TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS receipts (
  receipt_id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  plan_id TEXT NOT NULL,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operation_locks (
  target_key TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  acquired_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_intents (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  target_key TEXT,
  description TEXT NOT NULL,
  provider_op TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  completed_at TEXT,
  result TEXT
);
CREATE INDEX IF NOT EXISTS intents_request ON provider_intents(request_id);

CREATE TABLE IF NOT EXISTS schedules (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  operation TEXT NOT NULL,
  template TEXT NOT NULL,
  frequency_seconds INTEGER NOT NULL,
  lookback_seconds INTEGER NOT NULL,
  budgets TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  disclosure TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_run_at TEXT,
  last_request_id TEXT,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT
);

CREATE TABLE IF NOT EXISTS app_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  actor_kind TEXT NOT NULL,
  action TEXT NOT NULL,
  request_id TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS app_audit_request ON app_audit(request_id);
