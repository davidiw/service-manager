# Local Operations MCP (`local-ops-mcp`)

One localhost server that gives a coding assistant (Claude Code, Codex or any MCP client) three
separately authorized capabilities over a small production estate, with a local browser for human review:

| Capability | What it answers | Authority |
| --- | --- | --- |
| Discovery (`/mcp/discovery/`) | *What runs production?* Service map, observed resources, matches, gaps, contradictions, unknowns. | read-only; writes private observations |
| Diagnosis (`/mcp/diagnosis/`) | *This service is unhealthy, where should I look? Was there an intrusion?* Inspection, bounded evidence queries, explainable findings with coverage. | read-only; writes private evidence |
| Execution (`/mcp/execution/`) | *Restart this service. Update it to this digest.* Exact reviewed plans; native Kubernetes and Helm executors; explicit rollback. | declared operations on approved targets only |

Everything an assistant asks for becomes a durable request with two independent review gates (before the
operation runs, before its response is disclosed). The reviewer sees the normalized request and exact
before/after state, not the assistant's prose. YOLO mode skips the human stops only; it never widens
authorization.

## Quick start (no production credentials needed)

```bash
uv sync --locked
uv run local-ops init --config-dir ./local-config --state-dir ./local-state   # prompts for a reviewer password; writes local-config/keys.env (0600)
uv run local-ops doctor --config ./local-config/server.yaml --catalog ./catalog/demo
uv run local-ops serve  --config ./local-config/server.yaml --catalog ./catalog/demo
```

Open http://127.0.0.1:8765/review and log in as `reviewer`. Then, from another shell:

```bash
set -a; . ./local-config/keys.env; set +a
uv run python examples/mcp_client_example.py discovery discovery_scan '{"providers": ["demo-fake"]}'
```

Approve the request in the browser, watch it run, release the response, and the client prints the result.

### Disposable Kubernetes demo (real executors)

```bash
scripts/demo-cluster.sh up        # kind cluster + local registry + 3 image revisions (v1, v2, v2-broken) + helm release
scripts/demo-cluster.sh status
LOCAL_OPS_INTEGRATION=1 uv run pytest tests/integration -m integration -p no:cacheprovider   # opt-in: update/restart/rollback/helm/failure/reconcile against kind
scripts/demo-cluster.sh down
```

The demo catalog (`catalog/demo`) enables execution only against the disposable demo cluster.

## Connect an assistant

Start the server, export the keys (`set -a; . ./local-config/keys.env; set +a`), then:

- **Claude Code**: `.mcp.json` in this repository wires `local-ops-discovery` and `local-ops-diagnosis`
  (headers use `${LOCAL_OPS_KEY_*}`). Add execution explicitly:
  `claude mcp add --transport http -s local local-ops-execution http://127.0.0.1:8765/mcp/execution/ --header "Authorization: Bearer $LOCAL_OPS_KEY_EXECUTION_DEFAULT"`
- **Codex**: `.codex/config.toml` wires the same two servers via `bearer_token_env_var`; execution is present
  but disabled until you flip `enabled = true` or run
  `codex mcp add local-ops-execution --url http://127.0.0.1:8765/mcp/execution/ --bearer-token-env-var LOCAL_OPS_KEY_EXECUTION_DEFAULT`.
- **Any MCP client (official SDK)**: `examples/mcp_client_example.py`.

Grants are explicit, not cumulative: `local-ops keys create analyst --grant discovery --grant diagnosis --config ./local-config/server.yaml`.

## Review modes and YOLO

Per client and capability (Settings page): `review_both` (default), `review_requests`, `review_responses`
(read-only capabilities only), `yolo`. A temporary YOLO override expires and is shown in a banner. Mode
changes affect new requests only. YOLO keeps authorization, target validation, bounds, credential
protection, serialization and history. The stop switch blocks new mutation dispatches at any time.

## Catalog (service map)

One Markdown file per service with typed YAML front matter (`src/local_ops/catalog.py`). It answers what,
why, who, where, dependencies, artifact/repository/mechanism, credential *references*, health signals,
logs/metrics/alerts, restart path, knowledge holders, facts with confidence, contradictions and unknowns.
`local-ops catalog validate ./catalog/demo` and `local-ops catalog export` work without the server.

The catalog is also the shared memory across sessions and assistants. A service's `knowledge` block
holds reviewed saved queries (run with `saved_query_run`) and failure signatures. When an assistant learns
something durable it calls `catalog_propose` with a small JSON-Patch-style change and the evidence ids
behind it. You review it at `/proposals`; accepting writes `<state_dir>/proposals/<id>.patch`, which you
apply with `git apply` and commit. Assistants can only propose descriptive and knowledge fields, or add a
binding with execution disabled (DECISIONS D24).

## Provider authentication

Credential entries in `server.yaml` are references (env var, 0600 file, AWS profile/SSO, kubeconfig context,
1Password item via a service account). The server resolves them, registers the literal with the sanitizer,
and never returns them. AWS account identity is verified with STS against `expected_account_id`; SSO expiry
pauses with `auth_required` rather than switching profiles. See `docs/access-guide.md` for the minimum
access each adapter needs and which live checks remain unverified.

## Async behaviour

All provider I/O is async (aiobotocore, kubernetes_asyncio, httpx, the async 1Password SDK, aiosqlite).
Concurrency is bounded globally and per provider; a slow audit query does not stall status, the queue or an
unrelated operation (`tests/test_async_bounds.py`). Helm and other trusted helpers run through
`asyncio.create_subprocess_exec` with a minimal environment.

## Evidence handling

Provider results are collected privately, credential-scrubbed at ingestion (what was removed is recorded),
bounded, and released only by the reviewer (or automatically in modes without response review). Withheld
evidence cannot be read through ids, catalog reads, exports, findings, errors or another principal
(`tests/test_disclosure.py`). Large evidence lives in `local-state/evidence/` under restrictive permissions.
Retention: collected payloads 14 days, released evidence 30, audit events 90 (configurable; holds supported).

## Same-user limitation

A process running as the same OS user can read `local-state/` and `local-config/` directly. Ordinary local
mode gives tool-level authorization and review, not hostile-process containment. For stronger separation run
the server under a dedicated OS user that alone can read the state and config directories, and give agents
only the API keys.

## Repository map

`AGENTS.md` (agent rules) · `DECISIONS.md` (architecture) · `ENVIRONMENT.md` (Codex/Claude wiring) ·
`docs/build-report.md` (what was built and tested) · `docs/access-guide.md` (per-adapter access) ·
`src/local_ops/` (server) · `catalog/` (demo) · `runbooks/` (documentation only) ·
`scripts/demo-cluster.sh` (disposable cluster) · `tests/` (unit, contract, browser, opt-in integration).
