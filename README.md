# Local Operations MCP (`local-ops-mcp`)

One localhost server that gives a coding assistant (Claude Code, Codex or any MCP client) two separately
authorized capabilities over a small production estate, with a local browser for human review:

| Capability | What it answers | Authority |
| --- | --- | --- |
| Read (`/mcp/read/`) | *What runs production? This service is unhealthy, where should I look? Was there an intrusion?* Service map, observed resources, gaps, access graph; inspection, bounded evidence queries, explainable findings with coverage. | read-only; writes private observations and evidence |
| Write (`/mcp/write/`) | *Restart this service. Update it to this digest.* Exact reviewed plans; native Kubernetes and Helm executors; explicit rollback. | declared operations on approved targets only |

Review is set per client and **data class** (DECISIONS D28): `inventory` (provider metadata from
discovery scans), `content` (log lines, audit events with users and IPs, container output) and `mutation`.

Everything an assistant asks for becomes a durable request with two independent review gates (before the
operation runs, before its response is disclosed). The reviewer sees the normalized request and exact
before/after state, not the assistant's prose. YOLO mode skips the human stops only; it never widens
authorization.

New to local-ops? Start with [`docs/onboarding.md`](docs/onboarding.md).

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
uv run python examples/mcp_client_example.py read discovery_scan '{"providers": ["demo-fake"]}'
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

## AWS estate census

The AWS adapter inventories metadata for identity, compute, storage, networking/edge, data/state,
messaging, monitoring, orchestration, and CloudFormation families. With no `families` list in an AWS
provider configuration, it selects every supported read-only family; `regions` remains an explicit
configured scan boundary, not an assertion about every enabled AWS region. It never reads secret values,
log contents, application data, or performs KMS cryptographic operations.

Every AWS discovery response includes a coverage summary. A family scope is `complete`,
`partial_resumable`, `partial_restart`, or `unavailable`. Only a complete, verified, comparable scope can
support an empty-inventory conclusion. Incomplete and resumed-suffix scopes never mark a prior observation
missing. CloudWatch Logs log-group and Secrets Manager list pagination retain private 24-hour checkpoints
at committed page boundaries; other interrupted families restart. Checkpoints are bound to the configured
principal, verified account, configuration, and scope.

Organizations enumeration is opt-in. When it is available, the report distinguishes organization accounts
known from configured, reached, inaccessible, unconfigured, and intentionally excluded accounts. Without it,
the organization account denominator is unknown. Cost Explorer `SERVICE` labels with at least $0.01 spend
are a coverage signal only: the report says whether their enumerator completed, is incomplete/unavailable,
is intentionally non-resource billing, or is unsupported. Zero spend never proves absence. Management-account billing retains visible member-account spend, attributed to each linked account with `billing_source_account` provenance. Billing-only accounts appear in account coverage with billing evidence and their configuration/reachability status, even without Organizations access. They do not establish an Organizations denominator or imply successful resource discovery.

## Connect an assistant

Start the server, export the keys (`set -a; . ./local-config/keys.env; set +a`), then:

- **Claude Code**: `.mcp.json` in this repository wires `local-ops-read` (header uses
  `${LOCAL_OPS_KEY_READ_DEFAULT}`). Add write explicitly:
  `claude mcp add --transport http -s local local-ops-write http://127.0.0.1:8765/mcp/write/ --header "Authorization: Bearer $LOCAL_OPS_KEY_WRITE_DEFAULT"`
- **Codex**: `.codex/config.toml` wires `local-ops-read` via `bearer_token_env_var`; `local-ops-write` is
  present but disabled until you flip `enabled = true`.
- **Any MCP client (official SDK)**: `examples/mcp_client_example.py`.

Grants are explicit, not cumulative: `local-ops keys create analyst --grant read --config ./local-config/server.yaml`.

## Review modes and YOLO

Per client and data class (Settings page): `review_both` (default), `review_requests`, `review_responses`
(inventory and content only), `yolo`. A typical setup is inventory `yolo`, content `review_responses` (runs
immediately, you release what the assistant may see) and mutation `review_both`. A temporary YOLO override expires and is shown in a banner. Mode
changes affect new requests only. YOLO keeps authorization, target validation, bounds, credential
protection, serialization and history. The stop switch blocks new mutation dispatches at any time.

## Catalog (service map)

One Markdown file per service with typed YAML front matter (`src/local_ops/catalog.py`). It answers what,
why, who, where, dependencies, artifact/repository/mechanism, credential *references*, health signals,
logs/metrics/alerts, restart path, knowledge holders, facts with confidence, contradictions and unknowns.
`local-ops catalog validate ./catalog/demo` and `local-ops catalog export` work without the server.
For a separate documentary catalog, use `local-ops catalog validate /path/to/catalog --strict
--documentary --format json` in CI. `catalog schema --kind service` emits the canonical editor schema;
`catalog report /path/to/catalog` reports declarations and gaps without contacting providers. See
[catalog development](docs/catalog-development.md) for commands, exit codes and issue publication.

The catalog is also the shared memory across sessions and assistants. A service's `knowledge` block
holds reviewed saved queries (run with `saved_query_run`) and failure signatures. When an assistant learns
something durable it calls `catalog_propose` with a small JSON-Patch-style change and the evidence ids
behind it. You review it at `/proposals`; accepting writes the one service file and commits it into the
catalog's own Git repository (author `local-ops`), so the catalog directory must already be a Git
repository. A `.patch` audit copy is also kept under `<state_dir>/proposals/`. The server reloads within a
few seconds of the commit (uncommitted edits need the Reload button on `/catalog`). Assistants can only
propose descriptive and knowledge fields, or add a binding with execution disabled (DECISIONS D24).

An assistant can also propose a new Kubernetes connection or a cluster identity pin with `config_propose`
(DECISIONS D29); review it in the same `/proposals` page, in its own section. Accepting writes and commits
`config/overlay.yaml` in the catalog repository and hot-reloads the provider registry — no restart needed.

## Operational map and AWS access

`/ops` turns the approved catalog into an operations view: environment → service → the concrete resources
its bindings name, with state, IPs/DNS, launch times, exact provider relationships (subnet/VPC/security
groups, volumes, instance profile → role, ASG, target group → load balancer → DNS), logs, metrics
identifiers, alarms, access path, operations (display only) and what is unknown. Every resource shows its
freshness and its scope's coverage in the latest released scan; only released observations appear.
`/ops/inventory` keeps the provider-native listing, and `/ops/access` (plus `/ops/access/guide.md`) explains
how a person receives and loses AWS access from the observed Identity Center/IAM graph, with coverage
warnings, and gives an exact per-person offboarding checklist (DECISIONS D25-D27).

Bindings can name resources exactly with `resource_keys` or a tag `selector`:

```yaml
bindings:
  - id: nodes
    environment: <env>
    provider_id: <aws provider id>
    region: us-west-2
    selector: {resource_types: [aws/ec2_instance], tags: {<tag>: <value>}}
```

The server never groups resources into services itself. An assistant uses `observations_query`
(discovery/diagnosis surfaces) to correlate released observations, then proposes services and bindings with
`catalog_propose`; a reviewer accepts them at `/proposals` and a human commits the patch.

## Provider authentication

Credential entries in `server.yaml` are references (env var, 0600 file, AWS profile/SSO, kubeconfig context,
1Password item via a service account). The server resolves them, registers the literal with the sanitizer,
and never returns them. AWS account identity is verified with STS against `expected_account_id`; SSO expiry
pauses with `auth_required` rather than switching profiles. See `docs/access-guide.md` for the minimum
access each adapter needs and which live checks remain unverified.

### Human-operated 1Password CLI inventory

For a headless inventory operated with a human's existing 1Password CLI session, configure the credential
reference with the required account selector and point the existing provider at it. Keep the provider's
`vaults: []` setting: it means the scan is limited to vaults visible to that authenticated account; it does
not mean organization-wide visibility.

```yaml
credentials:
  - id: op-human-cli
    kind: onepassword_cli
    account: moveindustries
    purpose: read
providers:
  - id: onepassword-main
    kind: onepassword
    credential: op-human-cli
    vaults: []
```

Authenticate the CLI yourself through your normal 1Password flow before starting the server. This project
does not invoke `op signin`, read from standard input, or provide sign-in syntax; consult your normal CLI
flow if authentication is needed. If that flow exports session state, export it outside the server process
and restart the server so its inherited environment contains it.

These optional, human-run checks inspect the selected account without changing it:

```bash
op account list
op whoami --account moveindustries --format json
op vault list --account moveindustries --format json
```

The adapter only invokes `whoami`, `vault list`, and `item list`. Each backend invocation uses account
`moveindustries`, JSON output, ISO timestamps, and disabled CLI cache; item listing also supplies a vault
and includes archived items. It never invokes `get`, `read`, `inject`, `run`, document retrieval, or sign-in,
so CLI mode supports metadata inventory only and cannot resolve item secrets. It starts with no standard
input, disables desktop biometric unlocking, and removes inherited service-account and Connect credentials
before launching the CLI. Each invocation is bounded to 30 seconds, 16 MiB of stdout, and 64 KiB of stderr.
Scoped service-account automation remains a separate credential type for unattended access to specifically
granted vaults.

With the server's local discovery key loaded and the review UI open, run the first scan through the normal
review gate:

```bash
uv run local-ops doctor --config ./local-config/server.yaml --catalog ~/.local/share/local-ops/catalog --live
uv run local-ops serve --config ./local-config/server.yaml --catalog ~/.local/share/local-ops/catalog
# In another shell, load the local discovery key, submit the request, then approve and release it at /review.
set -a; . ./local-config/keys.env; set +a
uv run python examples/mcp_client_example.py read discovery_scan '{"providers":["onepassword-main"]}'
```

No real 1Password account has been verified in this build. `doctor --live` verifies the configured live
adapter; `serve` uses the same config and catalog. Review the request and its released result at
`http://127.0.0.1:8765/review`. Inventory metadata can contain unfamiliar or future fields; treat those as
unknown. Visibility is not organization-wide, and historical creator or editor metadata does not establish a
current custodian.

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
