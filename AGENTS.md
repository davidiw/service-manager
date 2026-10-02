# Local Operations MCP — Agent Rules

Local Operations MCP is a localhost MCP server that gives assistants protected, reviewed access to
discovery, diagnosis and controlled execution against an operator's estate. This file holds only rules
that must be visible in every agent session (Codex, Claude Code or another assistant). `CLAUDE.md` only
points here. Selectively loaded procedures live under `docs/agents/`.

## Safety core

- Implementation, integration (commit/push/merge), release metadata, deployment, installation, cluster
  changes and publication are separate user-authorized actions. Perform each only when the user names that
  action and target in the current conversation. A request to fix or test does not authorize the others.
- Never mutate a real estate while building or testing. Mutation tests run only
  against the disposable kind cluster created by `scripts/demo-cluster.sh`; the harness verifies the
  cluster identity recorded at creation (`local-state/demo-cluster.json`), not a context name, and rejects
  production-looking contexts.
- Documentary catalogs must keep `execution_allowed: false`. Production signing identities are never
  imported into the demo or a rehearsal.
- Secrets stay in credential systems. Catalog files, server config, source, tests, fixtures, logs, docs and
  assistant-visible results carry credential *references* only. Machine configuration holds tool paths,
  contexts and endpoints, never secret values.
- Absence is not deletion. A resource missing from an incomplete or non-comparable scan is unknown, not
  gone; only a complete comparable-scope scan may mark it missing, and history is kept.
- Diagnosis may inspect provider data and share relevant evidence with the operator to resolve a concrete
  issue, but never credentials or tokens, and only through the server's release gate.

## Universal architecture

- The server is application-neutral: application semantics live in catalog and config data, and the
  operator or calling assistant interprets them. Adding a service that uses an existing deployment
  mechanism requires a catalog file, not new Python.
- MCP surfaces and browser routes call the same core (`src/local_ops/requests.py`, `core.py`). There is
  no second, less-restricted route to provider operations.
- Approved configuration (Git), observed state (SQLite) and proposed changes/gaps are distinct
  representations; observed data never grants authority (`DECISIONS.md`).
- Each behavior has one canonical implementation path. Compatibility code is bounded and documented in
  `DECISIONS.md`, not a second product path.
- Major operations emit bounded start, progress, completion and failure signals without reproducing
  private content.
- `DECISIONS.md` records settled architecture and deviations from the external build specification
  (`docs/spec-pointer.md`); its decisions are settled unless a concrete contradiction is recorded there.

## Normal execution path

1. Inspect current state (`git status`, open work) and preserve unrelated user changes.
2. Load the documents the change triggers (see Context pointers), then inspect the code and tests before
   deciding where the work belongs.
3. Implement one coherent slice, run its focused verification, then commit it as a small imperative commit
   when commits are authorized. Distinct requests normally receive distinct commits; an explicit user
   request for no commits or a squash overrides this.
4. Before reporting completion, run the verification path below for the touched surfaces. A test that was
   not run is reported as unrun; fixture results never stand in for live verification.

## Verification path

```bash
uv sync --locked
uv run ruff check src tests
uv run mypy
uv run pytest -p no:cacheprovider --ignore=tests/integration          # unit, contract, browser
LOCAL_OPS_INTEGRATION=1 uv run pytest tests/integration -m integration -p no:cacheprovider   # opt-in kind suite
python3 ~/src/skills/engineering-harness/plugins/engineering-harness/scripts/profile_repository.py . --check engineering-harness.json
```

## Context pointers

- Before consequential changes or reviews — trust/authorization, disclosure, durable state, executors,
  shared testing or review policy — read `engineering-harness.json` for the accepted policy and enforcement
  owners, and `docs/agents/workflow.md` for delegation, review and the adopted harness revision.
- Before changing architecture, contracts or representations, read `DECISIONS.md`.
- Before touching agent, skill or MCP wiring, read `ENVIRONMENT.md`.
- Before any cluster action, read `scripts/demo-cluster.sh` and confirm the recorded identity.

## Canonical documents

- `AGENTS.md`: always-loaded safety, architecture, execution path and pointers.
- `docs/agents/workflow.md`: delegation, handbacks, fragility checkpoint, independent review, harness
  adoption.
- `DECISIONS.md`: architecture authority and spec deviations.
- `ENVIRONMENT.md`: Codex/Claude/harness/MCP wiring and machine setup.
- `README.md`: install, run and operator overview. `docs/build-report.md`: what was built and verified.
- `runbooks/`: documentation only; never executable authority.
