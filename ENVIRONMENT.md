# Engineering environment

How Codex, Claude Code, the shared Engineering Harness, agent roles and this server's MCP surfaces fit
together. `AGENTS.md` is the repository authority; this file is the map.

## What was found (2026-10-01)

| Item | Location | Status |
| --- | --- | --- |
| Engineering Harness checkout (`davidiw/skills`) | `~/src/skills/engineering-harness` (git, `v0.9.0-3-g35dd9a9`, policy 0.10.0) | canonical skills/policy |
| Codex plugin install of the harness | `~/.codex/plugins/cache/davidiw-skills/engineering-harness/0.10.0` (marketplace ref `5c5dd0d`) | upgraded from 0.8.0; matches the repository profile |
| Codex user config | `~/.codex/config.toml` (`[agents] enabled`, plugin `engineering-harness@davidiw-skills`) | reused; this repo added as a trusted project so `.codex/config.toml` loads (backup: `~/.codex/config.toml.pre-local-ops`) |
| Codex agents | `~/.codex/agents/{explorer,operator,reviewer,worker}.toml` | reused, mapped below |
| Codex user skills | `~/.codex/skills/{pr-first-development,vitalthread-web-ship,review-vitalthread-beta}` | project-specific to other repos; not adopted |
| Claude user config | `~/.claude/settings.json` (model, dart-flutter plugin), no `~/.claude/agents` | no prior engineering policy |
| Claude MCP config | `~/.claude.json` (mobbin; flutter-probe for another project) | none for this project |
| Reference adoption | `~/src/workout.codex` (`AGENTS.md`, `docs/agents/workflow.md`, `engineering-harness.json`) | safety core, execution path, commit boundaries, delegation/handback, fragility checkpoint and adversarial-review contract adapted; `./vt`, worktree and release-branch machinery not adopted |
| Local tooling | uv 0.12, kind 0.33, kubectl 1.37, helm 4.3, docker 29 (user added to `docker` group; current shells use `sudo -g docker`) | installed during Phase 0 |

## Canonical policy

- Methodology: Engineering Harness skills under
  `~/src/skills/engineering-harness/plugins/engineering-harness/skills/` (router
  `using-engineering-harness`). Invariants: `references/invariants.json`; activation:
  `references/capability-activation.json`.
- Repository decisions: `AGENTS.md`, `DECISIONS.md`, `engineering-harness.json` (accepted profile).
- Runbooks in `runbooks/` are documentation, never executable authority.

No forked copy of the harness exists in this repository; both Codex and Claude read the same checkout.

## Agent mapping

The Codex roles are canonical. Claude mirrors are generated from them by `scripts/sync-agents.py`, so both
tools run the same mandate text.

| Codex agent | Responsibility | Skill dependencies | Claude equivalent | Decision |
| --- | --- | --- | --- | --- |
| `explorer` (gpt-5.6-luna, read-only) | bounded discovery and evidence location | none (reads `AGENTS.md`) | `.claude/agents/explorer.md` (haiku) | keep, mirrored |
| `operator` (gpt-5.6-luna, workspace-write) | mechanical commands, narrow corrections | none | `.claude/agents/operator.md` (haiku) | keep, mirrored |
| `worker` (gpt-5.6-terra, workspace-write) | bounded delegated implementation | builder checkpoints stay with the coordinator | `.claude/agents/worker.md` (sonnet) | keep, mirrored |
| `reviewer` (gpt-6-astra high, read-only) | fresh-context independent review | security-assurance, privacy-assurance, verification-and-operations | `.claude/agents/reviewer.md` (opus) | keep, mirrored |

Claude cannot enforce Codex's read-only sandbox for a subagent; the mirrored read-only roles carry an
explicit instruction instead. Custom agents load at session start, so restart Claude after regenerating.

## Skills

- Claude: `scripts/claude` runs `claude --plugin-dir ~/src/skills/engineering-harness/plugins/engineering-harness`.
  All 13 harness skills load as `engineering-harness:*` directly from the checkout (verified with
  `claude plugin validate` and a live session listing). Nothing is copied into this repository.
- Codex: the installed plugin `engineering-harness@davidiw-skills` is 0.10.0, with the marketplace pinned to
  commit `5c5dd0d` (upgraded from `v0.8.0` on 2026-10-01 at the user's request; previous config saved as
  `~/.codex/config.toml.pre-harness-0.10.0`). Codex exposes the router `using-engineering-harness`; the
  specialists are internal and loaded by the router.

## Compatibility exercise (Phase 0)

1. **Profile** — `profile_repository.py . --output engineering-harness.json` proposed `durable_work`,
   `external_providers`, `shared_production_state` (high confidence), `interactive_clients` (medium),
   `event_delivery` (low). The accepted profile additionally enables `ai_mediated_actions`
   (assistants submit mutations), `mutable_authority_context` (revocation and YOLO expiry during work),
   `multiple_adapters`, `generated_artifacts`, and `sensitive_data` (audit logs, credential references,
   withheld evidence). `event_delivery` stays off: the UI polls; no correctness depends on events.
2. **Activated invariants and why** — canonical-authority (always); bounded-contracts,
   explicit-composition, resource-admission-and-reclamation (multiple adapters behind protocols; locks,
   semaphores); durable-admission, normal-failure-semantics, coalesced-bounded-work (persisted requests,
   restart recovery, idempotency, bounded concurrency); shared-semantics, separate-action-authority
   (MCP and browser share one core; prepare/submit/rollback are distinct authorizations);
   versioned-compatibility, discoverable-operations, typed-exact-evidence (migrations, CLI, labeled
   fixtures vs live); authority-context-fencing, privacy-lifecycle, typed-boundaries, open-world-assurance
   (revocation fencing, disclosure lifecycle, typed contracts, independent review). Enforcement owners
   are recorded per invariant in `engineering-harness.json`.
3. **Delegated exploration** — a read-only agent was given a bounded question about the disclosure gate.
   It read `AGENTS.md` first (it quoted the mutation-test rule), returned cited facts separated from
   hypotheses, and found one real gap (`catalog_gaps` listed scans without audience filtering), fixed as
   DECISIONS.md D10.
4. **Delegated independent review** — a fresh-context reviewer loaded the harness security-assurance
   skill, restated the `AGENTS.md` mutation-test rule, stayed read-only, and returned three blockers, all
   fixed; dispositions are in `docs/build-report.md`.
5. **Policy survival** — delegated agents received only the task and a pointer to `AGENTS.md`; both the
   explorer and the reviewer restated repository rules before working, and neither edited policy files.

## Local / user-specific setup

- Docker access: this user was added to the `docker` group during Phase 0; shells started before that use
  `sudo -g docker <cmd>`; `scripts/demo-cluster.sh` already does so.
- Keys: `local-config/keys.env` (0600, gitignored) is written by `local-ops init`.
- Playwright Chromium is installed in the uv venv (`uv run playwright install chromium`).

## Entering the repository

Claude Code:

```bash
cd ~/src/service-management
scripts/claude                                       # harness skills + MCP keys; reads CLAUDE.md -> AGENTS.md; .mcp.json wires read
# write surface on demand (explicit):
claude mcp add --transport http -s local local-ops-write http://127.0.0.1:8765/mcp/write/ \
  --header "Authorization: Bearer $LOCAL_OPS_KEY_WRITE_DEFAULT"
```

Codex:

```bash
cd ~/src/service-management
set -a; . ./local-config/keys.env; set +a
codex                                                # reads AGENTS.md; .codex/config.toml wires the MCP servers
# write is disabled in .codex/config.toml; enable it there (enabled = true) when a session needs it
```

Both assume `uv run local-ops serve --config ./local-config/server.yaml --catalog ./catalog/demo` is running.
