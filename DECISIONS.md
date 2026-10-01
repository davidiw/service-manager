# Architecture decisions and deviations from the build specification

This file is the repository's architecture authority (see `AGENTS.md`). Each entry records a settled
decision, why, and where it is enforced. The build specification
(`/media/data2/local-ops-mcp-build-spec.md`) remains authoritative except where an entry below records a
concrete contradiction found during implementation.

## Authority

| Concern | Owner |
| --- | --- |
| Public contracts (statuses, errors, coverage, plans, receipts) | `src/local_ops/models.py` |
| Approved configuration schema and validation | `src/local_ops/catalog.py` |
| Server/provider/credential configuration | `src/local_ops/config.py` |
| Request lifecycle, idempotency, approvals, release gate | `src/local_ops/requests.py`, `src/local_ops/storage.py` |
| Durable execution, serialization, recovery, schedules, retention | `src/local_ops/worker.py` |
| Disclosure sanitization/redaction/provenance | `src/local_ops/release.py` |
| Provider adapter protocol | `src/local_ops/providers/base.py` |
| Executor protocol, plans, fingerprints, receipts, reconciliation | `src/local_ops/executors/base.py` |
| MCP surfaces (thin) | `src/local_ops/mcp_surfaces.py` |
| Composition root, auth middleware, transport security | `src/local_ops/app.py` |
| Reviewer site | `src/local_ops/web/` |

## Three kinds of data

1. **Approved configuration** — Git-versioned Markdown service files with typed YAML front matter
   (`catalog/*/services/*.md`, `catalog.yaml`, `identities.yaml`). Loaded from a trusted path; never written
   by the server. Its hash is the *catalog revision* bound into approvals and plans.
2. **Observed state** — SQLite tables `observations`, `audit_events`, `findings`, `evidence`, `plans`,
   `receipts`. Every row carries `released_to`; nothing observed grants execution authority.
3. **Proposed changes / gaps** — computed at read time (`Catalog.gaps()`, `discovery.observed_gaps`) and
   from scans; exports are written only under the state directory.

## Decisions

### D1. Own bearer-key middleware instead of the SDK's OAuth resource-server auth
The MCP SDK v2 enables bearer auth only through `AuthSettings(issuer_url=…)`, which also publishes OAuth
protected-resource metadata. The spec forbids claiming OAuth. `BearerKeyMiddleware` (app.py) verifies the
key hash, checks the capability grant, and populates the same `scope["user"]` shape the SDK uses, so the SDK's
own per-credential session binding still rejects session swapping (tested in `tests/test_transport.py`).

### D2. Three review stops for an update in `review_both`
`action_prepare` is a reviewed read (request + response), and `action_submit` is a reviewed mutation.
`review_requests` collapses this to two stops, YOLO to zero. This follows the spec's two-step contract
literally; the reviewer UI labels pending execution versus pending disclosure to keep it legible.

### D3. Digest pinning requires a registry
`require_digest: true` resolves tags through a `registry` provider (OCI v2 API; ECR through the same API with
a token). The demo therefore runs a local registry beside kind so digests are real manifest digests, and the
plan records the digest kind (index vs manifest) separately from the running image id.

### D4. Target fingerprint excludes status timestamps
`target_fingerprint()` hashes UID, container images, pod-template annotations, managed-by markers and
replica count. Status changes do not invalidate a plan; a template change does (`plan_stale`). Patches are
conditional on `resourceVersion` with one re-verified retry on 409.

### D5. Serialization key is the shared deployment boundary
Locks are keyed by cluster identity + namespace + kind + UID (or Helm release), not by service id. Two catalog
services pointing at one workload serialize on the same key (`tests/test_execution.py`). Locks are taken
only at dispatch, never while waiting for a human.

### D6. Intent before side effect; reconcile, never retry
A `provider_intents` row is written before any mutation is sent. On restart, a mutation found with a recorded
intent is reconciled by inspecting the target (`executors/*.reconcile`) and classified
succeeded/partial/failed/outcome_unknown; a mutation without an intent is requeued; read-only work is
requeued. No mutation is ever re-sent automatically.

The same reconciliation is the only exit path for a mutation once it has run, not just the startup path:
- **Shutdown mid-mutation.** `Worker.stop()` cancels the running task via `asyncio.Task.cancel()`. A
  mutation's `_run` never finalizes that as CANCELLED, with or without a dispatched intent: finalizing
  approved work as cancelled would discard it outside this reconciliation path. It leaves the request
  `RUNNING` (and its lock held); `recover()` on the next start reconciles it (an intent was dispatched) or
  safely requeues it (nothing was ever sent), exactly as it does after a real process crash. Read-only
  operations are unaffected and still finalize as CANCELLED on shutdown (`worker.py::_run`).
- **Exception after dispatch.** An exception from a verification-stage provider call (`wait_for_rollout`,
  a post-patch `get_workload`/`list_pods`, `HelmRunner.status`, ...) must not escape to a bare FAILED with
  no receipt. `_run`'s generic exception handler checks for a dispatched intent (`executors.base.
  dispatched_intents`) and, when one exists, reconciles through the same `reconcile_request` path
  `recover()` uses instead of failing outright; this is the one canonical reconciliation path, not a
  second copy inside each executor. The dispatch call itself (`patch_workload`, `helm upgrade/rollback`)
  keeps its own narrower except block, because only it can record the intent's completion detail
  (`complete_intent` status `uncertain`/`accepted`/`failed`) at the moment of the call.
- **Transport error with no confirmation.** `Executor.reconcile(..., uncertain_if_absent=True)` is passed
  by that dispatch-call except block: a transport error carries no proof of what the provider did, so if
  the post-error re-read still shows the mutation absent, that stays `outcome_unknown`, not a confirmed
  `failed` -- only a re-read that positively shows the mutation applied may report succeeded/partial.
- **private_error is scrubbed.** The traceback stored in `private_error` and the line logged for it are
  both passed through `Sanitizer.scrub_text` (`worker.py::_sanitized_traceback`), not `repr(e)` directly.

### D7. Atomic finalization
Candidate storage, release (when no response review is required) and the terminal execution status are
written in one transaction (`Database.finalize_request`) so an observer never sees a terminal status without
its disclosure state. Discovered by a race in the test suite.

### D8. `review_responses` is invalid for execution
Enforced at write time (`AuthService.set_mode`) and at read time (`_valid_for` falls back to
`review_both`).

### D9. Schedules approve a read template only
A schedule is explicit approval of its bounded read template: runs enter the queue without request review and
release to the schedule's audience. Mutation operations and the execution capability are refused for
schedules (`worker._run_schedules`).

### D10. Catalog gaps only disclose released scans
`catalog_gaps` lists recent scans only when their response was released to the requesting principal
(found by the Phase 0 delegated exploration).

### D11. Demo catalog uses the provider id as the approved local-cluster identity reference
Bindings reference `cluster_identity: kube-demo`; the provider's `cluster_identity_file`
(`local-state/demo-cluster.json`, written by `scripts/demo-cluster.sh`) holds the kube-system UID that is
compared live before any mutation. For EKS, record the cluster ARN and the same UID in `cluster_identity`.

### D12. GitHub Actions executor is a typed interface, not a dispatcher
It refuses with `unsupported_deployment_mechanism` until a service supplies a fixed workflow contract
(repository, workflow file, ref, fixed input mapping) and a github provider has an `execution_credential`.
No bundled service has such a contract.

### D13. Python 3.12 minimum, developed on 3.14
`requires-python >= 3.12`; `uv.lock` is checked in; the suite runs on the system 3.14 and on a uv-managed
3.12 (see `docs/build-report.md`).

### D14. Credential hash
API keys are 32 random bytes; the stored verifier is SHA-256 (sufficient for high-entropy secrets). Reviewer
passwords use Argon2id.

### D16. Separate read connection
All coroutines shared one aiosqlite connection, so a status read issued mid-transaction saw uncommitted
writes (observed in the kind suite as `execution_status=running` with `response_status=released`). Reads now
use a second, `query_only` connection; under WAL they see only committed state. Writes keep the single
serialized writer.

### D17. A path redaction releases only the projection
Path redactions cannot be applied to stored evidence, observations, audit events, findings or plans, so a
release with any redacted path grants none of those rows; the projection's evidence list is emptied and
flagged. Excluding an evidence id also excludes observations, audit events and findings derived from it.
(Independent review blocker B1.)

### D18. Mandatory scrubbing of every persisted derived row
Observations, normalized audit events and finding bodies pass through the sanitizer before storage, not
only the reviewer's candidate. (Review blocker B2.)

### D19. Artifact references are validated at the boundary
`desired_artifact` must be `repository[:tag][@sha256:<64 hex>]` (or a Helm revision number); digests must be
64 lowercase hex; commas, `=`, whitespace and braces are rejected before any executor sees the value, and the
Helm executor re-checks the resolved reference before building `--set-string`. (Review blocker B3.)

### D20. Health checks settle before failing
HTTP checks retry for up to 45 seconds after rollout convergence, because Service endpoints lag the
controller; the receipt records the attempt count. A check that never passes in the window fails.

### D21. Controller-owned workloads are not patched directly
A workload with ownerReferences (an operator) is refused with `unsupported_deployment_mechanism`, like
Argo/Flux-managed workloads.

### D22. Health checks are data, not application code
The server knows two built-in controller checks (`ready_replicas`, `helm_release_deployed`) and two
declarable kinds: `http_status` and `http_json` (a dotted `json_field` that must equal a value, equal the
deployed artifact's version label, and/or increase between two reads). Earlier builds hard-coded an
application-specific `rpc_ledger_progress` check, demo-named check kinds and an `rpc_progress` recipe; those
are removed. Chain identity, ledger progress or any other application signal is now expressed in the
service file, and the `health_checks` investigation recipe runs whatever a service declares.

### D23. A scope key names a fully-enumerated, comparable scope; completeness is never borrowed

`discovery_scan` marks a resource missing by comparing everything previously observed under a
`scope_key` against what was seen in the current scan (`operations/discovery.run_scan`, via
`Database.mark_missing`). That comparison is only sound if `completed_scopes` names exactly the set of
resources that a scan *could* enumerate, fully:

- **Identity first.** A scope key must include every identity component needed to tell two comparable
  universes apart: provider id, verified account (AWS) or verified cluster identity (`kube_system_uid`,
  Kubernetes), region/namespace/global, resource family, and any filter that narrows the listing. Old
  pre-identity keys (e.g. `{provider}/{region}/{family}`, `{provider}/{namespace}`) are not reused; rows
  stored under them are simply outside comparable scope for future scans, which is acceptable because
  there is no production data yet. If a scan cannot verify identity (no `expected_account_id` configured
  for AWS, no `cluster_identity`/`cluster_identity_file` approved for Kubernetes), it completes no scope at
  all for that provider, even if every call it made succeeded.
- **A filter makes a scope incomparable, not smaller.** A scan narrowed by a cross-provider filter field
  (e.g. `DiscoveryScope.repositories`, shared between GitHub `owner/repo` and AWS ECR repository names) is
  a strict subset of the account/region's full inventory. It must never be marked complete under the same
  key an unfiltered scan would use — AWS ECR reports it partial outright rather than inventing a
  filter-specific key, since the filter's shape cannot be trusted to identify the provider it was meant
  for.
- **Child scopes do not borrow parent completeness.** A child listing or enrichment whose provider call
  fails is partial even if its parent list completed. AWS census paging is exhaustive within the discovery
  budget: IAM access keys, Route53 records, and ECR images are not first-N samples. A child scope still
  remains distinct wherever it has its own absence semantics (for example IAM access keys and account
  summary).
- **Assistant-supplied scope narrows, never widens, configuration.** When a provider's configuration
  declares an allowed set (AWS `regions`, GitHub `repositories`/`org`, Kubernetes `namespaces`, 1Password
  `vaults`), a request's scope is intersected with it; anything requested outside the configured set is
  refused (reported as an unavailable/refused scope) rather than queried.

Enforced in `src/local_ops/providers/{aws,github,kubernetes,onepassword,local_import}.py` and exercised in
`tests/providers/`.

### D24. Assistants propose catalog knowledge; humans commit it
Cross-session and cross-assistant memory is the approved catalog, not assistant-side memory or observed
state: every assistant reads the same Git-versioned service files through `catalog_read`.
- `ServiceSpec.knowledge` holds `queries` (saved `evidence_query` templates) and `failure_signatures`
  (literal-substring matches with a meaning and first steps). It is application-neutral data. It never
  grants authority, and `saved_query_run` expands a template through one path
  (`operations.diagnosis.expand_saved_query`) into an ordinary `evidence_query` that passes the normal
  review gate. The caller chooses only the window and the reason.
- `catalog_propose` (discovery and diagnosis surfaces, `src/local_ops/proposals.py`) takes a bounded
  JSON-Patch-style change list for one service file or a new service. Only descriptive and knowledge fields
  (`PROPOSABLE_FIELDS`) and `add /bindings/-` of a binding with execution disabled and no verified state or identity claims (`cluster_identity`, `workload_uid`, `account_id`) may be proposed;
  identity, approval, disposition, operations, credential references, health checks and existing bindings
  stay human-edited. The proposed file must validate as a `ServiceSpec`, saved queries must fit the live
  query schema and name a configured provider, cited evidence/observation/finding ids must be released to
  the proposer, the rendered file must load back to exactly the validated spec, credential-shaped content is refused, and identical re-proposals return the existing proposal with its current status.
- Proposals live in the `proposals` table (`migrations/0002_proposals.sql`). A reviewer accepts or
  rejects one at `/proposals`. Accepting writes `state_dir/proposals/<id>.patch`; the server never writes
  the catalog (D-"three kinds of data"). A proposal is bound to the service file's hash, not the catalog
  revision (which also moves with git HEAD): it is `stale` once that file changes and `applied` once the
  file equals the proposal.
- Applying an accepted proposal changes the catalog revision, which invalidates approvals and plans bound
  to the previous revision like any other catalog edit.

### D15. Known thin areas (documented, not hidden)
- AWS census paging is exhaustive within the configured operation budget. CloudWatch Logs log groups and
  Secrets Manager list paging resume only at committed page boundaries using a private 24-hour checkpoint
  bound to configured principal, verified account identity, configuration, and scope; every other
  interrupted family restarts. A resumed suffix cannot establish absence. CloudTrail Lake and WAF Classic
  remain unsupported; Organizations enumeration is opt-in.
- Recurring collection runs only while the server is up; gaps are visible as missing runs.
- Automated credential scrubbing is a floor; the reviewer sees what was removed and can redact more.
