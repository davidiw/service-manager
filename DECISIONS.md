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
   (`catalog/*/services/*.md`, `catalog.yaml`, `identities.yaml`). Loaded from a trusted path. The server
   writes to a catalog file only when a reviewer accepts an agent's proposal (D24) for that exact file,
   one file per commit, authored `local-ops <local-ops@localhost>`; nothing else ever writes here. Its
   hash is the *catalog revision* bound into approvals and plans.
2. **Observed state** — SQLite tables `observations`, `audit_events`, `findings`, `evidence`, `plans`,
   `receipts`. Every row carries `released_to`; nothing observed grants execution authority.
3. **Proposed changes / gaps** — computed at read time (`Catalog.gaps()`, `discovery.observed_gaps`) and
   from scans; exports are written only under the state directory.

Machine configuration (`server.yaml`) is human-edited. The only other server-written path is
`config/overlay.yaml` in the catalog repository, committed only when a reviewer accepts a provider-connection
proposal (D29). It can only add, never override, and it is not part of the catalog revision. Both kinds of
acceptance commit through the same one-path-per-commit helper (D24).

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

### D8. `review_responses` is invalid for execution (the `mutation` data class, D28)
Enforced at write time (`AuthService.set_mode`) and at read time (`_valid_for` falls back to
`review_both`).

### D9. Schedules approve a read template only
A schedule is explicit approval of its bounded read template: runs enter the queue without request review and
release to the schedule's audience. Mutation operations and the write capability are refused for
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
- `catalog_propose` (read surface, `src/local_ops/proposals.py`) takes a bounded
  JSON-Patch-style change list for one service file or a new service. Only descriptive and knowledge fields
  (`PROPOSABLE_FIELDS`) and `add /bindings/-` of a binding with execution disabled and no verified state or identity claims (`cluster_identity`, `workload_uid`, `account_id`) may be proposed;
  identity, approval, disposition, operations, credential references, health checks and existing bindings
  stay human-edited. The proposed file must validate as a `ServiceSpec`, saved queries must fit the live
  query schema and name a configured provider, cited evidence/observation/finding ids must be released to
  the proposer, the rendered file must load back to exactly the validated spec, credential-shaped content is refused, and identical re-proposals return the existing proposal with its current status.
- Proposals live in the `proposals` table (`migrations/0002_proposals.sql`). A reviewer accepts or
  rejects one at `/proposals`. Accepting re-checks the proposal is not stale (the target file's hash still
  equals the proposal's base), then writes the already-validated `proposed_text` to that one service file in
  the catalog repository and commits only that path (author `local-ops <local-ops@localhost>`, message
  naming the proposal and service), through the same one-path-per-commit helper the D29 overlay uses. The
  `.patch` file is still written alongside, as an audit artifact. Accept fails, with nothing written, if the
  file is stale, the catalog directory is not a Git repository, or the repository already has other staged
  changes (never touch paths the proposal does not own). A proposal is bound to the service file's hash, not
  the catalog revision (which also moves with git HEAD): it is `stale` once that file changes and `applied`
  once the file equals the proposal. Accepting a second open proposal for the same file after the first was
  applied therefore finds it `stale` by construction; the reviewer UI shows this.
- Applying an accepted proposal changes the catalog revision, which invalidates approvals and plans bound
  to the previous revision like any other catalog edit.

### D25. Bindings name resources exactly; relationships come only from provider identifiers
A binding may name observed resources by exact `resource_keys` or by a `selector` (resource types plus tags
that must all be present with exactly those values), scoped by its `provider_id` (one verified account) and
optional `region`. `discovery.deterministic_binding_match` is the one exact matcher, used both when a scan
stores its match and when a view resolves bindings over released observations; the older inferred
heuristics (pod-name prefix, cluster-name tag/prefix) remain scan-time candidates labelled `inferred` and are
never shown as a service's resources. Relationships between observations are emitted by adapters from
identifiers the provider returned (ARNs, resource ids, `DescribeTargetHealth` targets, Lambda
`LoggingConfig.LogGroup`, the AWS-fixed `/aws/eks/<cluster>/cluster` log group) and resolved at read time
by exact key or id within the source account, alias DNS name (trailing dot and `dualstack.` normalized),
CloudWatch dimension value, or an A-record value equal to an observed instance IP (private addresses only
within one account). Grouping resources into logical services is never done in Python: an assistant reads
released observations (`observations_query`), forms hypotheses, and proposes bindings with
`catalog_propose`; every proposed `resource_key` must be an observation of that provider already released to
the proposer. No application or estate names (environments, services) exist in code.

### D26. Operational views read released observations only
`/ops` (environments → services → resources), `/ops/services/<id>`, `/ops/resource`, `/ops/inventory` and
`/ops/access` are reviewer-session pages over approved catalog data plus observations whose `released_to` is
non-empty (`Database.released_observations`); the MCP tools `observations_query` and `access_report` use the
same projection restricted to rows released to the calling principal. Pending and withheld rows are never
shown, evidence is linked only when its own `released_to` is non-empty, and no raw provider payload is
rendered by default. The views call no provider and change no state; operations are displayed without
controls. Freshness (`current` < 24 h, `stale`, `missing`) and the scope's status in the latest released scan
(`complete`, `partial`, `unavailable`, `partial_or_not_attempted`, `never_scanned`) are shown per resource,
so a stale observation never reads as live. The pre-existing `/catalog/<id>` page is unchanged.

### D27. The AWS access guide is derived from the observed access graph and its coverage
`access.AccessGraph` joins released Identity Center (instances, permission sets, account assignments,
identity-store users/groups/memberships, external-ID issuers only) and IAM (users, access-key metadata,
groups, policy *references*, roles with `role_class` and parsed trust principals, instance profiles)
observations. A person is found only by exact, case-insensitive user name, display name, user id or IAM user
name (plus catalog identity aliases). Effective access distinguishes direct and group-derived assignments;
IAM users, access keys, service roles and instance profiles are reported separately and never counted as a
person's Identity Center access. Identity Center coverage is `complete` only when an instance was observed
and every child listing (permission sets, assignments, users, groups, memberships) completed in the latest
released scan; otherwise the guide says so prominently and the offboarding checklist states that it cannot
establish removal. An empty `ListInstances` means only that no instance is administered from that
account/region. Policy documents are never fetched.

### D28. Two capabilities (read, write); review is per data class
The build specification's three capabilities (discovery, diagnosis, execution) split *reads* by surface,
which put related tools on different servers and doubled approvals. What actually distinguishes discovery
from diagnosis is the sensitivity of what comes back, so that is what review is keyed by now:
- Capabilities (`models.Capability`): `read` (one MCP server, `/mcp/read`) and `write` (`/mcp/write`,
  today's execution operations). A credential holds one or both; grants are explicit.
- Data classes (`models.DataClass`), each owned by one capability: `inventory` (discovery_scan) and
  `content` (evidence_query, service_inspect, investigation_run, saved_query_run) under read; `mutation`
  (action_prepare, action_submit) under write. Every `OperationSpec` declares its data class.
- Review settings and overrides are per client and data class (`AuthService.effective_mode`).
  `review_responses` stays invalid for mutations (D8). A setting or principal-specific override may only be
  created for a data class of a granted capability, and a principal-specific override must name one.
- Migration `0004_read_write_capabilities.sql` regrants existing credentials in place (discovery/diagnosis
  -> read, execution -> write; keys keep working) and moves each review setting to the data class
  its old capability governed, so no operation gets a laxer mode than before. It first deletes review state
  that never had effect: settings and principal-specific overrides for a capability the principal did not
  hold (the pre-D28 settings page allowed storing them). All temporary YOLO overrides are cleared, global
  ones included, because any of them could cover a data class a credential gains by the merge; overrides last
  at most `yolo_override_max_minutes`, and the reviewer re-creates any still wanted. A former discovery-only key can
  now *request* content queries, but content still uses that client's content review mode (default
  `review_both`), so nothing new is disclosed without the reviewer.
- There is no compatibility mount for `/mcp/discovery` or `/mcp/diagnosis`; clients point at `/mcp/read`.

### D29. Assistants propose provider connections; the server verifies, a human approves, the server applies
Connecting a new Kubernetes cluster used to need a human to hand-edit `server.yaml` (provider, credential,
`cluster_identity`), even though every value came from data the server had already observed. The edits were
toil and error-prone (a pasted block broke YAML parsing). D24's rule that identity claims are never proposable
stays for *catalog* bindings; this decision adds a separate, narrower path for *machine configuration*.
- **Proposal kinds** (`config_propose`, read surface; the same core path backs the review UI):
  1. `kubernetes_connection`: add one `kubernetes` provider and its `kubeconfig_context` credential
     (`purpose: read`, `namespaces: []`). The assistant names the provider id, kubeconfig path and context.
  2. `cluster_pin`: set `cluster_identity` on an existing `kubernetes` provider that has none.
  Nothing else is proposable: no AWS/1Password/GitHub providers, no `execute`/`write` credentials, no changes
  to existing entries, no secrets (credential *references* only).
- **The server builds identity claims; the assistant never supplies them.** For `cluster_pin` the assistant
  names the provider and a released `aws/eks_cluster` observation. The server reads the live identity through
  the provider's own context and accepts only if two independent sources agree: the live API server URL
  equals that observation's `endpoint`, and the observation came from a configured AWS provider whose account
  was verified (`expected_account_id`). The recorded pin is
  `{kube_system_uid: <live>, eks_arn: <observation arn>}`. The check is repeated when the reviewer accepts;
  if it no longer holds, accept fails and the proposal becomes `stale`.
- **`allow_exec_plugins` is proposable only in its read-only shape, enforced twice.** One canonical
  validator (`providers/exec_policy.py`) allows the exec command only if it is exactly `aws` with
  arguments `eks get-token` (plus `--cluster-name/--region/--output/--profile` options; never
  `--role-arn`), `env` contains at most `AWS_PROFILE`, and the effective profile (`--profile` or
  `AWS_PROFILE`) equals the `profile` of a configured `aws_sso` credential with `purpose: read`. A
  proposal is validated at propose time *and* re-validated unchanged at accept time (the merged config or
  the kubeconfig on disk may have drifted). The same validator runs again on every live connect
  (`kube_client.RealKubeClient._ensure`, for every kubernetes provider with `allow_exec_plugins: true`,
  not only ones a proposal added) because a proposal is only a point-in-time check: a kubeconfig swapped
  on disk after acceptance must still fail closed, not inherit trust from the file it replaced. Anything
  else is refused; a human can still enable other helpers by editing `server.yaml` (that path is not
  re-validated at runtime, by design: a human editing `server.yaml` is already the trusted path).
- **A proposed kubeconfig must resolve under `~/.kube/`.** Expanded, symlinks resolved, and the result
  checked to be a regular file owned by the server's own uid, not group/world-writable. This is
  independent of the exec-plugin check above (which is what makes a *swapped* file safe to run); it
  exists so a proposal cannot point the server at an arbitrary host path. The resolved path, never the
  proposer's raw string, is what gets stored in the overlay and committed.
- **Application.** Accepting writes the change to `config/overlay.yaml` in the catalog Git repository, the one
  repository for approved configuration. The server commits only that path (author `local-ops`, message
  naming the proposal and reviewer), refuses if other changes are staged, and never touches service files.
  `load_server_config` merges the overlay after `server.yaml`. The catalog revision ignores `config/`: its
  content hash excludes it, and its git component is the last commit touching catalog paths, so a pin never
  invalidates approvals or plans bound to the catalog revision. The overlay may only
  *add* providers/credentials with new ids, or set `cluster_identity` on a Kubernetes provider that has
  neither `cluster_identity` nor `cluster_identity_file`. Any conflict with the base file fails config load
  loudly, so the human-edited file always wins. The merged config still passes the ordinary
  `ServerConfig` validation.
- **Hot reload.** After a successful apply, the server rebuilds the provider registry from the merged config
  and swaps the registry reference atomically. Operations already running keep the registry they started
  with. Adapters for unchanged providers are reused in place (including an already-open client), so their
  semaphores carry over too; the reused adapter's reference to the live `ServerConfig` is refreshed so a
  provider whose own configuration did not change still sees something else that did (e.g. a newly
  accepted `aws_sso` credential the exec-plugin allowlist depends on). A provider whose own configuration
  changed (a newly pinned `cluster_identity`, or a human edit to `server.yaml`) is rebuilt from scratch and
  so briefly gets a fresh semaphore, not the one in-flight callers on the old adapter were waiting on; the
  old adapter is not forcibly closed, only dropped from the registry, so an in-flight call on it finishes
  normally.
- Accept (`config_propose` and `catalog_propose`) is serialized per service (`asyncio.Lock`) so two
  concurrent accepts never race on the same `overlay.yaml`/service-file read-modify-write or interleave
  their Git commits.
- Config proposals use their own table (`config_proposals`, migration 0005) and the existing
  `/proposals` page, listed separately. Statuses are `pending_review`, `accepted` (applied), `rejected`, `stale`.
  There is no auto-accept; a review-mode setting for corroborated pins is a possible follow-up.
- Still human-only: AWS-side access (EKS access entries), widening authority (exec helpers other than the
  read-only `aws eks get-token`, non-read credentials, roles, regions, Organizations enumeration), and any edit
  to an existing entry.

### D30. Provenance is observed through providers and recorded as typed catalog fields
The first provenance pass (2026-10-03) needed a side-channel `gh` session to link running digests to commits,
build runs and IaC pins. That linkage is now a local-ops capability, with the usual separation: providers
observe, assistants correlate and propose, humans accept.
- **GitHub (content data class).** The adapter gains bounded reads of (a) a commit by SHA or prefix, (b)
  workflow runs for a head SHA, and (c) the contents of a small allowlist of IaC paths per repository:
  `configs/*.yaml|yml`, `backend.tf`, `*.tfvars` excluded, `.github/workflows/*.yml|yaml`, and
  `catalog/services/*.yaml`. Repository files can contain secrets (a committed password was found in the first
  pass), so file contents are `content`, not `inventory`. They go through that client's content review
  mode, are stored as evidence only after the sanitizer runs, and are never echoed raw by tools. Files over a
  size bound are refused. Paths outside the allowlist are refused, as are symlinks, submodules and
  binary content. Metadata discovery (repos, workflows, deployments) stays `inventory` as before.
- **Registry (content data class).** `resolve_digest` becomes an `evidence_query` type
  (`registry_manifest`). It returns the manifest/index digest, platform digests, and the image config's OCI
  labels `org.opencontainers.image.{source,revision,version,created}`. It never pulls layers.
- **Catalog schema.** `SourceRepository` gains optional typed fields: `commit` (full or prefix SHA), `artifact`
  (image repository), `tag`, `digest`, `build_workflow`, `iac_backend` (for example
  `terrakube:MovementInfra/network-tools_`), and `evidence_class` (`direct` | `strong` | `weak`). Only `direct`
  is allowed when the cited evidence includes an exact identifier match. `catalog_propose` enforces that a
  `direct` entry cites at least one released evidence or observation id.
- **Drift is a computed gap, never stored state.** When a service's binding resolves a running workload whose
  image tag or digest differs from a `SourceRepository.tag`/`digest` declared for that artifact, `Catalog.gaps()`
  reports `artifact_drift` with both values. A mutable running tag (`latest`, `main`, `master`, or one with no
  digest) reports `mutable_artifact`.
- No Terrakube adapter yet: it needs a read-only API token, and it must never read raw state, which holds
  secrets. Workspace and run metadata only.

### D15. Known thin areas (documented, not hidden)
- AWS census paging is exhaustive within the configured operation budget. CloudWatch Logs log groups and
  Secrets Manager list paging resume only at committed page boundaries using a private 24-hour checkpoint
  bound to configured principal, verified account identity, configuration, and scope; every other
  interrupted family restarts. A resumed suffix cannot establish absence. CloudTrail Lake and WAF Classic
  remain unsupported; Organizations enumeration is opt-in.
- Recurring collection runs only while the server is up; gaps are visible as missing runs.
- Automated credential scrubbing is a floor; the reviewer sees what was removed and can redact more.
