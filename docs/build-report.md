# Build report

## Headless human 1Password CLI addition

Source snapshot: `daa3cb28dcce3b227b7ecace54bdbba04bbf6fe5` on
`feat/onepassword-headless-cli`, [PR #2](https://github.com/davidiw/service-manager/pull/2).
The subsequent documentation-only commit records this evidence.

- Config: `onepassword_cli` requires an explicit `account`; the existing `onepassword` provider selects
  a CLI metadata backend. Empty vault scope means all visible vaults. SDK/service-account/desktop paths
  remain, while the human CLI cannot resolve item secrets.
- Installed contract inspected: `op 2.39.0`; `op --version`, `op --help`, and help for `account list`,
  `whoami`, `user get`, `vault list`, `item list`. Verified global `--account`, `--format json`,
  `--iso-timestamps`, `--cache=false`, plus item-list `--vault` and `--include-archive`.
  No sign-in command or real account enumeration was run.
- Backend command forms are exclusively `whoami`, `vault list`, and `item list --vault <id>
  --include-archive`, each preceded by `op --account <configured-account> --format json --iso-timestamps
  --cache=false`. No generic CLI surface, item get, read, inject, run, document get or signin.
- Process limits: 30 seconds, 16 MiB stdout, 64 KiB stderr; no stdin or controlling terminal. Session
  values are registered for redaction. Raw output/errors/environment are not persisted or returned.

Verification actually run on that source snapshot:

```text
uv sync --locked                                  -> passed
uv run ruff check src tests                        -> passed
uv run mypy                                        -> passed, 51 source files
uv run pytest -q -p no:cacheprovider tests/providers/test_onepassword*.py
                                                   -> 41 passed (including installed help-only contract)
uv run pytest -p no:cacheprovider --ignore=tests/integration
                                                   -> 388 passed, 2 existing warnings, about 162 seconds
python3 ~/src/skills/engineering-harness/plugins/engineering-harness/scripts/profile_repository.py . --check engineering-harness.json
                                                   -> profile current; 4 existing detector-evidence warnings
```

GitHub CI on Python 3.12 and 3.13 passed for the source snapshot. CLI help tests skip on hosts without
`op`; all authenticated account operations in tests use fakes. No real account or production credential
was accessed/modified, and no integration/cluster tests ran for this addition.

Independent review: fresh `op_cli_review` reviewer context, no builder-history fork, combined security
and privacy lenses; packet SHA256 `e9fe9557df675910026fc4a4237519d7247876f7ba2ca83cb9a1fe80a6b68e97`.
Reviewed all changed files and relevant credential/evidence paths; 41 focused tests passed, with additional
synthetic real-Python-subprocess checks for timeout, output overflow and cancellation cleanup. No blockers.
Nonblocking follow-up N1: child environment currently inherits the server environment after excluding
alternate 1Password authentication and disabling desktop/debug modes; a narrower runtime/session variable
allowlist could further reduce unrelated environment credentials passed to the trusted `op` executable.
Live CLI response schemas, account enforcement and session expiry remain unverified against a real account.
Spawn-time cancellation and descendant cleanup were source-reviewed, not independently fault-injected.
Human sessions may expire; re-establish authentication outside the server and restart it when refreshed
session environment must be inherited. Missing overview fields remain unknown; field values are never
retrieved. See README/access guide for the first real scan workflow.

## First live scans: open defects

Date: 2026-10-02, branch `feat/onepassword-headless-cli` at `9a30696`. Operator-approved, read-only discovery
against the real estate: one 1Password human-CLI scan (`req_1ec935b02e07971f`, 5 vaults, 27 items, all
scopes complete) and AWS scans of the full 11-account organization through IAM Identity Center profiles
with a ViewOnlyAccess + SecurityAudit permission set (`req_dc732595e159c311`, `req_1a0f912b066c66b7`,
`req_18c515b9eaf81e6c`, `req_559c8bf8ae169477`; the last: 690/718 scopes complete, Organizations
denominator complete). This is the first live verification of the headless 1Password CLI path and of AWS
SSO/STS identity checks. The scans surfaced the defects below, which fixture tests did not catch.

Status (2026-10-02, uncommitted working tree): all ten have fixes with regression tests and pass the full
unit/contract/browser suite (453 passed). L1/L2: `tests/test_release_live_scan_regressions.py`; L3/L4:
`providers/aws_billing.py`, `tests/providers/test_aws_billing.py`, `tests/test_result_limits.py`; L5:
`tests/test_result_limits.py`; L6/L7: `tests/providers/test_aws.py` (clock-skew classification, SSO fast
fail); L8: `tests/test_scan_result_identity.py`, `tests/providers/test_aws_coverage.py`; L9:
`tests/test_review_modes.py::test_settings_cannot_preset_ungranted_capability_or_override`; L10:
`expected_role` in `ProviderConfig` with tests in `tests/providers/test_aws.py`. None is live-verified yet.

| # | Defect | Where | Done when |
| --- | --- | --- | --- |
| L1 | **Data loss.** Secrets Manager ARNs (`...:secret:<name>`) match the `password_assignment` pattern, so `resource_key` becomes `secret=[REDACTED:password_assignment]` and distinct secrets collide: about 64 secrets collapsed into 9 observation ids in one account. Secret *names* are metadata, not values. | `src/local_ops/release.py:39` (pattern), observation identity in `providers/aws.py` | Distinct secrets keep distinct, readable ARNs/keys; values still never retrieved; test with several `arn:aws:secretsmanager:...:secret:<name>-XXXXXX` ARNs |
| L2 | Field-name heuristic redacts whole containers whose key merely contains a keyword: `summary.identities["onepassword-main"]`, `enumeration_scope.secretsmanager` and every `aws_coverage.authorization_failures` entry came back as `[REDACTED:field:...]`, hiding the denial details operators need. | `src/local_ops/release.py:115-140`, `_CONTAINER_SECRET_KEYWORDS` (`release.py:87`) | Provider ids, family names and authorization-failure records are readable; real secret-named fields still redacted |
| L3 | Billing cost is reported twice per member account: by the member's own provider and by the management account's linked-account view (same `resource_key`, different observations). Summing items doubles spend. | `src/local_ops/providers/aws.py:1057`, `providers/aws_coverage.py:397` | One cost observation per (linked account, service, period), with provenance listing every source |
| L4 | Paged `items` total exceeds unique observations (1969 vs 1914), a consequence of L1. | result pagination over observations | `page.total` equals unique observations |
| L5 | `request_result` with `limit` > 500 raises `UnexpectedToolError` (pydantic `ValidationError` on `Page`) instead of a typed `INVALID_ARGUMENT`. | `src/local_ops/mcp_surfaces.py:64`, `models.py:376` | Typed error naming the 500 maximum, or clamp; MCP-level test |
| L6 | Local clock about 5 min slow produced about 250 `auth_required` "re-authenticate" failures (`Signature expired`, `SignatureDoesNotMatch`). | `src/local_ops/providers/aws.py:70-92` (`classify_boto_error`) | Signature-expiry errors classify as clock skew with one actionable message; optional preflight comparing the AWS `Date` header |
| L7 | A missing SSO token (`SSOTokenLoadError`, permanent until the operator logs in) was retried for about 8 min and logged a full traceback per attempt. | AWS credential refresh / identity path, `providers/aws.py:301-330` | Fail the provider fast as `auth_required` naming the sso-session; one log line |
| L8 | Coverage denominators wrong: `clusters_requested` counts non-Kubernetes providers; `aws_coverage` emitted on 1Password-only scans; `regions_completed` 0 despite completed regional scopes; every account's us-east-1 `regions` scope `not_attempted`. | `src/local_ops/discovery.py:104`, `operations/discovery.py:83` | Denominators only count relevant providers/regions; test on mixed and single-provider scans |
| L9 | **Authorization.** Settings lists every client x capability and `set_mode` accepts modes (including `yolo`) for capabilities the client is not granted; they lie dormant and apply silently if the grant is added later. | `src/local_ops/web/routes.py:427-449`, `auth.py:175` | Ungranted rows hidden/disabled; `set_mode` rejects ungranted capabilities; route test |
| L10 | **Authorization.** AWS identity verification checks the STS account against `expected_account_id` but not the role; a profile pointed at an administrator role is accepted. | `src/local_ops/providers/aws.py:301-310`, `ProviderConfig` | Optional `expected_role` (name or pattern) checked against the assumed-role ARN; mismatch refuses like `account_mismatch` |

Live operating notes from these runs: IAM Identity Center profiles must name the `sso-session` the operator
actually logged in with (the CLI caches tokens by session-name hash); the org's existing `ReadOnlyAccess`
permission set lacked several describe/list actions the census uses, so a dedicated ViewOnlyAccess +
SecurityAudit set with an inline `ce:GetCostAndUsage` / `organizations:List*` statement was used; host
time sync must be active (`timedatectl set-ntp true`).

## Operational map and AWS access graph (milestone, uncommitted)

Date: 2026-10-02, on `feat/onepassword-headless-cli` at `9a30696` plus the working tree. Adds (DECISIONS D25-D27):
the Identity Center census (`providers/aws_identity.py`: sso-admin ListInstances/ListPermissionSets/
DescribePermissionSet/ListManagedPoliciesInPermissionSet/ListCustomerManagedPolicyReferencesInPermissionSet/
ListAccountsForProvisionedPermissionSet/ListAccountAssignments; identitystore ListUsers/ListGroups/
ListGroupMemberships), IAM groups, policy references and instance profiles (ListGroups/GetGroup/
ListAttached{User,Group,Role}Policies/List{User,Group,Role}Policies/ListInstanceProfiles), ELB
DescribeTargetHealth, deterministic relationships (EC2 to subnet/VPC/SG/volume/instance profile, ASG contains,
target group routes_to, Lambda and EKS logs_to), exact binding `resource_keys`/`selector`, the read-only `/ops`
views, `/ops/access` with the generated guide, and the `observations_query`/`access_report` MCP tools.
Fixture-only: none of this is live-verified until a released scan exercises it.

Independent review: fresh `reviewer` context, no builder history, disclosure/authorization scope. No blockers.
Fixed from its findings: a structural-map entry named exactly like a secret field is redacted wholesale again;
a principal-specific YOLO override must name one granted capability. Accepted and documented: a Secrets
Manager ARN keeps whatever name the secret has (a secret named after its own value would show that name);
a proposed tag `selector` is not checked against released observations (it grants nothing, resolves only
over the viewer's released rows, and is human-reviewed); `missing_since` can be set by a complete scan before
that scan is released (pre-existing; one bit of absence information); the estate-wide unreleased-row count
is shown only on reviewer pages. Not reviewed: the integration suite.

## Read/write capabilities (D28) and audit tooling (uncommitted)

Capabilities are now read/write with review per data class (inventory, content, mutation); migration 0004
regrants existing keys in place. Audit tooling: container_logs honours max_events; CloudTrail limits apply
per region and capped regions state the covered window; identity_and_deployment_audit queries EKS audit per
released audited cluster, scales max_pages to max_events, and reports `window_fully_covered`.

Independent review (fresh `reviewer`, authorization/disclosure scope): first pass BLOCKED on (B1) migration
turning dormant pre-D28 settings for ungranted capabilities into active, laxer content/inventory review and
(B2) a default CloudTrail ReadOnly=false filter that would blind departed-identity and STS rules while still
reporting full coverage. Both fixed with regression tests; delta review: not blocking, one further widening
via global temporary overrides, fixed by clearing all overrides in 0004. Verification: ruff, mypy, 466 unit/
contract/browser tests passed (before the final override-clearing edit, whose migration test passes). The
kind integration suite was not run. Not live-verified.

## First live service checks and follow-up fixes

Date: 2026-10-02, commits `c6d7c55`, `af2238c`, `0db120b`, `2db7bba` on `feat/onepassword-headless-cli`.
Live-verified against the real estate through the Claude `local-ops-read` connection to `/mcp/read`:
`capabilities_get` (read granted, per-data-class review modes), `observations_query`, `catalog_proposals`,
`catalog_propose`, a `cloudwatch_metrics` evidence query (`req_61ca53ed57f839f4`), `container_logs`
(`req_1815d8b4101ba11a`) and `service_inspect` on four catalog services whose bindings name workloads by
resource key (`req_dcac94afddbe352d`, `req_796764de5cdf1f6d`, `req_74b48918b7f4af7f`, `req_c33cdf3ea9c9d9d6`;
all 23 Deployments/StatefulSets resolved, logs read on every pod, including the validator clusters).

Defects found live and fixed, each with regression tests: malformed `evidence_query` scopes failed only after
queueing, with the error held behind response review (now rejected at submission, scope shape documented in the
tool description); `service_inspect` skipped resource-key bindings as documentary; crash-loop detection used
lifetime restart counts; hypotheses did not name their workload; inspect results carried the runtime detail
twice; resource-key bindings reported a `documentary_binding` gap; new-service patches were not canonical.
Review UI: proposals stack per service with an open-only filter and inline decisions, a pending-decision banner
and nav counts poll `/api/ui/queue`, list and detail pages reload on state change (never while a field is being
edited), and form posts replace the history entry. Verification: ruff, mypy, 479 unit/contract/browser tests.
The kind integration suite was not run (its `runtime` assertions were updated to `items` but not executed).

## Earlier AWS census and original build evidence

Date: 2026-10-01. AWS census source snapshot: `739593a0b24eb1d77b8fcabe7392034b6d4bec4f`.
Current census checks use Python 3.14.7; older cross-version and kind results below are historical. MCP SDK 2.2.0.

## Implemented adapters and operations

| Area | Implemented | Fixture/contract tested | Live tested |
| --- | --- | --- | --- |
| Discovery: AWS census (sts, regions, eks, ec2 instances/volumes/VPCs/subnets/security groups/NAT gateways, elb, rds instances/clusters, ecr, s3, backup, route53, acm, lambda, ecs, events, autoscaling, iam, Secrets Manager, KMS, CloudWatch log groups/alarms, DynamoDB, ElastiCache, EFS, OpenSearch, SQS, SNS, API Gateway, CloudFront, WAFv2, Step Functions, CloudFormation, organizations opt-in, billing) | yes (`providers/aws.py`, `aws_data.py`, `aws_edge.py`, `aws_coverage.py`) | yes: 97 focused AWS/checkpoint tests; full suite 362 passed | **no** (no real AWS calls were run) |
| Diagnosis/audit: CloudTrail LookupEvents, CloudWatch Logs (FilterLogEvents + Insights jobs), CloudWatch metrics, GuardDuty findings, EKS audit via CloudWatch, EKS log coverage | yes | yes | **no** |
| Kubernetes discovery, events, container logs, workload inspection | yes (`providers/kubernetes.py` over `KubeClient`) | yes (FakeKubeClient) | **yes** against the disposable kind cluster |
| OCI registry tag→digest + version label | yes (`providers/registry.py`) | fake in unit tests | **yes** (local registry beside kind) |
| 1Password metadata + credential resolution (async SDK) | yes | yes, 14 tests with a fake SDK client | **no** (no service account) |
| 1Password Events API (introspect, cursor pagination) | yes | yes | **no** |
| GitHub repos/workflows/deployments, audit log, workflow runs, explicit file reads | yes | yes, 22 tests (httpx MockTransport) | **no** (a `gh` login exists on this machine but no token was wired into the server) |
| Grafana datasources/dashboards/alert rules, Loki and Prometheus queries (proxied and direct) | yes | yes, 9 tests | **no** |
| PagerDuty services/schedules/escalation policies/incidents (read-only) | yes | yes, 6 tests | **no** |
| Local import (billing, registrar, identities, services, dns, events, notes) | yes | yes, 6 tests | n/a (local files) |
| Demo fixture provider (CloudTrail/k8s-audit/GitHub/GuardDuty/logs, benign and suspicious scenarios) | yes | yes | n/a (labeled fixture) |
| Executors: native Kubernetes restart/image update/rollback; Helm upgrade/rollback/restart; GitHub Actions typed interface (refuses without contract) | yes | yes (fake cluster; helm runner factory) | **yes**: kind + helm 4.3 for native and Helm paths; GitHub Actions dispatch not live |
| Review site (queue, request, response, catalog, service, investigation, history, settings, evidence) | yes | 13 Playwright tests + httpx route tests | n/a |
| Recurring audit schedules, retention pruning, stop switch, YOLO overrides, key rotation/revocation | yes | partially (schedules: unit-level only through worker code paths; retention prune: storage test coverage is indirect) | n/a |

## AWS census verification

Run against source `739593a0b24eb1d77b8fcabe7392034b6d4bec4f`, followed only by this report update:

```text
uv sync --locked                                  -> passed (94 packages resolved, 91 checked)
uv run ruff check src tests                        -> passed
uv run mypy                                        -> passed, 50 source files
uv run pytest -p no:cacheprovider --ignore=tests/integration
                                                   -> 362 passed, 2 warnings, 160.29s
uv run pytest -q -p no:cacheprovider tests/providers/test_aws*.py tests/test_discovery_checkpoints.py
                                                   -> 97 passed, 6.21s
python3 ~/src/skills/engineering-harness/plugins/engineering-harness/scripts/profile_repository.py . --check engineering-harness.json
                                                   -> profile current, policy 0.10.0
```

The full suite includes 13 browser tests. The two warnings are an existing asyncio mark on a synchronous
health-check test and an httpx cookie deprecation. The harness check reports four existing detector-evidence
warnings (ai_mediated_actions, generated_artifacts, mutable_authority_context, multiple_adapters).
No live AWS calls or integration/cluster tests were run for the census change.

## Historical verification before the AWS census change

These earlier results do not establish current live-provider verification.

```
uv run ruff check src tests                      -> All checks passed
uv run mypy                                      -> Success: no issues found in 46 source files
uv run pytest -q -p no:cacheprovider --ignore=tests/integration
                                                 -> 222 passed (Python 3.14.7)  [includes 13 Playwright browser tests, 9 review-regression tests, 6 generic health-check tests]
UV_PROJECT_ENVIRONMENT=.venv312 uv run --python 3.12 pytest -q -p no:cacheprovider --ignore=tests/integration
                                                 -> 194 + 13 browser passed (Python 3.12.14; run before the review fixes, not rerun after)
LOCAL_OPS_INTEGRATION=1 uv run pytest tests/integration -q -p no:cacheprovider -m integration
                                                 -> 11 passed, three consecutive runs (~170s each) against kind-local-ops-demo
python3 .../profile_repository.py . --check engineering-harness.json   -> profile current for harness policy 0.10.0
python3 .../validate_profile.py engineering-harness.json              -> valid
uv run local-ops init/doctor/keys/catalog (scratch dir)               -> exercised; see "CLI smoke" below
```

Spec section 17 rows and where they are proven: Capabilities (`tests/test_transport.py`, `tests/test_execution.py::test_unauthorized_targets_and_escalation`, `tests/test_recovery.py::test_revocation_*`); Transport (`tests/test_transport.py`); Reviews (`tests/test_review_modes.py`); Disclosure (`tests/test_disclosure.py`, browser tests); Secrets/UI (`tests/test_disclosure.py`, `tests/providers/*` scrubbing assertions, browser escaping test); Async (`tests/test_async_bounds.py`); Discovery (`tests/providers/test_aws.py` multi-region/permission-denied/pagination; `tests/test_catalog.py` orphan/ambiguous/shared workload); Read-only (`tests/providers/test_pagerduty.py` GET-only, `tests/providers/test_grafana.py` secrets absent, kube client has no Secret/exec surface); Audit (`tests/test_audit_pipeline.py`); Findings (`tests/test_audit_rules.py`); Execution (`tests/test_execution.py`, `tests/integration/test_kind_execution.py`); Recovery (`tests/test_recovery.py`, kind reconcile); Catalog (`tests/test_catalog.py`); Demo (`tests/integration/*`, `scripts/demo-e2e.sh`).

Not run / not claimed: live AWS, 1Password, GitHub, Grafana/Loki/Prometheus and PagerDuty calls; SSO-expiry-mid-operation against a real SSO session (only the classification of botocore SSO errors is tested); GitHub Actions workflow dispatch.

## CLI smoke (scratch directory)

`local-ops init` wrote a non-secret `server.yaml`, a 0700 state dir, three capability keys into a 0600 `keys.env`
and a reviewer login without printing secrets. `doctor` reported package versions, binaries, config validity,
catalog validity and per-provider availability (local checks only unless `--live`). `keys create/list/revoke`
and CLI smoke checks were exercised against scratch state.

## Known limitations

- AWS discovery is an estate census only within configured accounts and regions. It does not claim every
  enabled AWS region was scanned. Organizations enumeration is opt-in; without a complete Organizations
  list the account denominator is unknown.
- A completed comparable family scope can support an empty-inventory conclusion. `partial_resumable`,
  `partial_restart`, `unavailable`, and resumed-suffix scopes cannot; they never mark prior observations
  missing. Only Secrets Manager and CloudWatch Logs log-group pagination resume at committed page
  boundaries, using private 24-hour checkpoints. Other interrupted families restart.
- CloudTrail Lake, WAF Classic, OpenSearch Serverless and ElastiCache Serverless have no enumerator. Edge/data sub-products not represented by the named
  family APIs may appear in billing coverage as unsupported rather than as absent resources.
- Recurring collection only runs while the server is up; gaps show as missing runs.
- Credential scrubbing is a floor; the reviewer sees what was removed and can redact more.
- `review_both` means three human stops for an update (prepare request, prepare response, submit request).
- Custom Claude agent files are only loaded at session start.
- The demo app does not handle SIGTERM quickly, so old pods take up to 30s to terminate after a rollout; the
  rollout watcher ignores terminating pods.

## AWS census independent review

A fresh reviewer examined the enumeration, metadata projections, private checkpoint persistence and
coverage composition. Three blockers were fixed: raw ECS task-definition evidence could retain payload
fields; filtered Backup scans could complete a broader scope; billing completeness could overlook a
resumed or omitted regional scope. Regression tests exercise each failure. Subsequent delta reviews
cleared supplemental scope composition, rejected-cursor redaction/restart behavior and S3 regional
comparison scopes. Final reviewed source: `6263cc6cceb2858f9aad54c6b2e6a5c802c4bc9f`; no blockers remain.

User review subsequently identified four gaps missed by the initial review: EventBridge's missing
botocore paginator, deleted CloudFormation history entering current inventory, the CloudFormation IAM
permission mismatch, and a misleading complete status on finished resumed suffixes. These were fixed
in `6263cc6cceb2858f9aad54c6b2e6a5c802c4bc9f`. A service-specific installed-model pagination contract
and stricter shared fake now catch unsupported paginator calls. Deleted stacks/resources and resumed
status have explicit regressions. Independent delta review passed with 56 relevant tests and no blockers.

A further billing correction in `47ad64b6b57ed660fcf7e007effdf2ae26818840` retains all visible
linked-account/service cost rows and exposes the collecting billing source account. A multipage regression
keeps payer/member spend separate and proves an Organizations-known member remains not configured and
incomplete despite visible spend. Independent delta review passed with 47 relevant tests and no findings.
Real Cost Explorer responses and cross-payer account transfers were not exercised.

Billing-only accounts join the first-class account coverage map in
`739593a0b24eb1d77b8fcabe7392034b6d4bec4f`, with explicit billing evidence. They do not establish
organization completeness or successful resource-discovery reach. The adapter regression exercises
Organizations enabled and disabled; independent delta review passed with 48 relevant tests and no findings.

Actual task cancellation during paging, budget expiry, throttling and rejected tokens are fixture-tested.
Live credential rotation, hard process termination and worker-level cancellation/release races were not
exercised. Optional retention of more safe ECS metadata remains a non-blocking follow-up.

## Historical independent review

A fresh-context, read-only reviewer (no builder history; security-assurance skill loaded) reviewed spec
sections 5, 6, 7, 8, 12 and 17. A first launch failed on a rate limit before reporting and was relaunched.

| Finding | Severity | Disposition |
| --- | --- | --- |
| B1 redacted fields still readable via evidence_get / findings_read / catalog reads | high | fixed (D17); `tests/test_review_fixes.py` |
| B2 observations, audit events and findings stored unscrubbed | high | fixed (D18); regression test reads secret-shaped annotations back through catalog_read/export |
| B3 caller artifact string could inject Helm `--set-string` values | high | fixed (D19); boundary and MCP-level tests |
| Stop-switch / lock-waiting mutations could starve diagnosis | medium | fixed: blocked rows are claimed last |
| Native executor patched controller-owned workloads | medium | fixed (D21); test |
| Mutation budget can cut off verification; re-enabling an expired schedule; unbounded export writes; audience members can cancel; login without CSRF token/throttle | low/low-medium | open follow-ups |
| No reviewer-UI route to execute a preview directly (§12); no StatefulSet enrollment flag; Helm values fingerprint not bound | spec gaps | open follow-ups |

Found during the post-review integration runs: shared-connection dirty reads (fixed, D16) and post-rollout
endpoint lag in health checks (fixed, D20).
