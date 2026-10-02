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
