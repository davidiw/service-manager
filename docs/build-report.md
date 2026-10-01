# Build report

Date: 2026-10-01. Snapshot: working tree of `~/src/service-management` (no commits were made; see "Run it").
Python 3.14.7 (system) and 3.12.14 (uv-managed) were both exercised. MCP SDK 2.2.0.

## Implemented adapters and operations

| Area | Implemented | Fixture/contract tested | Live tested |
| --- | --- | --- | --- |
| Discovery: AWS census (sts, regions, eks, ec2 instances/volumes, elb, rds, ecr, s3, backup, route53, acm, lambda, ecs, events, autoscaling, iam, Secrets Manager, KMS, CloudWatch log groups/alarms, DynamoDB, ElastiCache, EFS, OpenSearch, SQS, SNS, API Gateway, CloudFront, WAFv2, Step Functions, CloudFormation, organizations opt-in, billing) | yes (`providers/aws.py`, `aws_data.py`, `aws_edge.py`, `aws_coverage.py`) | pending coordinator verification of expanded fixture/contract suite | **no** (no real AWS calls were run) |
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

## Tests actually run (final state)

The expanded AWS census verification is pending the coordinator's final run. Do not treat the historical
commands and counts below as verification of the census change.

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
- CloudTrail Lake and WAF Classic have no enumerator. Edge/data sub-products not represented by the named
  family APIs may appear in billing coverage as unsupported rather than as absent resources.
- Recurring collection only runs while the server is up; gaps show as missing runs.
- Credential scrubbing is a floor; the reviewer sees what was removed and can redact more.
- `review_both` means three human stops for an update (prepare request, prepare response, submit request).
- Custom Claude agent files are only loaded at session start.
- The demo app does not handle SIGTERM quickly, so old pods take up to 30s to terminate after a rollout; the
  rollout watcher ignores terminating pods.

## Independent review

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
