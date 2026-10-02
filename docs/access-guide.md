# Access guide (generated from adapter descriptions)

Source config: `config/examples/server.yaml`. Regenerate with `uv run python scripts/gen-access-guide.py config/examples/server.yaml`.

Live verification status is reported honestly: an adapter is only *live-verified* when a developer ran a live check against a real account. Fixture tests never count.

## Human-operated 1Password CLI inventory

For the headless human CLI workflow, use a `CredentialRef` with `kind: onepassword_cli` and the required `account: moveindustries`, then retain the existing provider `vaults: []` scope. A human authenticates the CLI through their normal external flow before the server starts. Do not invoke sign-in from this workflow or provide unverified sign-in syntax. If the normal flow exports session state, export it outside the server process and restart the server so it inherits that state.

Optional human-run inspection commands are `op account list`, `op whoami --account moveindustries --format json`, and `op vault list --account moveindustries --format json`. The adapter itself uses only `whoami`, `vault list`, and `item list`; every backend call selects `moveindustries`, requests JSON and ISO timestamps, and disables the CLI cache. Item listing supplies its vault and includes archived items. It never invokes get/read/inject/run/document retrieval/sign-in, accepts no stdin login, and supports metadata inventory only; it cannot resolve item secrets. It also disables desktop biometric unlocking and removes inherited service-account and Connect credentials before launching the CLI. Each invocation is bounded to 30 seconds, 16 MiB of stdout, and 64 KiB of stderr.

No real 1Password account has been verified in this build. Run `local-ops doctor --config ./local-config/server.yaml --catalog ~/.local/share/local-ops/catalog --live`, then serve with the same config and catalog. With the local discovery key loaded, submit `uv run python examples/mcp_client_example.py discovery discovery_scan '{"providers":["onepassword-main"]}'` and review/release it in the local review UI. CLI access is a human-operated scoped view; service-account access is separate unattended automation for specifically granted vaults. Neither establishes organization-wide visibility. Unknown metadata fields remain unknown, and creator/editor metadata does not identify a current custodian.

## AWS census coverage semantics

AWS discovery is metadata-only. It never calls Secrets Manager `GetSecretValue`, cryptographic KMS APIs, CloudWatch Logs content APIs during census, or data-plane APIs for DynamoDB, caches, EFS, or OpenSearch. A `complete` comparable family scope may support an empty-inventory conclusion. `partial_resumable` has a saved provider cursor; `partial_restart` has no usable cursor and must begin again; `unavailable` failed through authorization or provider access. Every non-complete status, including a resumed suffix, is unknown for absence and never marks prior observations missing.

Only CloudWatch Logs log-group and Secrets Manager list paging resume, at committed page boundaries. Checkpoints are private, keyed to the configured provider principal, verified account identity, configuration, and scope, and expire after 24 hours. Other families restart if interrupted. Configured regions are the scan scope, not a claim that every enabled AWS region was scanned. Organizations account enumeration is opt-in; when disabled or incomplete, the organization denominator is unknown. Cost Explorer `SERVICE` labels with at least $0.01 spend are coverage signals: each is labeled enumerated, supported-but-incomplete, intentionally non-resource, or unsupported; spend never proves resource presence or absence. Management-account billing retains visible member-account spend, attributed to each linked account with billing_source_account provenance; billing-only accounts appear in account coverage with billing evidence even without Organizations access, without establishing an Organizations denominator or successful resource discovery.

## aws-primary (aws)

Example primary application account

- Required credentials: aws-primary-readonly (configured: yes)
- Minimum access: Read-only IAM role/SSO permission set. Core inventory: sts:GetCallerIdentity; ec2:Describe*; eks:List*/Describe*; elasticloadbalancing:Describe*; rds:Describe*; ecr:Describe*/List*; s3:ListAllMyBuckets/GetBucketLocation; backup:List*; route53:List*; acm:List*/Describe*; lambda:List*; ecs:List*/Describe*; events:List*; autoscaling:Describe*; iam:List*/Get*; organizations:ListAccounts (only when enabled); ce:GetCostAndUsage. Census families: secretsmanager:ListSecrets/DescribeSecret (never GetSecretValue); kms:ListKeys/ListAliases/DescribeKey/ListResourceTags/GetKeyRotationStatus; logs:DescribeLogGroups/ListTagsForResource (never GetLogEvents); cloudwatch:DescribeAlarms; dynamodb:ListTables/DescribeTable/ListTagsOfResource; elasticache:DescribeCacheClusters/DescribeReplicationGroups/ListTagsForResource; elasticfilesystem:DescribeFileSystems/DescribeMountTargets/DescribeMountTargetSecurityGroups/ListTagsForResource; es:ListDomainNames/DescribeDomains/ListTags; sqs:ListQueues/ListQueueTags/GetQueueAttributes; sns:ListTopics/ListSubscriptionsByTopic/ListTagsForResource; apigateway:GET (REST/HTTP/WebSocket APIs, resources and integrations under /restapis and /apis); cloudfront:ListDistributions/ListTagsForResource; wafv2:ListWebACLs/GetWebACL/ListTagsForResource; states:ListStateMachines/ListTagsForResource; cloudformation:ListStacks/ListStackResources. Diagnosis additionally needs cloudtrail:LookupEvents, logs:FilterLogEvents/StartQuery/GetQueryResults/DescribeLogGroups, cloudwatch:GetMetricData, guardduty:ListDetectors/ListFindings/GetFindings. No write permissions, cryptographic calls, secret values, log contents, or application data; never AdministratorAccess.
- Local availability check: True configured_not_live_checked
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Account identity, enabled regions, and inventory families: eks, ec2, elb, rds, ecr, backup, acm, lambda, ecs, events, autoscaling, secretsmanager, kms, logs, cloudwatch, dynamodb, elasticache, efs, opensearch, sqs, sns, apigateway, wafv2, stepfunctions, cloudformation, s3, route53, iam, organizations, billing, cloudfront. provider-side filters: ['regions', 'families', 'repositories']; limits: Discovery pagination exhausts provider pages within the configured deadline; partial scopes never prove absence; Log groups and Secrets Manager resume at committed page boundaries; other families restart; IAM access-key identifiers are hashed; metadata only, no secret values; Billing is a coverage signal, not a resource inventory
  - `cloudtrail_events` (read): CloudTrail management-event history (LookupEvents) per configured region. provider-side filters: ['time_range', 'one of: event_names[0] (EventName) > actors[0] (Username) > resource_names[0] (ResourceName) > event_source (EventSource)']; local filters: ['event_names', 'actors', 'resource_names', 'event_source', 'source_ips', 'outcome']; limits: CloudTrail event history is per account/region, management events only, 90 days; Exactly one LookupAttribute is applied server-side; every other filter runs locally over a result set capped by max_pages/max_events
  - `cloudwatch_logs` (read_with_bookkeeping): CloudWatch Logs: FilterLogEvents when filter_pattern is given (plain read), otherwise a Logs Insights query job (read with bookkeeping: StartQuery creates a provider-side job). provider-side filters: ['log_groups', 'time_range', 'filter_pattern', 'query']; limits: Insights queries are bounded by the operation budget; an unfinished job is stopped and reported as truncated; Log group retention is reported when readable, otherwise unknown
  - `cloudwatch_metrics` (read): CloudWatch GetMetricData for an explicit list of metric queries. provider-side filters: ['queries', 'time_range', 'period', 'stat']; limits: At most 20 metric queries per call; datapoints bounded by max_events
  - `guardduty_findings` (read): Existing GuardDuty findings per region; never enables detectors. provider-side filters: ['time_range (updatedAt)', 'min_severity']; local filters: ['finding_types']; limits: Regions without a detector are reported as guardduty_not_enabled coverage gaps; Findings are existing detections only; absence is not evidence of absence
  - `kubernetes_audit` (read): EKS kube-apiserver audit events delivered to CloudWatch Logs (/aws/eks/<cluster>/cluster). provider-side filters: ['cluster_name', 'time_range', 'filter_pattern']; local filters: ['actors', 'verbs', 'namespaces', 'resources']; limits: Requires EKS audit control-plane logging; disabled logging is a coverage gap, not a clean result; S3 data events and EKS audit activity are not in CloudTrail event history
  - `eks_log_coverage` (read): EKS control-plane logging configuration and log-group retention per cluster. provider-side filters: ['cluster_name', 'regions'];
- Limitations:
  - CloudTrail event history is per account/region, management events only, 90 days
  - CloudTrail Lake / historical stores not queried unless cloudtrail_lake_event_data_store is set (then unsupported in this release: report as unavailable scope)
  - S3 data events and EKS audit activity are not in event history
  - Billing dimensions are cost aggregation, not an inventory
  - Account identity is verified live via STS against expected_account_id; a familiar profile name is not proof of the right account
- Scope constraints: `{'account_alias': 'example-primary', 'expected_account_id': None, 'regions': ['us-east-1', 'us-west-2'], 'families': ['sts', 'regions', 'eks', 'ec2', 'elb', 'rds', 'ecr', 'backup', 'acm', 'lambda', 'ecs', 'events', 'autoscaling', 'secretsmanager', 'kms', 'logs', 'cloudwatch', 'dynamodb', 'elasticache', 'efs', 'opensearch', 'sqs', 'sns', 'apigateway', 'wafv2', 'stepfunctions', 'cloudformation', 's3', 'route53', 'iam', 'billing', 'cloudfront'], 'organizations_enumeration': False, 'cloudtrail_lake_event_data_store': None}`

## aws-shared (aws)

Example shared services account

- Required credentials: aws-shared-readonly (configured: yes)
- Minimum access: Read-only IAM role/SSO permission set. Core inventory: sts:GetCallerIdentity; ec2:Describe*; eks:List*/Describe*; elasticloadbalancing:Describe*; rds:Describe*; ecr:Describe*/List*; s3:ListAllMyBuckets/GetBucketLocation; backup:List*; route53:List*; acm:List*/Describe*; lambda:List*; ecs:List*/Describe*; events:List*; autoscaling:Describe*; iam:List*/Get*; organizations:ListAccounts (only when enabled); ce:GetCostAndUsage. Census families: secretsmanager:ListSecrets/DescribeSecret (never GetSecretValue); kms:ListKeys/ListAliases/DescribeKey/ListResourceTags/GetKeyRotationStatus; logs:DescribeLogGroups/ListTagsForResource (never GetLogEvents); cloudwatch:DescribeAlarms; dynamodb:ListTables/DescribeTable/ListTagsOfResource; elasticache:DescribeCacheClusters/DescribeReplicationGroups/ListTagsForResource; elasticfilesystem:DescribeFileSystems/DescribeMountTargets/DescribeMountTargetSecurityGroups/ListTagsForResource; es:ListDomainNames/DescribeDomains/ListTags; sqs:ListQueues/ListQueueTags/GetQueueAttributes; sns:ListTopics/ListSubscriptionsByTopic/ListTagsForResource; apigateway:GET (REST/HTTP/WebSocket APIs, resources and integrations under /restapis and /apis); cloudfront:ListDistributions/ListTagsForResource; wafv2:ListWebACLs/GetWebACL/ListTagsForResource; states:ListStateMachines/ListTagsForResource; cloudformation:ListStacks/ListStackResources. Diagnosis additionally needs cloudtrail:LookupEvents, logs:FilterLogEvents/StartQuery/GetQueryResults/DescribeLogGroups, cloudwatch:GetMetricData, guardduty:ListDetectors/ListFindings/GetFindings. No write permissions, cryptographic calls, secret values, log contents, or application data; never AdministratorAccess.
- Local availability check: True configured_not_live_checked
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Account identity, enabled regions, and inventory families: eks, ec2, elb, rds, ecr, backup, acm, lambda, ecs, events, autoscaling, secretsmanager, kms, logs, cloudwatch, dynamodb, elasticache, efs, opensearch, sqs, sns, apigateway, wafv2, stepfunctions, cloudformation, s3, route53, iam, organizations, billing, cloudfront. provider-side filters: ['regions', 'families', 'repositories']; limits: Discovery pagination exhausts provider pages within the configured deadline; partial scopes never prove absence; Log groups and Secrets Manager resume at committed page boundaries; other families restart; IAM access-key identifiers are hashed; metadata only, no secret values; Billing is a coverage signal, not a resource inventory
  - `cloudtrail_events` (read): CloudTrail management-event history (LookupEvents) per configured region. provider-side filters: ['time_range', 'one of: event_names[0] (EventName) > actors[0] (Username) > resource_names[0] (ResourceName) > event_source (EventSource)']; local filters: ['event_names', 'actors', 'resource_names', 'event_source', 'source_ips', 'outcome']; limits: CloudTrail event history is per account/region, management events only, 90 days; Exactly one LookupAttribute is applied server-side; every other filter runs locally over a result set capped by max_pages/max_events
  - `cloudwatch_logs` (read_with_bookkeeping): CloudWatch Logs: FilterLogEvents when filter_pattern is given (plain read), otherwise a Logs Insights query job (read with bookkeeping: StartQuery creates a provider-side job). provider-side filters: ['log_groups', 'time_range', 'filter_pattern', 'query']; limits: Insights queries are bounded by the operation budget; an unfinished job is stopped and reported as truncated; Log group retention is reported when readable, otherwise unknown
  - `cloudwatch_metrics` (read): CloudWatch GetMetricData for an explicit list of metric queries. provider-side filters: ['queries', 'time_range', 'period', 'stat']; limits: At most 20 metric queries per call; datapoints bounded by max_events
  - `guardduty_findings` (read): Existing GuardDuty findings per region; never enables detectors. provider-side filters: ['time_range (updatedAt)', 'min_severity']; local filters: ['finding_types']; limits: Regions without a detector are reported as guardduty_not_enabled coverage gaps; Findings are existing detections only; absence is not evidence of absence
  - `kubernetes_audit` (read): EKS kube-apiserver audit events delivered to CloudWatch Logs (/aws/eks/<cluster>/cluster). provider-side filters: ['cluster_name', 'time_range', 'filter_pattern']; local filters: ['actors', 'verbs', 'namespaces', 'resources']; limits: Requires EKS audit control-plane logging; disabled logging is a coverage gap, not a clean result; S3 data events and EKS audit activity are not in CloudTrail event history
  - `eks_log_coverage` (read): EKS control-plane logging configuration and log-group retention per cluster. provider-side filters: ['cluster_name', 'regions'];
- Limitations:
  - CloudTrail event history is per account/region, management events only, 90 days
  - CloudTrail Lake / historical stores not queried unless cloudtrail_lake_event_data_store is set (then unsupported in this release: report as unavailable scope)
  - S3 data events and EKS audit activity are not in event history
  - Billing dimensions are cost aggregation, not an inventory
  - Account identity is verified live via STS against expected_account_id; a familiar profile name is not proof of the right account
- Scope constraints: `{'account_alias': 'example-shared', 'expected_account_id': None, 'regions': ['us-west-2', 'eu-west-1'], 'families': ['sts', 'regions', 'eks', 'ec2', 'elb', 'rds', 'ecr', 'backup', 'acm', 'lambda', 'ecs', 'events', 'autoscaling', 'secretsmanager', 'kms', 'logs', 'cloudwatch', 'dynamodb', 'elasticache', 'efs', 'opensearch', 'sqs', 'sns', 'apigateway', 'wafv2', 'stepfunctions', 'cloudformation', 's3', 'route53', 'iam', 'billing', 'cloudfront'], 'organizations_enumeration': False, 'cloudtrail_lake_event_data_store': None}`

## kube-example-app (kubernetes)

Example application EKS cluster

- Required credentials: kubeconfig-example-app (configured: yes)
- Minimum access: A kubeconfig context with a read-only ClusterRole (get/list on namespaces, deployments, statefulsets, daemonsets, jobs, cronjobs, pods, pods/log, replicasets, services, ingresses, persistentvolumeclaims, rolebindings, events). Execution bindings additionally need patch on the exact Deployment/StatefulSet/DaemonSet. No secrets, no pods/exec, no pods/portforward.
- Local availability check: True configured_not_live_checked
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Namespaces, workloads, pods/owners, services/ingress, PVCs, role bindings, events. limits: No Secret data, exec, port-forward or manifest application.
  - `kubernetes_events` (read): Namespace events in a bounded window. provider-side filters: ['namespace']; local filters: ['reason', 'involved_object', 'time_range'];
  - `container_logs` (read): Bounded current/previous container logs. provider-side filters: ['namespace', 'pod', 'container', 'tail_lines', 'since_seconds', 'previous']; local filters: ['grep'];
  - `workload_inspect` (read): Exact running identity, artifact, rollout and restart state.
- Limitations:
  - Kubernetes events are best-effort and short-lived; they are not an audit log.
  - EKS/control-plane audit logs are a separate source (CloudWatch).
- Scope constraints: `{'context': 'example-app', 'namespaces': 'all'}`

## onepassword-main (onepassword)

- Required credentials: op-service-account (configured: no)
- Minimum access: Read access to the specific vaults to inventory. The configured credential determines the scoped view; it is not organization-wide visibility.
- Local availability check: False credential_not_configured
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Vault and item metadata (ids, titles, categories, tags, timestamps) within granted vaults. provider-side filters: ['vaults']; limits: The Items list API returns item overviews only; field names/values are not exposed and are deliberately not retrieved for inventory.; No whole-vault secret export; no item field values in results.
  - `resolve_item_secret` (read): Internal resolution of an approved onepassword_item credential reference (never returned to callers). limits: Only credentials declared in server configuration; values go to the sanitizer-registered resolver cache only.
- Limitations:
  - Access is a scoped view limited to vaults visible to the configured credential, not organization-wide visibility. Service accounts exclude personal/private/employee vaults; human sessions may see additional vaults.
  - The Items list API returns item overviews only; field names/values are not exposed and are deliberately not retrieved for inventory.
  - Do not infer the current custodian from the historical creator or last editor; 1Password metadata does not identify a current owner.
  - Events (sign-ins, item usage, audit) are a separate source: configure an onepassword_events provider.
- Scope constraints: `{'vaults': 'all vaults visible to the credential', 'auth': 'onepassword_service_account'}`

## onepassword-events (onepassword_events)

- Required credentials: op-events-token (configured: no)
- Minimum access: A separate Events Reporting token with the auditevents / signinattempts / itemusages features you want; the adapter introspects which it has.
- Local availability check: False credential_not_configured
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `onepassword_events` (read): Audit events, sign-in attempts and item usages from 1Password Events Reporting. provider-side filters: ['kinds', 'time_range', 'cursor']; limits: The Events API exposes vault/item/user UUIDs only (no names); join ids to onepassword metadata where available and treat unresolved ids as unresolved.; Each event kind is a separate token feature; kinds the token lacks are reported as unavailable scopes.
- Limitations:
  - The Events API exposes vault/item/user UUIDs only (no names); join ids to onepassword metadata where available and treat unresolved ids as unresolved.
  - Events Reporting token capabilities differ from the service-account token; introspection decides which kinds are collectable.
  - Source retention is not reported by the API; history before the first collected event is unknown.
- Scope constraints: `{'base_url': 'https://events.1password.com', 'kinds': ['auditevents', 'signinattempts', 'itemusages']}`

## github-example (github)

- Required credentials: github-token (configured: no)
- Minimum access: A fine-grained token with repository metadata/contents read on the listed repositories, actions read, deployments read; organization audit log read requires an org/enterprise plan that exposes the audit log API.
- Local availability check: False credential_not_configured
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Repository metadata, workflows (with recent runs) and recent deployments for configured repositories or an organization's repositories. provider-side filters: ['repositories', 'org']; limits: Metadata only; no checkout, no secrets, no artifact download.
  - `github_audit` (read): Organization audit log (where token/plan permit). provider-side filters: ['actor', 'action', 'created>=', 'phrase']; limits: GitHub audit log retention varies by event/plan; git events are retained ~7 days; Enterprise audit log and streaming are not read.
  - `github_workflow_runs` (read): Workflow runs for one repository in a time window. provider-side filters: ['repository', 'created', 'branch', 'event', 'status'];
  - `github_file` (read): Bounded read of one explicit in-repository path (runbook/source), max 200KB. provider-side filters: ['repository', 'path', 'ref']; limits: One explicit path per query; no directory listing or recursive reads.
- Limitations:
  - GitHub audit log retention varies by event/plan; git events are retained ~7 days
  - 404 is an access/location uncertainty (missing permission, renamed/moved, or private to another identity), not proof the repository does not exist
  - Rate limits are respected with one bounded wait; further limiting produces a coverage gap.
- Scope constraints: `{'base_url': 'https://api.github.com', 'org': 'example-org', 'repositories': ['example-org/example-app'], 'audit_log': True}`

## grafana-main (grafana)

- Required credentials: grafana-token (configured: no)
- Minimum access: A Grafana service-account token with Viewer role (datasource proxy reads).
- Local availability check: False credential_missing
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): List data sources, dashboards and provisioned alert rules visible to the configured credential. limits: dashboards and alert rules are bounded to 200 entries; data-source secrets (basic auth passwords, secureJsonData) are never read
  - `loki_logs` (read): LogQL query_range proxied through Grafana to a Loki data source (scope.datasource_uid). provider-side filters: ['query', 'time_range', 'limit']; limits: limit is min(max_events, 5000); direction=backward
  - `prometheus_metrics` (read): PromQL query_range proxied through Grafana to a Prometheus data source (scope.datasource_uid). provider-side filters: ['query', 'time_range', 'step'];
- Limitations:
  - uses existing endpoints; installs nothing
  - Read-only: discovery and bounded queries only; nothing is written to the provider.
  - Only data sources the credential's Grafana user/service account can see are discovered.
- Scope constraints: `{'url': 'https://grafana.example.invalid'}`

## pagerduty-main (pagerduty)

- Required credentials: pagerduty-token (configured: no)
- Minimum access: A read-only PagerDuty REST API key (services, schedules, escalation policies, incidents). It never triggers pages.
- Local availability check: False credential_missing
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): List services (with integration type/name only), escalation policies with their user/schedule targets, and on-call schedules. limits: each listing bounded to 500 entries; integration keys are never read or stored
  - `pagerduty_incidents` (read): Bounded recent incidents (since/until, statuses, service_ids) normalized as incident events. provider-side filters: ['time_range', 'statuses', 'service_ids', 'limit']; limits: PagerDuty caps incident history listing; very old incidents may be unavailable
- Limitations:
  - read-only; does not trigger pages
  - Only GET requests are issued; incident creation/acknowledge/resolve endpoints are never called.
- Scope constraints: `{'url': 'https://api.pagerduty.com'}`

## example-imports (local_import)

- Required credentials: none (configured: yes)
- Minimum access: Reviewed JSON/JSONL/CSV/Markdown files in the configured directory; never executed.
- Local availability check: False path_missing
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `discover` (read): Read reviewed import files (<kind>.<name>.{json,jsonl,csv,md}) for billing, registrar, dns, services, identities and notes. limits: observations are claims from files, not live observations; files over 20MB are skipped
  - `local_import` (read): filters.kind=events: load events.*.json/jsonl rows already in normalized-event shape. local filters: ['kind']; limits: imported events are claims from a reviewed file, not live collection
- Limitations:
  - Never executes imported content; parsed with csv/json only.
  - Symlinks escaping the import directory are refused.
  - Kind is declared by the filename prefix; files without a known kind prefix are listed as skipped.
- Scope constraints: `{'path': '/home/davidiw/src/service-management/config/examples/imports'}`

## ecr-registry (registry)

Resolve tags to digests for approved image repositories

- Required credentials: none (configured: yes)
- Minimum access: Anonymous or read-only pull credentials for the configured registries (ECR needs ecr:BatchGetImage/DescribeImages via the aws provider or a token).
- Local availability check: True configured_not_live_checked
- Live-verified in this build: no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)
- Operations:
  - `resolve_digest` (read): Resolve repo:tag to an immutable manifest/index digest and read OCI version labels.
- Limitations:
  - Multi-platform index digests differ from per-platform manifest digests; both are reported.
- Scope constraints: `{'registries': ['000000000000.dkr.ecr.us-east-1.amazonaws.com']}`
