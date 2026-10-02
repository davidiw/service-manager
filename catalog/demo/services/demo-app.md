---
schema_version: 1
id: demo-app
name: Demo app (native Kubernetes Deployment)
purpose: Tiny stdlib HTTP server used to exercise restart, digest-pinned image update and rollback through the kubernetes_native executor.
why_it_matters: It is the only workload the Local Operations MCP is allowed to mutate end to end; every execution path is demonstrated here before anything production-like is bound.
owner: local developer
backup: null
disposition: keep
approved_by: local developer
knowledge_holders:
  - name: local developer
    role: author of scripts/demo-cluster.sh
    status: current
environments: [demo]
depends_on: []
used_by: []
next_expiry: none
expiry_note: Disposable; recreated by scripts/demo-cluster.sh up and removed by scripts/demo-cluster.sh down.
bindings:
  - id: demo-deployment
    environment: demo
    provider_id: kube-demo
    cluster_name: local-ops-demo
    cluster_identity: kube-demo
    namespace: demo
    workload_kind: Deployment
    workload_name: demo-app
    container_name: app
    execution_enabled: true
    source_state: verified
    endpoints: ["http://127.0.0.1:30080"]
    sources: ["scripts/demo-cluster.sh", "demo/k8s/demo-app.yaml"]
    note: kind cluster local-ops-demo; identity approved via local-state/demo-cluster.json (kube-system namespace UID).
source_repositories:
  - url: "file://demo/app"
    deployment_mechanism: kubernetes_native
    note: built by scripts/demo-cluster.sh
    access: verified
credential_refs:
  - id: kubeconfig-demo
    kind: kubeconfig_context
    held_in: "~/.kube/config (context kind-local-ops-demo, written by kind)"
    resolver_id: kubeconfig-demo
    status: verified
observability:
  - kind: logs
    provider_id: kube-demo
    note: container logs via kube-demo
audit_sources: ["demo-fake"]
knowledge:
  queries:
    - id: recent_errors
      description: Recent error lines from the app container
      source_id: kube-demo
      query_type: container_logs
      scope: {namespace: demo, workload_kind: Deployment, workload_name: demo-app}
      filters: {grep: error}
      limits: {max_events: 500}
      lookback_minutes: 30
  failure_signatures:
    - id: not_serving
      match: {source: container_logs, contains: "Address already in use"}
      meaning: A second listener started in the pod; the app process is not serving requests.
      first_steps: ["service_inspect demo-app", "saved_query_run demo-app recent_errors"]
health_checks:
  - id: demo_http_health
    kind: http_status
    url: http://127.0.0.1:30080/health
  - id: demo_http_version
    kind: http_json
    url: http://127.0.0.1:30080/version
    json_field: version
    equals_artifact_version: true
operations:
  restart:
    executor: kubernetes_native
    kind: rollout_restart
    binding_id: demo-deployment
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health]
  update:
    executor: kubernetes_native
    kind: image_update
    binding_id: demo-deployment
    container: app
    allowed_image_repositories: ["localhost:5001/local-ops/demo-app"]
    require_digest: true
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health, demo_http_version]
    rollback_policy: explicit_only
  rollback:
    executor: kubernetes_native
    kind: rollback
    binding_id: demo-deployment
    container: app
    allowed_image_repositories: ["localhost:5001/local-ops/demo-app"]
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health]
    rollback_policy: explicit_only
facts:
  - topic: deployment
    statement: Deployment demo-app (2 replicas, container app) is applied from demo/k8s/demo-app.yaml with the v1 image digest substituted by the script.
    confidence: verified
    evidence:
      - source: scripts/demo-cluster.sh
        note: "`up` subcommand: sed-substitutes the v1 digest and kubectl-applies the manifest"
  - topic: images
    statement: Tags v1, v2 and v2-broken of localhost:5001/local-ops/demo-app are built and pushed to the local registry; digests are recorded in local-state/demo-images.json.
    confidence: verified
    evidence:
      - source: scripts/demo-cluster.sh
        note: "`images` subcommand"
  - topic: endpoint
    statement: NodePort 30080 is mapped to host port 30080 by the kind extraPortMappings, so http://127.0.0.1:30080 reaches the Service.
    confidence: verified
    evidence:
      - source: scripts/demo-cluster.sh
        note: kind config extraPortMappings
contradictions: []
unknowns: []
tags: [demo, disposable, kind]
---
# Demo app (native Kubernetes)

This service exists only inside the disposable kind cluster `local-ops-demo`. Nothing here is
production. The approved cluster identity is the kube-system namespace UID recorded by
`scripts/demo-cluster.sh up` in `local-state/demo-cluster.json`; the server refuses to execute
if the live context points anywhere else.

## Failure demonstration

`scripts/demo-cluster.sh break` patches the Deployment to the `v2-broken` digest directly with
kubectl (outside the server) so a failed rollout can be observed; `scripts/demo-cluster.sh reset`
restores the v1 digest.

## Human runbook (documentation only; the server never executes this text)

    scripts/demo-cluster.sh status
    curl http://127.0.0.1:30080/health
    curl http://127.0.0.1:30080/version
