---
schema_version: 1
id: demo-helm
name: Demo app (Helm release)
purpose: The same demo HTTP server deployed as Helm release demo-helm to exercise the helm executor (upgrade with digest pin, rollback, post-upgrade hook disclosure).
why_it_matters: Demonstrates the Helm execution path, including hook disclosure and revision-based rollback, inside the disposable cluster only.
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
  - id: demo-helm-release
    environment: demo
    provider_id: kube-demo
    cluster_name: local-ops-demo
    cluster_identity: kube-demo
    namespace: demo
    workload_kind: Deployment
    workload_name: demo-helm
    container_name: app
    execution_enabled: true
    source_state: verified
    endpoints: ["http://127.0.0.1:30081"]
    sources: ["scripts/demo-cluster.sh", "catalog/demo/charts/demo-helm"]
    note: Helm release demo-helm installed by scripts/demo-cluster.sh with --set image.ref=<v1 digest reference>.
source_repositories:
  - url: "file://demo/app"
    deployment_mechanism: helm
    path: catalog/demo/charts/demo-helm
    note: image built by scripts/demo-cluster.sh; chart lives in the catalog
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
health_checks:
  - id: demo_http_health
    kind: http_status
    url: http://127.0.0.1:30081/health
  - id: demo_http_version
    kind: http_json
    url: http://127.0.0.1:30081/version
    json_field: version
    equals_artifact_version: true
operations:
  restart:
    executor: helm
    kind: rollout_restart
    binding_id: demo-helm-release
    release: demo-helm
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health]
  update:
    executor: helm
    kind: helm_upgrade
    binding_id: demo-helm-release
    release: demo-helm
    chart_path: charts/demo-helm
    image_value_path: image.ref
    container: app
    allowed_image_repositories: ["localhost:5001/local-ops/demo-app"]
    require_digest: true
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health, demo_http_version]
    rollback_policy: explicit_only
  rollback:
    executor: helm
    kind: helm_rollback
    binding_id: demo-helm-release
    release: demo-helm
    chart_path: charts/demo-helm
    readiness_timeout_seconds: 120
    health_checks: [ready_replicas, demo_http_health]
    rollback_policy: explicit_only
facts:
  - topic: release
    statement: Helm release demo-helm (chart demo-helm 0.1.0, 1 replica, container app) is installed in namespace demo with image.ref set to the v1 digest reference.
    confidence: verified
    evidence:
      - source: scripts/demo-cluster.sh
        note: "`up` subcommand: helm upgrade --install demo-helm catalog/demo/charts/demo-helm -n demo --set image.ref=<v1 digest> --wait"
  - topic: hooks
    statement: The chart declares a post-upgrade Job hook (templates/post-upgrade-hook.yaml) that reads /version with busybox and is deleted on success.
    confidence: verified
    evidence:
      - source: catalog/demo/charts/demo-helm/templates/post-upgrade-hook.yaml
  - topic: endpoint
    statement: NodePort 30081 is mapped to host port 30081 by the kind extraPortMappings, so http://127.0.0.1:30081 reaches the Service.
    confidence: verified
    evidence:
      - source: scripts/demo-cluster.sh
        note: kind config extraPortMappings
contradictions: []
unknowns: []
tags: [demo, disposable, kind, helm]
---
# Demo app (Helm release)

Helm-managed twin of `demo-app` in the disposable kind cluster `local-ops-demo`. The chart is the
single canonical copy at `catalog/demo/charts/demo-helm` (the `chart_path` above is relative to the
catalog root). Upgrades pin the image by digest through `--set-string image.ref=...`; rollback is an
explicit, separate action (`helm rollback`).

## Human runbook (documentation only; the server never executes this text)

    helm -n demo status demo-helm
    helm -n demo history demo-helm
    curl http://127.0.0.1:30081/version
