#!/usr/bin/env python3
"""Generate docs/access-guide.md from the adapters' own describe() output: what each needs, what it
supports, its limitations, and which live checks remain unverified. Run: uv run python scripts/gen-access-guide.py"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from local_ops.app import build_providers  # noqa: E402
from local_ops.config import load_server_config  # noqa: E402
from local_ops.providers.credentials import CredentialResolver  # noqa: E402
from local_ops.release import Sanitizer  # noqa: E402

MIN_ACCESS = {
    "aws": "Read-only IAM role/SSO permission set: sts:GetCallerIdentity, ec2:Describe*, eks:List*/Describe*, elasticloadbalancing:Describe*, rds:Describe*, ecr:Describe*/List*, s3:ListAllMyBuckets/GetBucketLocation, backup:List*, route53:List*, acm:List*/Describe*, lambda:List*, ecs:List*/Describe*, events:List*, autoscaling:Describe*, iam:List*/Get* (bounded), ce:GetCostAndUsage, cloudtrail:LookupEvents, logs:FilterLogEvents/StartQuery/GetQueryResults/DescribeLogGroups, cloudwatch:GetMetricData, guardduty:ListDetectors/ListFindings/GetFindings. No write permissions; never AdministratorAccess.",
    "kubernetes": "A kubeconfig context with a read-only ClusterRole (get/list on namespaces, deployments, statefulsets, daemonsets, jobs, cronjobs, pods, pods/log, replicasets, services, ingresses, persistentvolumeclaims, rolebindings, events). Execution bindings additionally need patch on the exact Deployment/StatefulSet/DaemonSet. No secrets, no pods/exec, no pods/portforward.",
    "onepassword": "A 1Password service account granted read access to the specific vaults to inventory; its view is scoped and excludes personal/private/employee vaults.",
    "onepassword_events": "A separate Events Reporting token with the auditevents / signinattempts / itemusages features you want; the adapter introspects which it has.",
    "github": "A fine-grained token with repository metadata/contents read on the listed repositories, actions read, deployments read; organization audit log read requires an org/enterprise plan that exposes the audit log API.",
    "grafana": "A Grafana service-account token with Viewer role (datasource proxy reads).",
    "prometheus": "Network access to the Prometheus HTTP API (read-only).",
    "loki": "Network access to the Loki HTTP API (read-only).",
    "pagerduty": "A read-only PagerDuty REST API key (services, schedules, escalation policies, incidents). It never triggers pages.",
    "local_import": "Reviewed JSON/JSONL/CSV/Markdown files in the configured directory; never executed.",
    "registry": "Anonymous or read-only pull credentials for the configured registries (ECR needs ecr:BatchGetImage/DescribeImages via the aws provider or a token).",
    "demo": "Nothing; in-process fixtures labeled fixture=true.",
}


async def main(config_path: str) -> None:
    cfg = load_server_config(config_path)
    reg = build_providers(cfg, CredentialResolver(cfg, Sanitizer()))
    lines = ["# Access guide (generated from adapter descriptions)", "", f"Source config: `{config_path}`. Regenerate with `uv run python scripts/gen-access-guide.py {config_path}`.", "", "Live verification status is reported honestly: an adapter is only *live-verified* when a developer ran a live check against a real account. Fixture tests never count.", ""]
    for a in reg.adapters.values():
        d = a.describe()
        try:
            av = await a.check_availability(live=False)
            avd = av.model_dump()
        except Exception as e:  # noqa: BLE001
            avd = {"available": False, "reason": type(e).__name__}
        lines += [f"## {d.provider_id} ({d.kind})", ""]
        if d.description:
            lines += [d.description, ""]
        lines += [f"- Required credentials: {', '.join(d.required_credentials) or 'none'} (configured: {'yes' if d.credential_configured else 'no'})", f"- Minimum access: {MIN_ACCESS.get(d.kind, 'see adapter')}", f"- Local availability check: {avd.get('available')} {avd.get('reason') or ''}", f"- Live-verified in this build: {'yes' if d.live_verified else 'no (requires a real account and an explicit `local-ops doctor --live` or Settings → Check now)'}", "- Operations:"]
        for op in d.operations:
            lines.append(f"  - `{op.name}` ({op.effect.value}): {op.description}" + (f" provider-side filters: {op.provider_side_filters};" if op.provider_side_filters else "") + (f" local filters: {op.local_filters};" if op.local_filters else "") + (f" limits: {'; '.join(op.limitations)}" if op.limitations else ""))
        if d.limitations:
            lines.append("- Limitations:")
            lines += [f"  - {l}" for l in d.limitations]
        if d.scope_constraints:
            lines.append(f"- Scope constraints: `{d.scope_constraints}`")
        lines.append("")
        close = getattr(a, "close", None)
        if close:
            try:
                await close()
            except Exception:  # noqa: BLE001
                pass
    out = ROOT / "docs" / "access-guide.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out} ({len(reg.adapters)} adapters)")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "config/examples/server.yaml"))
