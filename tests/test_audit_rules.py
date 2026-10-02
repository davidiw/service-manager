"""Pure unit tests over the explainable rule families (R1..R8) and coverage merging, using the demo
fixtures normalized exactly as the demo provider does, and a catalog whose identities.yaml marks
`carol-departed` as departed on 2026-08-01 and `eks-admin` as a shared role."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from local_ops.audit import merge_coverage, run_rules
from local_ops.catalog import Catalog, load_catalog
from local_ops.models import Coverage, Finding, UnavailableScope
from local_ops.providers.demo import (
    demo_audit_events,
    demo_github_events,
    demo_guardduty_findings,
    demo_kube_audit_events,
    normalize_cloudtrail,
    normalize_github_audit,
    normalize_k8s_audit,
)
from tests.conftest import write_catalog

EV_CT, EV_K8S, EV_GH, EV_GD = "evd_cloudtrail", "evd_k8s", "evd_github", "evd_guardduty"
ALL_REFS = {EV_CT, EV_K8S, EV_GH, EV_GD}


@pytest.fixture
def catalog(tmp_path: Path) -> Catalog:
    write_catalog(tmp_path / "c", health_port=1)
    cat = load_catalog(tmp_path / "c")
    assert cat.errors == []
    return cat


def events_for(scenario: str) -> list[dict[str, Any]]:
    return (
        [normalize_cloudtrail(e, "demo-fake", EV_CT) for e in demo_audit_events(scenario)]
        + [normalize_k8s_audit(e, "demo-fake", EV_K8S) for e in demo_kube_audit_events(scenario)]
        + [normalize_github_audit(e, "demo-fake", EV_GH) for e in demo_github_events(scenario)]
    )


def guardduty_for(scenario: str) -> list[dict[str, Any]]:
    return [{**f, "evidence_ref": EV_GD} for f in demo_guardduty_findings(scenario)]


def run(scenario: str, catalog: Catalog, extra_events: list[dict[str, Any]] | None = None) -> list[Finding]:
    return run_rules(events_for(scenario) + (extra_events or []), catalog, security_findings=guardduty_for(scenario))


def by_rule(findings: list[Finding], prefix: str) -> list[Finding]:
    return [f for f in findings if f.rule_id.startswith(prefix)]


# ---------------------------------------------------------------------------- suspicious scenario


def test_r1_departed_identity_exact_join_is_high(catalog: Catalog) -> None:
    r1 = by_rule(run("suspicious", catalog), "R1.")
    assert r1, "departed identity activity must be reported"
    carol = [f for f in r1 if "carol-departed" in f.title]
    assert carol and all(f.identity_join == "exact" for f in carol)
    assert all(f.severity == "high" and f.confidence == "high" for f in carol)
    # every reported action happened after the configured departure date
    assert all("departed since 2026-08-01" in " ".join(f.observed_facts) for f in carol)
    assert all("identity join: exact" in f.observed_facts for f in carol)
    # activity across all three sources is attributed to the departed identity
    actions = {f.title.rsplit(": ", 1)[1] for f in carol}
    assert {"ConsoleLogin", "CreateAccessKey", "StopLogging", "repo.remove_branch_protection"} <= actions


def test_r1_identitycenter_user_removed_from_current_listing(catalog: Catalog) -> None:
    store_id, user_id = "d-1234567890", "11111111-2222-3333-4444-555555555555"
    raw = {
        "eventID": "ic1", "eventName": "GetRoleCredentials", "eventTime": "2026-09-30T12:00:00Z", "eventSource": "sso.amazonaws.com",
        "userIdentity": {"type": "IdentityCenterUser", "onBehalfOf": {"userId": user_id, "identityStoreArn": f"arn:aws:identitystore::123456789012:identitystore/{store_id}"}},
        "requestParameters": {"accountId": "123456789012", "roleName": "AdministratorAccess"},
        "sourceIPAddress": "203.0.113.50", "userAgent": "aws-internal", "resources": [], "awsRegion": "us-east-1", "recipientAccountId": "123456789012",
    }
    ev = normalize_cloudtrail(raw, "demo-fake", EV_CT)
    assert ev["actor"] == f"identitycenter:{store_id}:{user_id}"
    removed_obs = [{"resource_type": "aws/identitystore_user", "missing_since": "2026-09-29T00:00:00Z", "identity": {"identity_store_id": store_id, "user_id": user_id}}]
    r1 = by_rule(run_rules([ev], catalog, identity_center_observations=removed_obs), "R1.identitycenter_user_removed")
    assert len(r1) == 1
    assert r1[0].severity == "high" and r1[0].confidence == "medium"
    assert user_id in " ".join(r1[0].observed_facts) and store_id in " ".join(r1[0].observed_facts)
    # a listing that still carries the user (missing_since unset) must not fire
    present_obs = [{"resource_type": "aws/identitystore_user", "missing_since": None, "identity": {"identity_store_id": store_id, "user_id": user_id}}]
    assert by_rule(run_rules([ev], catalog, identity_center_observations=present_obs), "R1.identitycenter_user_removed") == []
    # and omitting the observation list entirely (the default) must not fire either
    assert by_rule(run_rules([ev], catalog), "R1.identitycenter_user_removed") == []


def test_r2_privileged_changes(catalog: Catalog) -> None:
    r2 = by_rule(run("suspicious", catalog), "R2.")
    titles = {f.title for f in r2}
    assert "Privileged change: CreateAccessKey" in titles
    assert "Privileged change: UpdateAssumeRolePolicy" in titles
    assert "Privileged change: AttachUserPolicy" in titles
    cak = next(f for f in r2 if f.title.endswith("CreateAccessKey"))
    assert cak.severity in ("high", "critical") and cak.confidence == "high"
    assert any("svc-backup" in r for r in cak.affected_resources)
    uarp = next(f for f in r2 if f.title.endswith("UpdateAssumeRolePolicy"))
    assert uarp.severity in ("high", "critical")
    assert any("role/eks-admin" in r for r in uarp.affected_resources)


def test_r2_trust_policy_open_to_any_principal_is_critical(catalog: Catalog) -> None:
    r2 = by_rule(run("suspicious", catalog), "R2.")
    uarp = next(f for f in r2 if f.title.endswith("UpdateAssumeRolePolicy"))
    assert uarp.severity == "critical"
    assert any("any AWS principal" in fact for fact in uarp.observed_facts)


def test_r3_stop_logging_is_critical(catalog: Catalog) -> None:
    r3 = by_rule(run("suspicious", catalog), "R3.")
    stop = [f for f in r3 if f.title.endswith("StopLogging")]
    assert len(stop) == 1
    assert stop[0].severity == "critical" and stop[0].confidence == "high"
    assert any("trail/main" in r for r in stop[0].affected_resources)


def test_r5_failed_auth_burst_then_success(catalog: Catalog) -> None:
    r5 = by_rule(run("suspicious", catalog), "R5.failed_auth_burst")
    assert len(r5) == 1
    f = r5[0]
    assert f.title.startswith("5 failed authentications then success for carol-departed")
    assert f.severity == "high"
    assert len(f.event_keys) == 6  # five failures plus the success
    assert any("192.0.2.44" in fact for fact in f.observed_facts)


def test_r5_single_failure_does_not_fire_for_bob(catalog: Catalog) -> None:
    assert by_rule(run("benign", catalog), "R5.") == []


def test_r6_kubernetes_sensitive_actions(catalog: Catalog) -> None:
    r6 = by_rule(run("suspicious", catalog), "R6.")
    actions = {f.title.split(": ", 1)[1].split(" by ")[0]: f for f in r6}
    assert {"get secrets", "create pods/exec", "create clusterrolebindings"} <= set(actions)
    assert actions["create pods/exec"].severity == "high"
    assert actions["create clusterrolebindings"].severity == "high"
    assert actions["get secrets"].severity == "medium"
    assert all(f.confidence == "high" for f in r6)
    assert "demo-app" in actions["get secrets"].affected_services


def test_r4_unexpected_image_outside_allow_lists_is_critical(catalog: Catalog) -> None:
    r4 = by_rule(run("suspicious", catalog), "R4.")
    assert len(r4) == 1
    f = r4[0]
    assert f.severity == "critical" and f.confidence == "high"
    assert "demo/deployments/demo-app" in f.affected_resources
    assert "demo-app" in f.affected_services
    facts = " ".join(f.observed_facts)
    assert "registry.example.invalid/unknown/miner:latest" in facts
    assert "outside any approved allow list" in facts


def test_r4_allowed_repository_via_direct_api_is_medium(catalog: Catalog) -> None:
    allowed = demo_kube_audit_events("suspicious")[0]
    allowed = {**allowed, "auditID": "k8s-allowed-1", "requestObject": {"spec": {"template": {"spec": {"containers": [{"name": "app", "image": "registry.test/team/demo-app@sha256:" + "d4" * 32}]}}}}}
    ev = [normalize_k8s_audit(allowed, "demo-fake", EV_K8S)]
    r4 = by_rule(run_rules(ev, catalog), "R4.")
    assert len(r4) == 1 and r4[0].severity == "medium"
    assert any("within an approved allow list" in fact for fact in r4[0].observed_facts)


def test_r7_provider_severity_preserved_separately(catalog: Catalog) -> None:
    r7 = by_rule(run("suspicious", catalog), "R7.")
    assert len(r7) == 1
    f = r7[0]
    assert f.provider_severity == "5.0"
    assert f.severity == "medium"  # local assessment, derived but stored separately
    assert f.confidence == "medium"
    assert f.evidence_ids == [EV_GD]
    assert "carol-departed" in f.affected_resources


def test_r8_correlation_shares_identifiers_not_time(catalog: Catalog) -> None:
    r8 = by_rule(run("suspicious", catalog), "R8.")
    assert r8
    for f in r8:
        assert f.severity == "critical"
        providers = {k.split(":", 1)[0] for k in f.event_keys}
        assert providers == {"cloudtrail", "github", "k8saudit"}
        facts = "\n".join(f.observed_facts)
        assert "ip=192.0.2.44" in facts
        assert "shared identifiers" in facts and "not time proximity alone" in facts
        assert "source_ip" in f.title
        assert {EV_CT, EV_GH, EV_K8S} <= set(f.evidence_ids)


# ---------------------------------------------------------------------------- benign scenario


def test_benign_scenario_has_no_departed_burst_or_correlation_findings(catalog: Catalog) -> None:
    fs = run("benign", catalog)
    assert by_rule(fs, "R1.") == []
    assert by_rule(fs, "R5.") == []
    assert by_rule(fs, "R8.") == []
    assert by_rule(fs, "R4.") == []
    assert by_rule(fs, "R7.") == []
    assert not any(f.severity == "critical" for f in fs)
    r2 = by_rule(fs, "R2.")
    assert all(f.title.endswith("CreateAccessKey") for f in r2)
    for f in r2:
        assert f.severity in ("medium", "high")
        assert any("rotation" in b for b in f.benign_explanations)
        assert any("ci-deployer" in fact for fact in f.observed_facts)


def test_benign_update_trail_that_widens_coverage_does_not_fire_r3(catalog: Catalog) -> None:
    assert by_rule(run("benign", catalog), "R3.") == []


# ---------------------------------------------------------------------------- finding contract


def test_every_finding_is_complete_and_evidence_backed(catalog: Catalog) -> None:
    for scenario in ("suspicious", "benign"):
        for f in run(scenario, catalog):
            assert f.rule_id and f.rule_version
            assert f.observed_facts, f.rule_id
            assert f.benign_explanations, f.rule_id
            assert f.next_queries, f.rule_id
            assert f.evidence_ids, f.rule_id
            assert set(f.evidence_ids) <= ALL_REFS, f.evidence_ids
            assert f.finding_id.startswith("fnd_")


def test_shared_role_session_is_not_attributed_to_a_human(catalog: Catalog) -> None:
    events = events_for("suspicious")
    assumed = [e for e in events if e.get("actor_type") == "AssumedRole"]
    assert assumed and all(e["actor"] == "eks-admin" and e["session"] == "svc-backup" for e in assumed)
    shared = next(i for i in catalog.identities if i.id == "eks-admin")
    assert shared.kind == "shared_role"
    fs = run_rules(events, catalog)
    assumed_keys = {e["event_key"] for e in assumed}
    # R1 never fires on the shared role (join 'exact' against a non-departed shared role is not a human claim)
    assert not any(set(f.event_keys) & assumed_keys for f in by_rule(fs, "R1."))
    humans = {i.id for i in catalog.identities if i.kind == "human"}
    for f in fs:
        if set(f.event_keys) <= assumed_keys:
            assert not any(h in f.title for h in humans), f.title


def test_rules_are_deterministic_and_deduplicated(catalog: Catalog) -> None:
    a = run("suspicious", catalog)
    b = run("suspicious", catalog)
    ids_a = [f.finding_id for f in a]
    assert ids_a == [f.finding_id for f in b]
    assert len(ids_a) == len(set(ids_a))
    # event order does not change identities either
    shuffled = run_rules(list(reversed(events_for("suspicious"))), catalog, security_findings=guardduty_for("suspicious"))
    assert sorted(f.finding_id for f in shuffled) == sorted(ids_a)


def test_alias_substring_match_yields_uncertain_join_with_lower_confidence(catalog: Catalog) -> None:
    raw = demo_audit_events("suspicious")[7]  # CreateAccessKey by carol-departed
    raw = {**raw, "eventID": "evt-alias-1", "userIdentity": {**raw["userIdentity"], "userName": "svc-carol-departed-backup", "arn": "arn:aws:iam::000000000000:user/svc-carol-departed-backup"}}
    ev = normalize_cloudtrail(raw, "demo-fake", EV_CT)
    fs = run_rules([ev], catalog)
    r1 = by_rule(fs, "R1.")
    assert len(r1) == 1
    f = r1[0]
    assert f.identity_join == "uncertain"
    assert f.severity == "medium" and f.confidence == "low"
    assert "identity join: uncertain" in f.observed_facts
    assert any("join uncertain" in b for b in f.benign_explanations)
    # exact join on the real alias is strictly stronger
    exact = next(x for x in by_rule(run("suspicious", catalog), "R1.") if x.title.endswith("CreateAccessKey"))
    assert exact.identity_join == "exact" and exact.severity == "high" and exact.confidence == "high"


def test_merge_coverage_conclusion_scope_disclaims_unavailable_scopes() -> None:
    a = Coverage(requested_sources=["x"], completed_scopes=["x/r1"], time_range_observed={"first_event": "2026-09-30T10:00:00Z", "last_event": "2026-09-30T10:10:00Z"})
    b = Coverage(requested_sources=["y"], unavailable_scopes=[UnavailableScope(source="y", reason="permission_denied")], truncated=True, pagination_complete=False, time_range_observed={"first_event": "2026-09-30T09:00:00Z", "last_event": "2026-09-30T10:05:00Z"})
    cov = merge_coverage([a, b])
    assert "no conclusion about unavailable" in cov.conclusion_scope
    assert cov.requested_sources == ["x", "y"]
    assert cov.completed_scopes == ["x/r1"]
    assert [u.source for u in cov.unavailable_scopes] == ["y"]
    assert cov.truncated is True and cov.pagination_complete is False
    assert cov.time_range_observed == {"first_event": "2026-09-30T09:00:00Z", "last_event": "2026-09-30T10:10:00Z"}
