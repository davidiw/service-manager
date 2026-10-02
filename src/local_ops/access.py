"""AWS human-access graph and onboarding/offboarding guide derived from released observations (D27).

Every statement here comes from an observed, released provider record: Identity Center instances,
permission sets, account assignments, identity-store users/groups/memberships, and IAM users, groups,
access-key metadata, roles and instance profiles. Nothing is inferred from names. A person's access is
reported only with the coverage that supports it: when the Identity Center or IAM scopes that would show
an assignment were not completely enumerated in the latest released scan, the guide says so and never
concludes that access is absent or removed.

Service roles and instance profiles are machine identities and are listed separately from human paths.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from local_ops.opsview import Snapshot


def _g(row: dict[str, Any], where: str, key: str) -> Any:
    return (row.get(where) or {}).get(key)


def _find_lists(obj: Any, key: str) -> list[Any]:
    """Collect list values stored under `key` anywhere in a released coverage projection."""
    out: list[Any] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key and isinstance(v, list):
                out.extend(v)
            else:
                out.extend(_find_lists(v, key))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_find_lists(v, key))
    return out


@dataclass
class AccessGraph:
    accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    instances: list[dict[str, Any]] = field(default_factory=list)
    permission_sets: dict[str, dict[str, Any]] = field(default_factory=dict)
    users: dict[str, dict[str, Any]] = field(default_factory=dict)
    groups: dict[str, dict[str, Any]] = field(default_factory=dict)
    members: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # group key -> user keys
    member_of: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))  # user key -> group keys
    assignments: list[dict[str, Any]] = field(default_factory=list)
    iam_users: list[dict[str, Any]] = field(default_factory=list)
    iam_groups: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    instance_profiles: list[dict[str, Any]] = field(default_factory=list)
    ic_coverage: list[dict[str, Any]] = field(default_factory=list)
    iam_coverage: dict[str, dict[str, Any]] = field(default_factory=dict)
    eks_access_entries: list[dict[str, Any]] = field(default_factory=list)

    # ------------------------------------------------------------------ build
    @classmethod
    def build(cls, snap: Snapshot) -> AccessGraph:
        g = cls()
        rows = snap.index.rows
        aws_providers = {p for p, k in snap.provider_kinds.items() if k == "aws"}
        for r in rows:
            if r["provider_id"] not in aws_providers:
                continue
            rt, ident, attrs = r["resource_type"], r.get("identity") or {}, r.get("attributes") or {}
            acct = str(ident.get("account") or "")
            if acct:
                entry = g.accounts.setdefault(acct, {"account_id": acct, "name": None, "providers": set(), "in_organization": False})
                # Only a provider whose verified account is this one (its scope keys embed it) speaks for the
                # account's IAM coverage; a management account's billing view of a member does not.
                if str(r.get("scope_key") or "").startswith(f"{r['provider_id']}/{acct}/"):
                    entry["providers"].add(r["provider_id"])
            if rt == "aws/org_account" and ident.get("account_id"):
                a = g.accounts.setdefault(str(ident["account_id"]), {"account_id": str(ident["account_id"]), "name": None, "providers": set(), "in_organization": False})
                a.update(name=ident.get("name"), in_organization=True, status=attrs.get("status"))
            elif rt == "aws/sso_instance":
                g.instances.append({"arn": r["resource_key"], "name": ident.get("name"), "identity_store_id": ident.get("identity_store_id"), "region": ident.get("region"), "owner_account_id": attrs.get("owner_account_id"), "seen_from": acct, "status": attrs.get("status")})
            elif rt == "aws/sso_permission_set":
                g.permission_sets[r["resource_key"]] = {"arn": r["resource_key"], "name": ident.get("name"), "description": attrs.get("description"), "session_duration": attrs.get("session_duration"), "managed_policies": attrs.get("managed_policies") or [], "customer_managed_policies": attrs.get("customer_managed_policies") or [], "provisioned_account_ids": attrs.get("provisioned_account_ids") or []}
            elif rt == "aws/identitystore_user":
                g.users[r["resource_key"]] = {"key": r["resource_key"], "user_id": ident.get("user_id"), "user_name": ident.get("user_name"), "display_name": attrs.get("display_name"), "external_id_issuers": attrs.get("external_id_issuers"), "identity_store_id": ident.get("identity_store_id")}
            elif rt == "aws/identitystore_group":
                g.groups[r["resource_key"]] = {"key": r["resource_key"], "group_id": ident.get("group_id"), "name": ident.get("name"), "description": attrs.get("description"), "members_complete": attrs.get("members_complete"), "external_id_issuers": attrs.get("external_id_issuers"), "identity_store_id": ident.get("identity_store_id")}
            elif rt == "aws/identitystore_group_membership":
                rels = {x.get("kind"): x.get("target") for x in attrs.get("relationships") or []}
                if rels.get("member") and rels.get("group"):
                    g.members[str(rels["group"])].add(str(rels["member"]))
                    g.member_of[str(rels["member"])].add(str(rels["group"]))
            elif rt == "aws/sso_account_assignment":
                principal = next((x.get("target") for x in attrs.get("relationships") or [] if x.get("kind") == "assigns"), None)
                g.assignments.append({"key": r["resource_key"], "target_account_id": str(ident.get("target_account_id")), "permission_set_arn": ident.get("permission_set_arn"), "permission_set_name": attrs.get("permission_set_name"), "principal_type": ident.get("principal_type"), "principal_id": ident.get("principal_id"), "principal_key": principal})
            elif rt == "aws/iam_user":
                keys = attrs.get("access_keys") or []
                ssc = attrs.get("service_specific_credentials") or []
                g.iam_users.append({"arn": r["resource_key"], "account": acct, "name": ident.get("name"), "created_at": attrs.get("created_at"), "password_last_used": attrs.get("password_last_used"), "console_access_observed": bool(attrs.get("password_last_used")), "access_keys": keys, "active_access_keys": sum(1 for k in keys if k.get("status") == "Active"), "service_specific_credentials": ssc, "active_service_specific_credentials": [c for c in ssc if c.get("status") == "Active"], "group_names": attrs.get("group_names") or [], "attached_policies": attrs.get("attached_policies") or [], "inline_policy_names": attrs.get("inline_policy_names") or [], "access_keys_inspected": attrs.get("access_keys_inspected"), "service_specific_credentials_inspected": attrs.get("service_specific_credentials_inspected")})
            elif rt == "aws/iam_group":
                g.iam_groups.append({"arn": r["resource_key"], "account": acct, "name": ident.get("name"), "member_user_names": attrs.get("member_user_names") or [], "attached_policies": attrs.get("attached_policies") or [], "inline_policy_names": attrs.get("inline_policy_names") or []})
            elif rt == "aws/iam_role":
                g.roles.append({"arn": r["resource_key"], "account": acct, "name": ident.get("name"), "role_class": attrs.get("role_class") or "unclassified", "trust_principals": attrs.get("trust_principals") or {}, "last_used_at": attrs.get("last_used_at"), "attached_policies": attrs.get("attached_policies") or []})
            elif rt == "aws/iam_instance_profile":
                g.instance_profiles.append({"arn": r["resource_key"], "account": acct, "name": ident.get("name"), "role_arns": attrs.get("role_arns") or []})
            elif rt == "aws/eks_access_entry":
                principal = next((x.get("target") for x in attrs.get("relationships") or [] if x.get("kind") == "principal"), None)
                g.eks_access_entries.append({"key": r["resource_key"], "account": acct, "region": ident.get("region"), "cluster": ident.get("cluster"), "principal_arn": principal or ident.get("principal_arn"), "kubernetes_groups": attrs.get("kubernetes_groups") or [], "username": attrs.get("username"), "permission_set_name": attrs.get("permission_set_name"), "access_scope_types": attrs.get("access_scope_types") or []})
        for a in g.accounts.values():
            a["providers"] = sorted(a["providers"])
        # Every account in an organization can list the organization instance; keep one record per instance,
        # describing it from its owner (management) account when that view was observed.
        by_arn: dict[str, dict[str, Any]] = {}
        for inst in g.instances:
            cur = by_arn.get(inst["arn"])
            if cur is None or (inst.get("seen_from") == inst.get("owner_account_id") and cur.get("seen_from") != cur.get("owner_account_id")):
                by_arn[inst["arn"]] = inst
        g.instances = list(by_arn.values())
        for res in snap.released_results:
            for entry in _find_lists(res.get("aws_coverage"), "identity_center"):
                if isinstance(entry, dict):
                    g.ic_coverage.append({**entry, "scan_request_id": res["request_id"], "finished_at": res.get("finished_at")})
        for acct, a in g.accounts.items():
            statuses = {}
            for pid in a["providers"]:
                for child in ("", "/access_keys", "/groups", "/policy_refs", "/instance_profiles", "/service_specific_credentials"):
                    statuses[child.lstrip("/") or "users_roles"] = snap.coverage.status(pid, f"{pid}/{acct}/global/iam{child}")["status"]
            g.iam_coverage[acct] = statuses
        return g

    # ------------------------------------------------------------------ coverage
    def latest_ic_coverage(self) -> list[dict[str, Any]]:
        """Latest released Identity Center coverage entry per (account, region)."""
        latest: dict[tuple[str, str], dict[str, Any]] = {}
        for e in sorted(self.ic_coverage, key=lambda x: str(x.get("finished_at") or "")):
            latest[(str(e.get("account")), str(e.get("region")))] = e
        return list(latest.values())

    @staticmethod
    def _entry_complete(e: dict[str, Any]) -> bool:
        return e.get("status") == "complete" and all(v == "complete" for v in (e.get("child_scopes") or {}).values())

    def instance_coverage(self) -> dict[str, dict[str, Any]]:
        """Per Identity Center instance: the account/region view that completed every listing, if any.

        All member accounts of an organization can see the organization instance, but only its management
        or delegated-administrator account can list permission sets and assignments. One complete view of
        an instance is complete coverage of it; partial member-account views do not reduce that."""
        out: dict[str, dict[str, Any]] = {}
        for e in self.latest_ic_coverage():
            for arn in e.get("instances") or []:
                cur = out.setdefault(arn, {"instance_arn": arn, "complete_view": None, "partial_views": []})
                if self._entry_complete(e):
                    cur["complete_view"] = {"account": e.get("account"), "region": e.get("region"), "scan_request_id": e.get("scan_request_id"), "finished_at": e.get("finished_at")}
                else:
                    cur["partial_views"].append({"account": e.get("account"), "region": e.get("region"), "status": e.get("status"), "child_scopes": e.get("child_scopes") or {}})
        return out

    def ic_complete(self) -> bool:
        """True only when at least one instance was observed and every observed instance has a view whose
        instance, permission-set, assignment, user, group and membership listings all completed in the
        latest released scan from that account/region."""
        inst = self.instance_coverage()
        return bool(inst) and all(v["complete_view"] for v in inst.values())

    def coverage_summary(self) -> dict[str, Any]:
        entries = self.latest_ic_coverage()
        inst = self.instance_coverage()
        warnings = []
        notes = []
        if not entries:
            warnings.append("No released scan reported Identity Center coverage. Whether Identity Center is used, and who it grants access to, is unknown.")
        elif not inst:
            warnings.append("No Identity Center instance was observed from any scanned account/region. An organization instance is only fully listable from its management or delegated-administrator account in its home region; this is not evidence that Identity Center is unused.")
        for e in entries:
            if not e.get("instances") and e.get("status") not in ("complete", "no_instance_in_this_account_region"):
                warnings.append(f"Identity Center listing in {e.get('account')}/{e.get('region')} is {e.get('status')}: {e.get('note') or ''}".strip())
        for arn, v in sorted(inst.items()):
            if v["complete_view"]:
                cv = v["complete_view"]
                notes.append(f"Identity Center instance {arn} is completely listed from account {cv['account']} ({cv['region']}).")
                if v["partial_views"]:
                    notes.append(f"{len(v['partial_views'])} other accounts can see {arn} but cannot list its permission sets/assignments; that is expected for member accounts and does not reduce coverage.")
            else:
                for pv in v["partial_views"]:
                    bad = ", ".join(f"{k}={s}" for k, s in sorted(pv["child_scopes"].items()) if s != "complete") or pv["status"]
                    warnings.append(f"Identity Center instance {arn} has no complete view; from {pv['account']}/{pv['region']}: {bad}. Assignments not shown may still exist.")
        for acct, st in sorted(self.iam_coverage.items()):
            bad = {k: v for k, v in st.items() if v != "complete"}
            if bad:
                warnings.append(f"IAM in account {acct}: " + ", ".join(f"{k}={v}" for k, v in sorted(bad.items())))
        return {"identity_center": entries, "instances": inst, "identity_center_complete": self.ic_complete(), "iam": self.iam_coverage, "warnings": warnings, "notes": notes}

    # ------------------------------------------------------------------ queries
    def account_name(self, acct: str) -> str | None:
        return (self.accounts.get(acct) or {}).get("name")

    def _principal_label(self, a: dict[str, Any]) -> str:
        key = a.get("principal_key") or ""
        if a.get("principal_type") == "GROUP":
            grp = self.groups.get(key)
            return f"group {grp['name']}" if grp else f"group {a.get('principal_id')} (not in released identity-store listing)"
        usr = self.users.get(key)
        return f"user {usr['user_name']}" if usr else f"user {a.get('principal_id')} (not in released identity-store listing)"

    def account_access(self, acct: str) -> dict[str, Any]:
        by_ps: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in self.assignments:
            if a["target_account_id"] == acct:
                members = sorted(self.users[u]["user_name"] for u in self.members.get(a.get("principal_key") or "", set()) if u in self.users) if a.get("principal_type") == "GROUP" else []
                by_ps[a.get("permission_set_name") or str(a.get("permission_set_arn"))].append({"principal": self._principal_label(a), "principal_type": a.get("principal_type"), "group_members": members})
        roles = [r for r in self.roles if r["account"] == acct]
        return {
            "account_id": acct, "account_name": self.account_name(acct),
            "identity_center": [{"permission_set": k, "principals": v} for k, v in sorted(by_ps.items())],
            "iam_users": [u for u in self.iam_users if u["account"] == acct],
            "iam_groups": [x for x in self.iam_groups if x["account"] == acct],
            "roles_by_class": {c: sum(1 for r in roles if r["role_class"] == c) for c in sorted({r["role_class"] for r in roles})},
            "assumable_standard_roles": [r for r in roles if r["role_class"] == "standard" and ((r["trust_principals"].get("aws") or []) or (r["trust_principals"].get("federated") or []))],
            "coverage": self.iam_coverage.get(acct, {}),
        }

    def eks_clusters_for_permission_set(self, permission_set_name: str | None, account_id: str) -> list[dict[str, Any]]:
        """EKS clusters reachable from a specific account through an Identity Center permission set,
        matched only by the permission-set name AWS encodes into its reserved
        `AWSReservedSSO_<permission set>_<suffix>` role name and by the account that observed the
        access entry; never a guess from any other field."""
        if not permission_set_name:
            return []
        return [{"cluster": e["cluster"], "kubernetes_groups": e["kubernetes_groups"], "username": e["username"]} for e in self.eks_access_entries if e.get("permission_set_name") == permission_set_name and e.get("account") == account_id]

    def eks_access_by_permission_set(self) -> dict[str, list[str]]:
        """Every permission set observed to reach an EKS cluster through an access entry, and which
        clusters, independent of any specific person."""
        out: dict[str, set[str]] = defaultdict(set)
        for e in self.eks_access_entries:
            if e.get("permission_set_name"):
                out[str(e["permission_set_name"])].add(str(e["cluster"]))
        return {k: sorted(v) for k, v in sorted(out.items())}

    def effective_assignments(self, user_key: str) -> list[dict[str, Any]]:
        out = []
        groups = self.member_of.get(user_key, set())
        for a in self.assignments:
            pk = a.get("principal_key")
            if a.get("principal_type") == "USER" and pk == user_key:
                via = "direct assignment"
            elif a.get("principal_type") == "GROUP" and pk in groups:
                grp = self.groups.get(pk or "")
                via = f"group {grp['name'] if grp else pk}"
            else:
                continue
            out.append({"account_id": a["target_account_id"], "account_name": self.account_name(a["target_account_id"]), "permission_set": a.get("permission_set_name"), "via": via, "assignment_key": a["key"], "group_key": pk if a.get("principal_type") == "GROUP" else None, "eks_clusters": self.eks_clusters_for_permission_set(a.get("permission_set_name"), a["target_account_id"])})
        return sorted(out, key=lambda x: (x["account_name"] or x["account_id"], x["permission_set"] or ""))

    def find_person(self, query: str, aliases: list[str] | None = None) -> dict[str, Any]:
        """Exact (case-insensitive) match on Identity Center user name/display name/user id and IAM user name,
        plus catalog identity aliases. No partial or fuzzy matching."""
        names = {query.strip().lower()} | {a.strip().lower() for a in aliases or [] if a.strip()}
        users = [u for u in self.users.values() if {str(u.get("user_name") or "").lower(), str(u.get("display_name") or "").lower(), str(u.get("user_id") or "").lower()} & names]
        iam = [u for u in self.iam_users if str(u.get("name") or "").lower() in names or str(u.get("arn") or "").lower() in names]
        return {
            "query": query, "matched_names": sorted(names),
            "identity_center_users": [{**u, "groups": sorted(self.groups[gk]["name"] for gk in self.member_of.get(u["key"], set()) if gk in self.groups), "group_keys": sorted(self.member_of.get(u["key"], set())), "effective_access": self.effective_assignments(u["key"])} for u in users],
            "iam_users": iam,
        }

    # ------------------------------------------------------------------ guide
    def access_model(self) -> dict[str, Any]:
        group_assignments = [a for a in self.assignments if a.get("principal_type") == "GROUP"]
        user_assignments = [a for a in self.assignments if a.get("principal_type") == "USER"]
        group_paths: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for a in group_assignments:
            grp = self.groups.get(a.get("principal_key") or "")
            group_paths[grp["name"] if grp else str(a.get("principal_id"))].append({"permission_set": a.get("permission_set_name"), "account_id": a["target_account_id"], "account_name": self.account_name(a["target_account_id"])})
        issuers = sorted({i for u in self.users.values() for i in (u.get("external_id_issuers") or [])})
        iam_human_like = [u for u in self.iam_users if u["console_access_observed"]]
        iam_with_keys = [u for u in self.iam_users if u["active_access_keys"]]
        return {
            "instances": self.instances,
            "external_identity_sources": issuers,
            "group_assignment_count": len(group_assignments), "direct_user_assignment_count": len(user_assignments),
            "group_paths": {k: sorted(v, key=lambda x: (x["account_name"] or x["account_id"], x["permission_set"] or "")) for k, v in sorted(group_paths.items())},
            "direct_user_assignments": [{"user": self._principal_label(a), "permission_set": a.get("permission_set_name"), "account_id": a["target_account_id"], "account_name": self.account_name(a["target_account_id"])} for a in user_assignments],
            "permission_sets": sorted(self.permission_sets.values(), key=lambda p: str(p.get("name"))),
            "iam_users_with_console_use": iam_human_like, "iam_users_with_active_keys": iam_with_keys,
            "accounts": sorted(self.accounts.values(), key=lambda a: str(a.get("name") or a["account_id"])),
        }

    def onboarding(self) -> dict[str, Any]:
        m = self.access_model()
        cov = self.coverage_summary()
        steps: list[str] = []
        if m["instances"]:
            inst = m["instances"][0]
            steps.append(f"Identity Center instance {inst.get('name') or inst['arn']} (identity store {inst.get('identity_store_id')}, region {inst.get('region')}, administered from account {inst.get('owner_account_id') or inst.get('seen_from')}) is the observed human access path.")
            if m["external_identity_sources"]:
                steps.append("Users and groups carry external identifiers from: " + ", ".join(m["external_identity_sources"]) + ". Create the person in that identity source and let provisioning sync them; do not create them directly in the identity store.")
            else:
                steps.append("No external identity-source identifiers were observed on identity-store users; users appear to be created directly in the identity store (verify before relying on this).")
            if m["group_paths"]:
                steps.append("Access is granted through group assignments. Add the person to the group whose observed path matches the access they need:")
                for grp, paths in m["group_paths"].items():
                    steps.append(f"  - {grp}: " + "; ".join(f"{p['permission_set']} on {p['account_name'] or p['account_id']}" for p in paths))
            if m["direct_user_assignments"]:
                steps.append(f"{len(m['direct_user_assignments'])} direct user assignments also exist (user -> permission set -> account). Prefer the group path unless a direct assignment is intended.")
            eks_by_ps = self.eks_access_by_permission_set()
            if eks_by_ps:
                steps.append("Kubernetes access via EKS access entries: holding one of these permission sets also reaches the listed clusters through an EKS access entry for the matching AWSReservedSSO role:")
                for ps, clusters in eks_by_ps.items():
                    steps.append(f"  - {ps}: {', '.join(clusters)}")
        else:
            steps.append("No Identity Center instance is observed. Human access cannot be described from Identity Center data.")
        if m["iam_users_with_console_use"]:
            steps.append(f"{len(m['iam_users_with_console_use'])} IAM users have observed console sign-in. These are a legacy/direct path; do not create new IAM users for people unless that is an intended exception.")
        verify = [
            "The person signs in to the AWS access portal and sees the expected accounts and permission sets.",
            "For each expected account/permission set, a read-only identity check returns that account and an assumed role named AWSReservedSSO_<permission set>_<suffix>: `aws sts get-caller-identity --profile <profile for that account and permission set>`.",
            "Run a discovery scan of the Identity Center account and confirm the new membership/assignment appears with complete coverage on this page.",
        ]
        return {"model": m, "steps": steps, "verify": verify, "coverage": cov}

    def offboarding(self, person: dict[str, Any] | None, credential_refs: list[dict[str, Any]], onepassword_vaults: list[str]) -> dict[str, Any]:
        cov = self.coverage_summary()
        items: list[dict[str, Any]] = []
        if person:
            for u in person["identity_center_users"]:
                for gkey in u["group_keys"]:
                    gname = self.groups[gkey]["name"] if gkey in self.groups else f"{gkey} (group not in released listing)"
                    grants = sorted({f"{a['permission_set']} on {a['account_name'] or a['account_id']}" + (f" (also reaches EKS cluster(s) {', '.join(c['cluster'] for c in a['eks_clusters'])} via access entry)" if a.get("eks_clusters") else "") for a in u["effective_access"] if a.get("group_key") == gkey})
                    items.append({"kind": "identity_center_group_membership", "action": f"Remove {u['user_name']} from group {gname}", "effect": grants or ["no assignment observed for this group"], "evidence": gkey})
                for a in u["effective_access"]:
                    if a["via"] == "direct assignment":
                        eks_note = f" (also reaches EKS cluster(s) {', '.join(c['cluster'] for c in a['eks_clusters'])} via access entry)" if a.get("eks_clusters") else ""
                        items.append({"kind": "identity_center_direct_assignment", "action": f"Remove direct assignment {a['permission_set']} on {a['account_name'] or a['account_id']} from {u['user_name']}{eks_note}", "evidence": a["assignment_key"]})
                src = u.get("external_id_issuers") or []
                items.append({"kind": "identity_center_user", "action": f"Disable/remove identity-store user {u['user_name']}" + (f" in its source ({', '.join(src)}); provisioning removes it downstream" if src else ""), "evidence": u["key"]})
            for iu in person["iam_users"]:
                items.append({"kind": "iam_user", "action": f"Remove IAM user {iu['name']} in account {iu['account']} (console sign-in observed: {iu['console_access_observed']})", "evidence": iu["arn"]})
                for k in iu["access_keys"] or []:
                    items.append({"kind": "access_key", "action": f"Deactivate then delete access key ...{k.get('access_key_suffix')} ({k.get('status')}, last used {k.get('last_used_at') or 'never/unknown'})", "evidence": iu["arn"]})
                for c in iu["service_specific_credentials"] or []:
                    items.append({"kind": "service_specific_credential", "action": f"Deactivate then delete {c.get('service_name')} service-specific credential ...{c.get('credential_id_suffix')} ({c.get('status')}, created {c.get('created_at') or 'unknown'})", "evidence": iu["arn"]})
                for gname in iu["group_names"]:
                    items.append({"kind": "iam_group_membership", "action": f"Remove IAM user {iu['name']} from IAM group {gname}", "evidence": iu["arn"]})
        follow_up = [f"Catalog credential reference {c.get('id')} ({c.get('kind')}, held in {c.get('held_in')}) may be known to this person; rotate if they had access." for c in credential_refs]
        if onepassword_vaults:
            follow_up.append("1Password vault membership is not observed by this server. Review the person's access to these observed vaults separately: " + ", ".join(onepassword_vaults))
        verify = ["Run a discovery scan of every Identity Center and IAM scope listed in the coverage section; only a scan whose relevant scopes are all complete can show that no assignment remains.", "Re-open this page for the person and confirm no effective access is listed AND coverage is complete."]
        limits = []
        if not self.ic_complete():
            limits.append("Identity Center coverage is incomplete: assignments not shown here may still exist. This checklist cannot establish that access is removed.")
        if person is not None and not person["identity_center_users"] and not person["iam_users"]:
            limits.append("No observed identity matched exactly. That is not evidence that the person has no access: check the exact user name, catalog identity aliases, and coverage.")
        return {"checklist": items, "follow_up": follow_up, "verify": verify, "limits": limits, "coverage": cov}

    def machine_identities(self) -> dict[str, Any]:
        roles = [r for r in self.roles if r["role_class"] in ("service_linked",) or (r["role_class"] == "standard" and (r["trust_principals"].get("services") or []) and not (r["trust_principals"].get("aws") or []) and not (r["trust_principals"].get("federated") or []))]
        keys_without_console = [u for u in self.iam_users if u["active_access_keys"] and not u["console_access_observed"]]
        return {"service_roles": roles, "instance_profiles": self.instance_profiles, "iam_users_with_keys_and_no_observed_console_use": keys_without_console, "note": "IAM users with access keys and no observed console sign-in may be people or automation; the provider data does not say which."}


def guide_markdown(onboard: dict[str, Any], offboard: dict[str, Any], person_query: str | None) -> str:
    lines = ["# AWS access: onboarding and offboarding (generated from observed configuration)", ""]
    cov = onboard["coverage"]
    lines.append("## Coverage")
    lines.append(f"- Identity Center coverage complete: **{cov['identity_center_complete']}**")
    for w in cov["warnings"]:
        lines.append(f"- WARNING: {w}")
    lines.append("")
    lines.append("## How a person receives AWS access (observed path)")
    lines += [f"{i}. {s}" if not s.startswith("  ") else s for i, s in enumerate(onboard["steps"], 1)]
    lines.append("")
    lines.append("### Verify")
    lines += [f"- {v}" for v in onboard["verify"]]
    lines.append("")
    lines.append("## How a person loses AWS access" + (f" (for `{person_query}`)" if person_query else " (template)"))
    for lim in offboard["limits"]:
        lines.append(f"- LIMIT: {lim}")
    for it in offboard["checklist"]:
        lines.append(f"- [ ] {it['action']}" + (f" — grants: {'; '.join(it['effect'])}" if it.get("effect") else ""))
    if not offboard["checklist"]:
        lines.append("- Look the person up to produce their exact checklist. In general: remove group memberships, remove direct assignments, disable the identity-store user at its source, remove IAM users and access keys in each account.")
    lines.append("")
    lines.append("### Separate follow-up")
    lines += [f"- {f}" for f in offboard["follow_up"]] or ["- none recorded"]
    lines.append("")
    lines.append("### Verify")
    lines += [f"- {v}" for v in offboard["verify"]]
    lines.append("")
    return "\n".join(lines)
