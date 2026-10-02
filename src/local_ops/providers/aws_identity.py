"""AWS IAM Identity Center (SSO) and Identity Store census.

This module is deliberately called by :class:`AwsAdapter`, in the same style as
``aws_data.py``/``aws_edge.py``: it uses the adapter's canonical client, pagination,
evidence, and observation paths and never requests policy documents, credential
values, or Identity Store contact/address fields (email, phone, address, name
sub-fields). Only ``user_id``, ``user_name`` and ``display_name`` are kept for a
user; only ``group_id``, ``name`` and ``description`` for a group.

An inaccessible Identity Center API is reported `unavailable`, never "no Identity
Center": an empty ``ListInstances`` result is complete-with-zero-instances for that
account/region only, since an organization instance is visible only from its
management or delegated-administrator account.
"""

from __future__ import annotations

from typing import Any


def _ts(value: Any) -> Any:
    from local_ops.providers.aws import _ts as _real_ts

    return _real_ts(value)


def _external_id_issuers(external_ids: Any) -> list[str]:
    """Keep only the issuer strings of SCIM-provisioned external ids; never the id values."""
    issuers = {str(e.get("Issuer")) for e in (external_ids or []) if isinstance(e, dict) and e.get("Issuer")}
    return sorted(issuers)


async def _child_failure(adapter: Any, report: Any, scope_key: str, operation: str, exc: BaseException) -> None:
    from local_ops.providers.aws import _AwsCallError, classify_boto_error

    if isinstance(exc, _AwsCallError):
        reason, detail = classify_boto_error(exc.exc)
        operation = exc.operation
    else:
        reason, detail = classify_boto_error(exc)
    report.unavailable.append({"source": scope_key, "reason": reason, "operation": operation, "detail": detail})


async def _paginated(adapter: Any, client: Any, operation: str, result_key: str, ctx: Any, budget: Any, report: Any, scope_key: str, **kwargs: Any) -> tuple[list[Any], bool]:
    try:
        return await adapter._paginate(client, operation, result_key, ctx, budget, **kwargs)
    except Exception as exc:  # adapter normalizes provider exceptions
        from local_ops.models import ErrorCode, OpsError

        if isinstance(exc, OpsError) and exc.code == ErrorCode.LIMIT_REACHED:
            raise
        await _child_failure(adapter, report, scope_key, operation, exc)
        return [], False


async def discover(adapter: Any, family: str, ctx: Any, budget: Any, report: Any, scope: Any, account: str, region: str, regions: list[str]) -> bool:
    """Discover the Identity Center (SSO) instance(s) visible from this account/region."""
    scope_key = adapter._fkey(account, region, family)
    coverage: dict[str, Any] = {"account": account, "region": region, "status": "unavailable", "instances": [], "child_scopes": {}, "note": None}
    try:
        async with adapter._client("sso-admin", region) as sso:
            instances, complete = await adapter._paginate(sso, "list_instances", "Instances", ctx, budget)
    except Exception:
        report.aws_coverage.setdefault("identity_center", []).append(coverage)
        raise

    eid = await adapter._evidence(ctx, account, region, "identitycenter", {"instances": instances}, f"{len(instances)} Identity Center instances in {region}")
    for inst in instances:
        arn = str(inst.get("InstanceArn"))
        instance_id = arn.rsplit("/", 1)[-1]
        report.observations.append(adapter._obs(arn, "aws/sso_instance", {"account": account, "region": region, "arn": arn, "instance_id": instance_id, "identity_store_id": inst.get("IdentityStoreId"), "name": inst.get("Name")}, {"owner_account_id": inst.get("OwnerAccountId"), "status": inst.get("Status"), "created_at": _ts(inst.get("CreatedDate"))}, scope_key, eid))

    if not instances:
        status = "no_instance_in_this_account_region" if complete else "unavailable"
        coverage.update(status=status, instances=[], child_scopes={}, note="No Identity Center instance is visible from this account/region; an organization instance is only visible from its management or delegated-administrator account, in the Identity Center home region.")
        report.aws_coverage.setdefault("identity_center", []).append(coverage)
        return complete

    overall_complete = complete
    merged_children: dict[str, str] = {}
    async with adapter._client("sso-admin", region) as sso, adapter._client("identitystore", region) as idstore:
        for inst in instances:
            instance_arn = str(inst.get("InstanceArn"))
            instance_id = instance_arn.rsplit("/", 1)[-1]
            identity_store_id = str(inst.get("IdentityStoreId"))
            child_status: dict[str, str] = {}

            pset_scope = f"{scope_key}/{instance_id}/permission_sets"
            pset_ok = await _permission_sets(adapter, ctx, budget, report, account, region, sso, instance_arn, instance_id, pset_scope)
            child_status["permission_sets"] = "complete" if pset_ok else "partial"
            overall_complete = overall_complete and pset_ok

            assignments_scope = f"{scope_key}/{instance_id}/assignments"
            assignments_ok = await _assignments(adapter, ctx, budget, report, account, region, sso, instance_arn, instance_id, identity_store_id, assignments_scope)
            child_status["assignments"] = "complete" if assignments_ok else "partial"
            overall_complete = overall_complete and assignments_ok

            users_scope = f"{scope_key}/{instance_id}/users"
            users_ok = await _users(adapter, ctx, budget, report, account, region, idstore, identity_store_id, users_scope)
            child_status["users"] = "complete" if users_ok else "partial"
            overall_complete = overall_complete and users_ok

            groups_scope = f"{scope_key}/{instance_id}/groups"
            memberships_scope = f"{scope_key}/{instance_id}/memberships"
            groups_ok, memberships_ok = await _groups_and_memberships(adapter, ctx, budget, report, account, region, idstore, identity_store_id, groups_scope, memberships_scope)
            child_status["groups"] = "complete" if groups_ok else "partial"
            child_status["memberships"] = "complete" if memberships_ok else "partial"
            overall_complete = overall_complete and groups_ok and memberships_ok

            for key, status in child_status.items():
                if merged_children.get(key) in (None, "complete"):
                    merged_children[key] = status

            (report.completed_scopes if (pset_ok and adapter._approved) else report.partial_scopes).append(pset_scope)
            (report.completed_scopes if (assignments_ok and adapter._approved) else report.partial_scopes).append(assignments_scope)
            (report.completed_scopes if (users_ok and adapter._approved) else report.partial_scopes).append(users_scope)
            (report.completed_scopes if (groups_ok and adapter._approved) else report.partial_scopes).append(groups_scope)
            (report.completed_scopes if (memberships_ok and adapter._approved) else report.partial_scopes).append(memberships_scope)

    coverage.update(status="complete" if overall_complete else "partial", instances=[str(i.get("InstanceArn")) for i in instances], child_scopes=merged_children, note=None)
    report.aws_coverage.setdefault("identity_center", []).append(coverage)
    return overall_complete


async def _permission_sets(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, sso: Any, instance_arn: str, instance_id: str, scope_key: str) -> bool:
    arns, complete = await _paginated(adapter, sso, "list_permission_sets", "PermissionSets", ctx, budget, report, scope_key, InstanceArn=instance_arn)

    async def describe(arn: str) -> tuple[dict[str, Any], bool]:
        budget.check()
        ok = True
        try:
            detail = (await adapter._call(sso, "describe_permission_set", InstanceArn=instance_arn, PermissionSetArn=arn)).get("PermissionSet") or {}
        except Exception as exc:
            from local_ops.models import ErrorCode, OpsError

            if isinstance(exc, OpsError) and exc.code == ErrorCode.LIMIT_REACHED:
                raise
            await _child_failure(adapter, report, scope_key, "describe_permission_set", exc)
            detail, ok = {}, False
        managed, managed_ok = await _paginated(adapter, sso, "list_managed_policies_in_permission_set", "AttachedManagedPolicies", ctx, budget, report, scope_key, InstanceArn=instance_arn, PermissionSetArn=arn)
        custom, custom_ok = await _paginated(adapter, sso, "list_customer_managed_policy_references_in_permission_set", "CustomerManagedPolicyReferences", ctx, budget, report, scope_key, InstanceArn=instance_arn, PermissionSetArn=arn)
        accounts, accounts_ok = await _paginated(adapter, sso, "list_accounts_for_provisioned_permission_set", "AccountIds", ctx, budget, report, scope_key, InstanceArn=instance_arn, PermissionSetArn=arn)
        row = {"arn": arn, "name": detail.get("Name"), "description": detail.get("Description"), "session_duration": detail.get("SessionDuration"), "created_at": _ts(detail.get("CreatedDate")), "managed_policies": [{"name": m.get("Name"), "arn": m.get("Arn")} for m in managed], "customer_managed_policies": [{"name": c.get("Name"), "path": c.get("Path")} for c in custom], "provisioned_account_ids": sorted(str(a) for a in accounts)}
        return row, ok and managed_ok and custom_ok and accounts_ok

    results = await adapter._bounded_map(arns, describe)
    all_ok = complete and all(ok for _, ok in results)
    psets = [{**r, "policy_refs_complete": ok} for r, ok in results]
    pset_eid = await adapter._evidence(ctx, account, region, "identitycenter_permission_sets", {"permission_sets": psets}, f"{len(psets)} Identity Center permission sets for {instance_id}")
    for row, ok in results:
        arn = str(row["arn"])
        rels = [{"kind": "member_of", "target": instance_arn}] + [{"kind": "grants_access_to", "target": f"aws:account:{acct}"} for acct in row["provisioned_account_ids"]]
        report.observations.append(adapter._obs(arn, "aws/sso_permission_set", {"account": account, "region": region, "arn": arn, "name": row.get("name"), "instance_arn": instance_arn}, {"description": row.get("description"), "session_duration": row.get("session_duration"), "created_at": row.get("created_at"), "managed_policies": row["managed_policies"], "customer_managed_policies": row["customer_managed_policies"], "provisioned_account_ids": row["provisioned_account_ids"], "policy_refs_complete": ok}, scope_key, pset_eid, rels))
    return all_ok


async def _assignments(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, sso: Any, instance_arn: str, instance_id: str, identity_store_id: str, scope_key: str) -> bool:
    # Re-list permission sets and their provisioned accounts; this scope is independent of
    # (and does not borrow completeness from) the permission_sets child scope.
    arns, complete = await _paginated(adapter, sso, "list_permission_sets", "PermissionSets", ctx, budget, report, scope_key, InstanceArn=instance_arn)
    pset_names: dict[str, str] = {}

    async def pairs(arn: str) -> list[tuple[str, str]]:
        budget.check()
        try:
            detail = (await adapter._call(sso, "describe_permission_set", InstanceArn=instance_arn, PermissionSetArn=arn)).get("PermissionSet") or {}
            pset_names[arn] = str(detail.get("Name") or "")
        except Exception:
            pset_names[arn] = ""
        accounts, ok = await _paginated(adapter, sso, "list_accounts_for_provisioned_permission_set", "AccountIds", ctx, budget, report, scope_key, InstanceArn=instance_arn, PermissionSetArn=arn)
        nonlocal complete
        complete = complete and ok
        return [(arn, str(acct)) for acct in accounts]

    pair_lists = await adapter._bounded_map(arns, pairs)
    work = [p for lst in pair_lists for p in lst]

    async def assignments_for(pair: tuple[str, str]) -> tuple[str, str, list[dict[str, Any]], bool]:
        pset_arn, target_account = pair
        budget.check()
        found, ok = await _paginated(adapter, sso, "list_account_assignments", "AccountAssignments", ctx, budget, report, scope_key, InstanceArn=instance_arn, AccountId=target_account, PermissionSetArn=pset_arn)
        return pset_arn, target_account, found, ok

    rows = await adapter._bounded_map(work, assignments_for)
    all_ok = complete and all(ok for *_, ok in rows)
    projected = [{"permission_set_arn": pset_arn, "target_account": target_account, "principal_type": a.get("PrincipalType"), "principal_id": a.get("PrincipalId")} for pset_arn, target_account, found, _ in rows for a in found]
    assignments_eid = await adapter._evidence(ctx, account, region, "identitycenter_assignments", {"assignments": projected}, f"{len(projected)} Identity Center account assignments for {instance_id}")
    for pset_arn, target_account, found, _ in rows:
        for a in found:
            principal_type = str(a.get("PrincipalType") or "")
            principal_id = str(a.get("PrincipalId") or "")
            principal_key = f"identitystore:{identity_store_id}:{'user' if principal_type == 'USER' else 'group'}:{principal_id}"
            key = f"sso:{instance_id}:assignment:{target_account}:{pset_arn}:{principal_type}:{principal_id}"
            rels = [{"kind": "assigns", "target": principal_key}, {"kind": "grants_permission_set", "target": pset_arn}, {"kind": "grants_access_to", "target": f"aws:account:{target_account}"}]
            report.observations.append(adapter._obs(key, "aws/sso_account_assignment", {"account": account, "region": region, "instance_arn": instance_arn, "target_account_id": target_account, "permission_set_arn": pset_arn, "principal_type": principal_type, "principal_id": principal_id}, {"permission_set_name": pset_names.get(pset_arn)}, scope_key, assignments_eid, rels))
    return all_ok


async def _users(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, idstore: Any, identity_store_id: str, scope_key: str) -> bool:
    users, ok = await _paginated(adapter, idstore, "list_users", "Users", ctx, budget, report, scope_key, IdentityStoreId=identity_store_id)
    projected = [{"user_id": u.get("UserId"), "user_name": u.get("UserName"), "display_name": u.get("DisplayName"), "external_id_issuers": _external_id_issuers(u.get("ExternalIds"))} for u in users]
    users_eid = await adapter._evidence(ctx, account, region, "identitycenter_users", {"users": projected}, f"{len(projected)} Identity Store users for {identity_store_id}")
    for u in projected:
        key = f"identitystore:{identity_store_id}:user:{u['user_id']}"
        report.observations.append(adapter._obs(key, "aws/identitystore_user", {"account": account, "region": region, "identity_store_id": identity_store_id, "user_id": u.get("user_id"), "user_name": u.get("user_name")}, {"display_name": u.get("display_name"), "external_id_issuers": u.get("external_id_issuers") or []}, scope_key, users_eid))
    return ok


async def _groups_and_memberships(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, idstore: Any, identity_store_id: str, groups_scope_key: str, memberships_scope_key: str) -> tuple[bool, bool]:
    groups, groups_ok = await _paginated(adapter, idstore, "list_groups", "Groups", ctx, budget, report, groups_scope_key, IdentityStoreId=identity_store_id)

    async def memberships_for(g: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
        gid = str(g.get("GroupId"))
        budget.check()
        found, ok = await _paginated(adapter, idstore, "list_group_memberships", "GroupMemberships", ctx, budget, report, memberships_scope_key, IdentityStoreId=identity_store_id, GroupId=gid)
        return gid, found, ok

    results = await adapter._bounded_map(groups, memberships_for)
    memberships_by_group = {gid: (found, ok) for gid, found, ok in results}
    memberships_ok = all(ok for _, _, ok in results)

    all_memberships = [m for _, found, _ in results for m in found]
    groups_eid = await adapter._evidence(ctx, account, region, "identitycenter_groups", {"groups": [{"group_id": g.get("GroupId"), "display_name": g.get("DisplayName"), "description": g.get("Description"), "external_id_issuers": _external_id_issuers(g.get("ExternalIds"))} for g in groups]}, f"{len(groups)} Identity Store groups for {identity_store_id}")
    memberships_eid = await adapter._evidence(ctx, account, region, "identitycenter_memberships", {"memberships": [{"membership_id": m.get("MembershipId"), "group_id": m.get("GroupId"), "user_id": (m.get("MemberId") or {}).get("UserId")} for m in all_memberships]}, f"{len(all_memberships)} Identity Store group memberships for {identity_store_id}")

    for g in groups:
        gid = str(g.get("GroupId"))
        found, members_ok = memberships_by_group.get(gid, ([], False))
        key = f"identitystore:{identity_store_id}:group:{gid}"
        report.observations.append(adapter._obs(key, "aws/identitystore_group", {"account": account, "region": region, "identity_store_id": identity_store_id, "group_id": gid, "name": g.get("DisplayName")}, {"description": g.get("Description"), "member_count": len(found), "members_complete": members_ok, "external_id_issuers": _external_id_issuers(g.get("ExternalIds"))}, groups_scope_key, groups_eid))
        for m in found:
            mid = str(m.get("MembershipId"))
            user_id = str((m.get("MemberId") or {}).get("UserId") or "")
            mkey = f"identitystore:{identity_store_id}:membership:{mid}"
            user_key = f"identitystore:{identity_store_id}:user:{user_id}"
            rels = [{"kind": "member", "target": user_key}, {"kind": "group", "target": key}]
            report.observations.append(adapter._obs(mkey, "aws/identitystore_group_membership", {"account": account, "region": region, "identity_store_id": identity_store_id, "membership_id": mid, "group_id": gid, "user_id": user_id}, {}, memberships_scope_key, memberships_eid, rels))
    return groups_ok, memberships_ok
