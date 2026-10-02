"""Metadata-only AWS data, key, logging, and cache inventory families.

This module is deliberately called by :class:`AwsAdapter`, rather than being an
adapter in its own right.  It uses the adapter's canonical client, pagination,
evidence, and observation paths.  In particular it never reads secret values,
log events, or application data.

OpenSearch Serverless collections and ElastiCache Serverless caches are separate
AWS service surfaces and are intentionally not enumerated by these classic
OpenSearch/ElastiCache families yet; coverage must report them unsupported.
"""

from __future__ import annotations

import asyncio
from typing import Any


def _time(adapter: Any, value: Any) -> Any:
    # Keep the conversion owned by aws.py so observations have one format.
    from local_ops.providers.aws import _ts

    return _ts(value)


def _tags(tags: Any) -> dict[str, str]:
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {str(t.get("Key") or t.get("TagKey")): str(t.get("Value") if "Key" in t else t.get("TagValue", "")) for t in (tags or []) if isinstance(t, dict) and ("Key" in t or "TagKey" in t)}


async def _failed(adapter: Any, report: Any, scope_key: str, operation: str, exc: BaseException) -> bool:
    """Make a failed optional enrichment explicit without discarding listed resources."""
    from local_ops.providers.aws import _AwsCallError, classify_boto_error

    if isinstance(exc, _AwsCallError):
        reason, detail = classify_boto_error(exc.exc)
        operation = exc.operation
    else:
        reason, detail = classify_boto_error(exc)
    report.unavailable.append({"source": scope_key, "reason": reason, "operation": operation, "detail": detail})
    return False


async def _call_or_partial(adapter: Any, client: Any, operation: str, report: Any, scope_key: str, **kwargs: Any) -> tuple[dict[str, Any] | None, bool]:
    try:
        return await adapter._call(client, operation, **kwargs), True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # adapter normalizes provider exceptions
        from local_ops.models import ErrorCode, OpsError
        if isinstance(exc, OpsError) and exc.code == ErrorCode.LIMIT_REACHED:
            raise
        await _failed(adapter, report, scope_key, operation, exc)
        return None, False


async def _paginated(adapter: Any, client: Any, operation: str, result_key: str, ctx: Any, budget: Any, report: Any, scope_key: str, **kwargs: Any) -> tuple[list[Any], bool]:
    try:
        return await adapter._paginate(client, operation, result_key, ctx, budget, **kwargs)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # A deadline is handled by AwsAdapter.discover so it marks all unattempted
        # scopes and, for resumable families, retains the provider continuation.
        from local_ops.models import ErrorCode, OpsError
        if isinstance(exc, OpsError) and exc.code == ErrorCode.LIMIT_REACHED:
            raise
        await _failed(adapter, report, scope_key, operation, exc)
        return [], False


async def _efs_tags(adapter: Any, client: Any, ctx: Any, budget: Any, report: Any, scope_key: str, resource_id: str) -> tuple[list[Any], bool]:
    """EFS ListTagsForResource has NextToken but no botocore paginator model."""
    tags: list[Any] = []
    token: str | None = None
    while True:
        budget.check()
        response, ok = await _call_or_partial(adapter, client, "list_tags_for_resource", report, scope_key, **{"ResourceId": resource_id, **({"NextToken": token} if token else {})})
        if not ok or response is None:
            return tags, False
        tags.extend(response.get("Tags") or [])
        next_token = response.get("NextToken")
        if not next_token:
            return tags, True
        if next_token == token:
            report.unavailable.append({"source": scope_key, "reason": "provider_error", "operation": "list_tags_for_resource", "detail": "EFS returned a repeated tag pagination token"})
            return tags, False
        token = str(next_token)


async def discover(adapter: Any, family: str, ctx: Any, budget: Any, report: Any, scope: Any, account: str, region: str, regions: list[str]) -> bool:
    """Discover one metadata family.  All evidence is an explicit safe projection."""
    scope_key = adapter._fkey(account, region, family)
    handlers = {
        "secretsmanager": _secretsmanager,
        "kms": _kms,
        "logs": _logs,
        "cloudwatch": _cloudwatch,
        "dynamodb": _dynamodb,
        "elasticache": _elasticache,
        "efs": _efs,
        "opensearch": _opensearch,
    }
    return await handlers[family](adapter, ctx, budget, report, account, region, scope_key)


async def _secretsmanager(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("secretsmanager", region) as sm:
        complete = True
        # _census_pages records the provider continuation token.  Storing each completed
        # page before advancing makes this family resumable without pretending a partial
        # page sequence is comparable to a complete scan.
        async for listed in adapter._census_pages(sm, "list_secrets", "SecretList", ctx, budget, report, IncludePlannedDeletion=True):
            secrets: list[dict[str, Any]] = []
            for item in listed:
                budget.check()
                secret_id = item.get("ARN") or item.get("Name")
                if not secret_id:
                    complete = False
                    continue
                detail, ok = await _call_or_partial(adapter, sm, "describe_secret", report, scope_key, SecretId=secret_id)
                complete = complete and ok
                source = detail or item
                # Deliberately no GetSecretValue or ListSecretVersionIds.
                rotation_rules = source.get("RotationRules") or {}
                secrets.append({"arn": source.get("ARN"), "name": source.get("Name"), "description": source.get("Description"), "tags": _tags(source.get("Tags")), "created_at": _time(adapter, source.get("CreatedDate")), "last_changed_at": _time(adapter, source.get("LastChangedDate")), "deleted_at": _time(adapter, source.get("DeletedDate")), "last_rotated_at": _time(adapter, source.get("LastRotatedDate")), "rotation_enabled": source.get("RotationEnabled"), "rotation_lambda_arn": source.get("RotationLambdaARN"), "rotation_rules": {k: rotation_rules.get(k) for k in ("AutomaticallyAfterDays", "Duration", "ScheduleExpression") if rotation_rules.get(k) is not None}, "kms_key_id": source.get("KmsKeyId"), "replica_regions": [{"region": r.get("Region"), "status": r.get("Status"), "kms_key_id": r.get("KmsKeyId")} for r in (source.get("ReplicationStatus") or [])]})
            eid = await adapter._evidence(ctx, account, region, "secretsmanager", {"secrets": secrets}, f"{len(secrets)} Secrets Manager secrets in {region}")
            for s in secrets:
                arn = str(s.get("arn") or f"arn:aws:secretsmanager:{region}:{account}:secret:{s.get('name')}")
                rels = [{"kind": "encrypted_by", "target": str(s["kms_key_id"])}] if s.get("kms_key_id") else []
                report.observations.append(adapter._obs(arn, "aws/secretsmanager_secret", {"account": account, "region": region, "arn": arn, "name": s.get("name")}, {k: v for k, v in s.items() if k not in {"arn", "name"}}, scope_key, eid, rels))
    return complete


async def _kms(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("kms", region) as kms:
        key_refs, complete = await _paginated(adapter, kms, "list_keys", "Keys", ctx, budget, report, scope_key)
        aliases, aliases_ok = await _paginated(adapter, kms, "list_aliases", "Aliases", ctx, budget, report, scope_key)
        complete = complete and aliases_ok
        aliases_by_key: dict[str, list[str]] = {}
        for alias in aliases:
            if alias.get("TargetKeyId") and alias.get("AliasName"):
                aliases_by_key.setdefault(str(alias["TargetKeyId"]), []).append(str(alias["AliasName"]))
        keys: list[dict[str, Any]] = []
        for ref in key_refs:
            budget.check()
            key_id = ref.get("KeyId")
            if not key_id:
                complete = False
                continue
            response, ok = await _call_or_partial(adapter, kms, "describe_key", report, scope_key, KeyId=key_id)
            complete = complete and ok
            metadata = (response or {}).get("KeyMetadata") or {}
            key_tags, tags_ok = await _paginated(adapter, kms, "list_resource_tags", "Tags", ctx, budget, report, scope_key, KeyId=key_id)
            complete = complete and tags_ok
            rotation: Any = "not_applicable"
            # KMS exposes rotation state for symmetric encryption keys, including AWS-managed
            # keys where the service reports AWS-managed rotation. Unsupported key types are
            # deliberately distinct from a permission failure (which remains "unknown").
            if metadata.get("KeyUsage") == "ENCRYPT_DECRYPT" and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT" and metadata.get("Origin", "AWS_KMS") == "AWS_KMS" and not metadata.get("CustomKeyStoreId"):
                rotation_response, rotation_ok = await _call_or_partial(adapter, kms, "get_key_rotation_status", report, scope_key, KeyId=key_id)
                complete = complete and rotation_ok
                rotation = (rotation_response or {}).get("KeyRotationEnabled") if rotation_ok else "unknown"
            keys.append({"key_id": metadata.get("KeyId") or key_id, "arn": metadata.get("Arn"), "description": metadata.get("Description"), "state": metadata.get("KeyState"), "manager": metadata.get("KeyManager"), "spec": metadata.get("KeySpec"), "usage": metadata.get("KeyUsage"), "created_at": _time(adapter, metadata.get("CreationDate")), "multi_region": metadata.get("MultiRegion"), "rotation_enabled": rotation, "aliases": sorted(aliases_by_key.get(str(metadata.get("KeyId") or key_id), [])), "tags": _tags(key_tags)})
    eid = await adapter._evidence(ctx, account, region, "kms", {"keys": keys}, f"{len(keys)} KMS keys in {region}")
    for key in keys:
        arn = str(key.get("arn") or f"arn:aws:kms:{region}:{account}:key/{key.get('key_id')}")
        report.observations.append(adapter._obs(arn, "aws/kms_key", {"account": account, "region": region, "arn": arn, "key_id": key.get("key_id")}, {k: v for k, v in key.items() if k not in {"arn", "key_id"}}, scope_key, eid))
    return complete


async def _logs(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("logs", region) as logs:
        complete = True
        async for groups in adapter._census_pages(logs, "describe_log_groups", "logGroups", ctx, budget, report):
            projected: list[dict[str, Any]] = []
            for group in groups:
                budget.check()
                arn = group.get("arn") or group.get("logGroupArn")
                # DescribeLogGroups may return an ARN ending in :*; ListTagsForResource
                # requires the log-group ARN itself.
                tag_arn = arn.removesuffix(":*") if isinstance(arn, str) else arn
                tag_response: dict[str, Any] | None = None
                ok = True
                if tag_arn:
                    tag_response, ok = await _call_or_partial(adapter, logs, "list_tags_for_resource", report, scope_key, resourceArn=tag_arn)
                complete = complete and ok
                projected.append({"arn": arn, "name": group.get("logGroupName"), "retention_days": group.get("retentionInDays"), "kms_key_id": group.get("kmsKeyId"), "stored_bytes": group.get("storedBytes"), "created_at": _time(adapter, group.get("creationTime")), "tags": _tags((tag_response or {}).get("tags"))})
            eid = await adapter._evidence(ctx, account, region, "logs", {"log_groups": projected}, f"{len(projected)} CloudWatch log groups in {region}")
            for group in projected:
                arn = str(group.get("arn") or f"arn:aws:logs:{region}:{account}:log-group:{group.get('name')}")
                rels = [{"kind": "encrypted_by", "target": str(group["kms_key_id"])}] if group.get("kms_key_id") else []
                report.observations.append(adapter._obs(arn, "aws/cloudwatch_log_group", {"account": account, "region": region, "arn": arn, "name": group.get("name")}, {k: v for k, v in group.items() if k not in {"arn", "name"}}, scope_key, eid, rels))
    return complete


async def _cloudwatch(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("cloudwatch", region) as cw:
        metric, complete = await _paginated(adapter, cw, "describe_alarms", "MetricAlarms", ctx, budget, report, scope_key, AlarmTypes=["MetricAlarm"])
        composite, cok = await _paginated(adapter, cw, "describe_alarms", "CompositeAlarms", ctx, budget, report, scope_key, AlarmTypes=["CompositeAlarm"])
        logs, lok = await _paginated(adapter, cw, "describe_alarms", "LogAlarms", ctx, budget, report, scope_key, AlarmTypes=["LogAlarm"])
        complete = complete and cok and lok
    alarms = [{"arn": a.get("AlarmArn"), "name": a.get("AlarmName"), "type": "composite" if a.get("AlarmRule") else "metric", "state": a.get("StateValue"), "reason": a.get("StateReason"), "metric_name": a.get("MetricName"), "namespace": a.get("Namespace"), "dimensions": [{"name": d.get("Name"), "value": d.get("Value")} for d in (a.get("Dimensions") or [])], "comparison": a.get("ComparisonOperator"), "threshold": a.get("Threshold"), "actions": a.get("AlarmActions") or [], "rule": a.get("AlarmRule")} for a in [*metric, *composite]]
    for alarm in logs:
        query = alarm.get("ScheduledQueryConfiguration") or {}
        alarms.append({"arn": alarm.get("AlarmArn"), "name": alarm.get("AlarmName"), "type": "log", "state": alarm.get("StateValue"), "reason": alarm.get("StateReason"), "comparison": alarm.get("ComparisonOperator"), "threshold": alarm.get("Threshold"), "actions": alarm.get("AlarmActions") or [], "log_group_identifiers": query.get("LogGroupIdentifiers") or [], "query_arn": query.get("QueryARN")})
    eid = await adapter._evidence(ctx, account, region, "cloudwatch", {"alarms": alarms}, f"{len(alarms)} CloudWatch alarms in {region}")
    for alarm in alarms:
        arn = str(alarm.get("arn") or f"arn:aws:cloudwatch:{region}:{account}:alarm:{alarm.get('name')}")
        rels = [{"kind": "targets", "target": str(v)} for v in alarm["actions"]] + [{"kind": "monitors", "target": f"aws:metric:{alarm['namespace']}:{alarm['metric_name']}:{d['name']}={d['value']}"} for d in alarm.get("dimensions", []) if alarm.get("namespace") and alarm.get("metric_name") and d.get("name")] + [{"kind": "monitors", "target": str(group)} for group in alarm.get("log_group_identifiers", [])]
        report.observations.append(adapter._obs(arn, "aws/cloudwatch_alarm", {"account": account, "region": region, "arn": arn, "name": alarm.get("name")}, {k: v for k, v in alarm.items() if k not in {"arn", "name"}}, scope_key, eid, rels))
    return complete


async def _dynamodb(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("dynamodb", region) as ddb:
        names, complete = await _paginated(adapter, ddb, "list_tables", "TableNames", ctx, budget, report, scope_key)
        tables: list[dict[str, Any]] = []
        for name in names:
            budget.check()
            response, ok = await _call_or_partial(adapter, ddb, "describe_table", report, scope_key, TableName=name)
            complete = complete and ok
            table = (response or {}).get("Table") or {}
            arn = table.get("TableArn")
            table_tags, tags_ok = await _paginated(adapter, ddb, "list_tags_of_resource", "Tags", ctx, budget, report, scope_key, ResourceArn=arn) if arn else ([], False)
            complete = complete and tags_ok
            tables.append({"arn": arn, "name": table.get("TableName") or name, "status": table.get("TableStatus"), "created_at": _time(adapter, table.get("CreationDateTime")), "billing_mode": (table.get("BillingModeSummary") or {}).get("BillingMode"), "table_size_bytes": table.get("TableSizeBytes"), "item_count": table.get("ItemCount"), "sse_status": (table.get("SSEDescription") or {}).get("Status"), "kms_key_arn": (table.get("SSEDescription") or {}).get("KMSMasterKeyArn"), "stream_arn": table.get("LatestStreamArn"), "replicas": [{"region": r.get("RegionName"), "status": r.get("ReplicaStatus")} for r in (table.get("Replicas") or [])], "tags": _tags(table_tags)})
    eid = await adapter._evidence(ctx, account, region, "dynamodb", {"tables": tables}, f"{len(tables)} DynamoDB tables in {region}")
    for table in tables:
        arn = str(table.get("arn") or f"arn:aws:dynamodb:{region}:{account}:table/{table.get('name')}")
        rels = [{"kind": "encrypted_by", "target": str(table["kms_key_arn"])}] if table.get("kms_key_arn") else []
        report.observations.append(adapter._obs(arn, "aws/dynamodb_table", {"account": account, "region": region, "arn": arn, "name": table.get("name")}, {k: v for k, v in table.items() if k not in {"arn", "name"}}, scope_key, eid, rels))
    return complete


async def _elasticache(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("elasticache", region) as ec:
        clusters, complete = await _paginated(adapter, ec, "describe_cache_clusters", "CacheClusters", ctx, budget, report, scope_key, ShowCacheNodeInfo=False)
        groups, groups_ok = await _paginated(adapter, ec, "describe_replication_groups", "ReplicationGroups", ctx, budget, report, scope_key)
        complete = complete and groups_ok
        projected: list[dict[str, Any]] = []
        for cluster in clusters:
            budget.check()
            arn = cluster.get("ARN")
            tag_response, tags_ok = await _call_or_partial(adapter, ec, "list_tags_for_resource", report, scope_key, ResourceName=arn) if arn else (None, False)
            complete = complete and tags_ok
            projected.append({"arn": arn, "id": cluster.get("CacheClusterId"), "status": cluster.get("CacheClusterStatus"), "engine": cluster.get("Engine"), "engine_version": cluster.get("EngineVersion"), "node_type": cluster.get("CacheNodeType"), "created_at": _time(adapter, cluster.get("CacheClusterCreateTime")), "subnet_group": cluster.get("CacheSubnetGroupName"), "security_groups": [g.get("SecurityGroupId") for g in (cluster.get("SecurityGroups") or []) if g.get("SecurityGroupId")], "replication_group_id": cluster.get("ReplicationGroupId"), "kms_key_id": cluster.get("KmsKeyId"), "transit_encryption": cluster.get("TransitEncryptionEnabled"), "at_rest_encryption": cluster.get("AtRestEncryptionEnabled"), "configuration_endpoint": (cluster.get("ConfigurationEndpoint") or {}).get("Address"), "tags": _tags((tag_response or {}).get("TagList"))})
        replications = [{"id": g.get("ReplicationGroupId"), "arn": g.get("ARN"), "status": g.get("Status"), "description": g.get("Description"), "primary_endpoint": (g.get("NodeGroups") or [{}])[0].get("PrimaryEndpoint", {}).get("Address"), "member_clusters": g.get("MemberClusters") or [], "kms_key_id": g.get("KmsKeyId"), "transit_encryption": g.get("TransitEncryptionEnabled"), "at_rest_encryption": g.get("AtRestEncryptionEnabled")} for g in groups]
    eid = await adapter._evidence(ctx, account, region, "elasticache", {"clusters": projected, "replication_groups": replications}, f"{len(projected)} ElastiCache clusters, {len(replications)} replication groups in {region}")
    cluster_arns = {str(cluster.get("id")): str(cluster.get("arn")) for cluster in projected if cluster.get("id") and cluster.get("arn")}
    for cluster in projected:
        arn = str(cluster.get("arn") or f"aws:{account}:{region}:elasticache:{cluster.get('id')}")
        rels = ([{"kind": "encrypted_by", "target": str(cluster["kms_key_id"])}] if cluster.get("kms_key_id") else []) + [{"kind": "uses", "target": f"arn:aws:ec2:{region}:{account}:security-group/{sg}"} for sg in cluster["security_groups"]]
        report.observations.append(adapter._obs(arn, "aws/elasticache_cluster", {"account": account, "region": region, "arn": arn, "id": cluster.get("id")}, {k: v for k, v in cluster.items() if k not in {"arn", "id"}}, scope_key, eid, rels))
    for group in replications:
        arn = str(group.get("arn") or f"aws:{account}:{region}:elasticache-replication:{group.get('id')}")
        rels = [{"kind": "contains", "target": cluster_arns[name]} for name in group["member_clusters"] if name in cluster_arns]
        report.observations.append(adapter._obs(arn, "aws/elasticache_replication_group", {"account": account, "region": region, "arn": arn, "id": group.get("id")}, {k: v for k, v in group.items() if k not in {"arn", "id"}}, scope_key, eid, rels))
    return complete


async def _efs(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("efs", region) as efs:
        systems, complete = await _paginated(adapter, efs, "describe_file_systems", "FileSystems", ctx, budget, report, scope_key)
        projected: list[dict[str, Any]] = []
        for system in systems:
            budget.check()
            fs_id = system.get("FileSystemId")
            fs_tags, tags_ok = await _efs_tags(adapter, efs, ctx, budget, report, scope_key, fs_id) if fs_id else ([], False)
            mounts, mounts_ok = await _paginated(adapter, efs, "describe_mount_targets", "MountTargets", ctx, budget, report, scope_key, FileSystemId=fs_id) if fs_id else ([], False)
            complete = complete and tags_ok and mounts_ok
            mount_targets = []
            for mount in mounts:
                groups_response, groups_ok = await _call_or_partial(adapter, efs, "describe_mount_target_security_groups", report, scope_key, MountTargetId=mount.get("MountTargetId")) if mount.get("MountTargetId") else (None, False)
                complete = complete and groups_ok
                mount_targets.append({"id": mount.get("MountTargetId"), "subnet_id": mount.get("SubnetId"), "security_groups": (groups_response or {}).get("SecurityGroups") or [], "ip_address": mount.get("IpAddress"), "state": mount.get("LifeCycleState")})
            projected.append({"arn": system.get("FileSystemArn"), "id": fs_id, "state": system.get("LifeCycleState"), "created_at": _time(adapter, system.get("CreationTime")), "encrypted": system.get("Encrypted"), "kms_key_id": system.get("KmsKeyId"), "performance_mode": system.get("PerformanceMode"), "throughput_mode": system.get("ThroughputMode"), "size_bytes": (system.get("SizeInBytes") or {}).get("Value"), "tags": _tags(fs_tags), "mount_targets": mount_targets})
    eid = await adapter._evidence(ctx, account, region, "efs", {"file_systems": projected}, f"{len(projected)} EFS file systems in {region}")
    for system in projected:
        arn = str(system.get("arn") or f"arn:aws:elasticfilesystem:{region}:{account}:file-system/{system.get('id')}")
        rels = ([{"kind": "encrypted_by", "target": str(system["kms_key_id"])}] if system.get("kms_key_id") else [])
        for mount in system["mount_targets"]:
            if mount.get("subnet_id"):
                rels.append({"kind": "mounted_in", "target": f"arn:aws:ec2:{region}:{account}:subnet/{mount['subnet_id']}"})
            rels.extend({"kind": "uses", "target": f"arn:aws:ec2:{region}:{account}:security-group/{sg}"} for sg in mount["security_groups"])
        report.observations.append(adapter._obs(arn, "aws/efs_file_system", {"account": account, "region": region, "arn": arn, "id": system.get("id")}, {k: v for k, v in system.items() if k not in {"arn", "id"}}, scope_key, eid, rels))
    return complete


async def _opensearch(adapter: Any, ctx: Any, budget: Any, report: Any, account: str, region: str, scope_key: str) -> bool:
    async with adapter._client("opensearch", region) as os:
        # ListDomainNames has no paginator in the AWS model; it returns all names.
        listed, complete = await _call_or_partial(adapter, os, "list_domain_names", report, scope_key)
        complete = complete and listed is not None
        names = [item.get("DomainName") for item in (listed or {}).get("DomainNames", []) if item.get("DomainName")]
        domains: list[dict[str, Any]] = []
        for start in range(0, len(names), 5):  # API accepts at most five names per request.
            budget.check()
            response, ok = await _call_or_partial(adapter, os, "describe_domains", report, scope_key, DomainNames=names[start : start + 5])
            complete = complete and ok
            for domain in (response or {}).get("DomainStatusList", []):
                arn = domain.get("ARN")
                tag_response, tags_ok = await _call_or_partial(adapter, os, "list_tags", report, scope_key, ARN=arn) if arn else (None, False)
                complete = complete and tags_ok
                domains.append({"arn": arn, "name": domain.get("DomainName"), "created": domain.get("Created"), "deleted": domain.get("Deleted"), "processing": domain.get("Processing"), "upgrade_processing": domain.get("UpgradeProcessing"), "engine_version": domain.get("EngineVersion"), "endpoint": domain.get("Endpoint") or (domain.get("Endpoints") or {}), "vpc_options": {"vpc_id": (domain.get("VPCOptions") or {}).get("VPCId"), "subnet_ids": (domain.get("VPCOptions") or {}).get("SubnetIds") or [], "security_group_ids": (domain.get("VPCOptions") or {}).get("SecurityGroupIds") or []}, "encryption_at_rest": (domain.get("EncryptionAtRestOptions") or {}).get("Enabled"), "kms_key_id": (domain.get("EncryptionAtRestOptions") or {}).get("KmsKeyId"), "node_to_node_encryption": (domain.get("NodeToNodeEncryptionOptions") or {}).get("Enabled"), "tags": _tags((tag_response or {}).get("TagList"))})
    eid = await adapter._evidence(ctx, account, region, "opensearch", {"domains": domains}, f"{len(domains)} OpenSearch domains in {region}")
    for domain in domains:
        arn = str(domain.get("arn") or f"arn:aws:es:{region}:{account}:domain/{domain.get('name')}")
        rels = ([{"kind": "encrypted_by", "target": str(domain["kms_key_id"])}] if domain.get("kms_key_id") else []) + [{"kind": "member_of", "target": f"arn:aws:ec2:{region}:{account}:subnet/{subnet}"} for subnet in domain["vpc_options"]["subnet_ids"]] + [{"kind": "uses", "target": f"arn:aws:ec2:{region}:{account}:security-group/{sg}"} for sg in domain["vpc_options"]["security_group_ids"]]
        report.observations.append(adapter._obs(arn, "aws/opensearch_domain", {"account": account, "region": region, "arn": arn, "name": domain.get("name")}, {k: v for k, v in domain.items() if k not in {"arn", "name"}}, scope_key, eid, rels))
    return complete
