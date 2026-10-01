"""Metadata-only AWS edge, messaging, workflow, and stack discovery.

This module deliberately projects API responses before storing evidence.  In
particular it never requests queue messages, state-machine definitions or
executions, CloudFormation templates/parameters/outputs, API mapping
templates/credentials, or CloudFront custom header values.
"""

from __future__ import annotations

import json
from typing import Any

from local_ops.models import OpsError


def _ts(value: Any) -> Any:
    return value.isoformat().replace("+00:00", "Z") if hasattr(value, "isoformat") else value


def _tags(value: Any) -> dict[str, str]:
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {str(t["Key"]): str(t.get("Value", "")) for t in value or [] if isinstance(t, dict) and "Key" in t}


def _scope(adapter: Any, account: str, region: str, family: str) -> str:
    return adapter._fkey(account, region, family)


def _global_region(regions: list[str]) -> str:
    first = regions[0] if regions else "us-east-1"
    return first if first.startswith(("cn-", "us-gov-")) else "us-east-1"


async def _tags_for(
    adapter: Any, client: Any, arn: str, *, service_hint: str | None = None
) -> dict[str, str]:
    """Tags are optional enrichment; callers retain listed primary resources on failure."""
    model = getattr(getattr(client, "meta", None), "service_model", None)
    service = service_hint or getattr(model, "service_name", "")
    param = (
        "Resource"
        if service == "cloudfront"
        else "ResourceARN"
        if service == "wafv2"
        else "ResourceArn"
        if service == "sns"
        else "resourceArn"
    )
    result = await adapter._call(client, "list_tags_for_resource", **{param: arn})
    if service == "wafv2":
        tag_list = list((result.get("TagInfoForResource") or {}).get("TagList") or [])
        marker = result.get("NextMarker")
        while marker:
            result = await adapter._call(client, "list_tags_for_resource", ResourceARN=arn, NextMarker=marker)
            tag_list.extend((result.get("TagInfoForResource") or {}).get("TagList") or [])
            marker = result.get("NextMarker")
        return _tags(tag_list)
    # AWS has three tag response shapes across these services.
    tags = result.get("Tags")
    if isinstance(tags, dict) and "Items" in tags:
        tags = tags["Items"]
    return _tags(tags or result.get("tags") or (result.get("TagInfoForResource") or {}).get("TagList"))


async def _partial_enrichment(report: Any, scope_key: str, resource: str, exc: Exception) -> None:
    # Import lazily: aws.py loads this module to dispatch edge families.
    from local_ops.providers.aws import classify_boto_error

    reason, detail = classify_boto_error(getattr(exc, "exc", exc))
    report.unavailable.append(
        {
            "source": f"{scope_key}/{resource}",
            "reason": reason,
            "operation": getattr(exc, "operation", "metadata_enrichment"),
            "detail": detail,
        }
    )


async def _token_pages(
    adapter: Any, client: Any, operation: str, result_key: str, ctx: Any, budget: Any, **kwargs: Any
) -> tuple[list[Any], bool]:
    """Manual NextToken paging for APIs whose botocore model has no paginator."""
    items: list[Any] = []
    token: str | None = None
    while True:
        ctx.check_cancel()
        budget.check()
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        page = await adapter._call(client, operation, **params)
        items.extend(page.get(result_key) or [])
        token = page.get("NextToken")
        if not token:
            return items, True


async def _marker_pages(
    adapter: Any, client: Any, operation: str, result_key: str, ctx: Any, budget: Any, **kwargs: Any
) -> tuple[list[Any], bool]:
    """Manual NextMarker paging for WAFv2 APIs, which have no paginator model."""
    items: list[Any] = []
    marker: str | None = None
    while True:
        ctx.check_cancel()
        budget.check()
        params = dict(kwargs)
        if marker:
            params["NextMarker"] = marker
        page = await adapter._call(client, operation, **params)
        items.extend(page.get(result_key) or [])
        marker = page.get("NextMarker")
        if not marker:
            return items, True


async def discover(
    adapter: Any,
    family: str,
    ctx: Any,
    budget: Any,
    report: Any,
    scope: Any,
    account: str,
    region: str,
    regions: list[str],
) -> bool:
    """Discover one family.  Returns false when any child listing/enrichment is incomplete.

    All paginator calls are deliberately unbounded; the owning adapter checks the
    operation budget between pages.  Child failures are reported without losing
    already listed primary resources.
    """
    scope_key = _scope(adapter, account, region, family)
    complete = True
    if family == "sqs":
        async with adapter._client("sqs", region) as c:
            urls, complete = await adapter._paginate(
                c, "list_queues", "QueueUrls", ctx, budget, MaxResults=1000
            )
            queue_rows: list[dict[str, Any]] = []
            for url in urls:
                ctx.check_cancel()
                budget.check()
                try:
                    tags = (await adapter._call(c, "list_queue_tags", QueueUrl=str(url))).get("Tags") or {}
                    attributes = (
                        await adapter._call(
                            c,
                            "get_queue_attributes",
                            QueueUrl=str(url),
                            AttributeNames=[
                                "QueueArn",
                                "KmsMasterKeyId",
                                "SqsManagedSseEnabled",
                                "RedrivePolicy",
                                "CreatedTimestamp",
                                "LastModifiedTimestamp",
                                "VisibilityTimeout",
                                "MessageRetentionPeriod",
                                "ReceiveMessageWaitTimeSeconds",
                                "FifoQueue",
                                "ContentBasedDeduplication",
                            ],
                        )
                    ).get("Attributes") or {}
                except Exception as exc:  # listed queue remains useful
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, str(url), exc)
                    tags = {}
                    attributes = {}
                    complete = False
                name = str(url).rstrip("/").rsplit("/", 1)[-1]
                redrive = attributes.get("RedrivePolicy")
                # RedrivePolicy is a compact provider relationship document; retain only its target ARN.
                try:
                    dead_letter = json.loads(redrive).get("deadLetterTargetArn") if redrive else None
                except (TypeError, ValueError):
                    dead_letter = None
                queue_rows.append(
                    {
                        "url": str(url),
                        "name": name,
                        "tags": _tags(tags),
                        "arn": attributes.get("QueueArn"),
                        "kms_key_id": attributes.get("KmsMasterKeyId"),
                        "sqs_managed_sse": attributes.get("SqsManagedSseEnabled"),
                        "dead_letter_target": dead_letter,
                        "created_at": attributes.get("CreatedTimestamp"),
                        "last_modified_at": attributes.get("LastModifiedTimestamp"),
                        "visibility_timeout": attributes.get("VisibilityTimeout"),
                        "message_retention_period": attributes.get("MessageRetentionPeriod"),
                        "fifo": attributes.get("FifoQueue"),
                        "content_based_deduplication": attributes.get("ContentBasedDeduplication"),
                    }
                )
        eid = await adapter._evidence(
            ctx, account, region, family, {"queues": queue_rows}, f"{len(queue_rows)} SQS queues in {region}"
        )
        for r in queue_rows:
            report.observations.append(
                adapter._obs(
                    r["url"],
                    "aws/sqs_queue",
                    {"account": account, "region": region, "url": r["url"], "name": r["name"]},
                    {k: v for k, v in r.items() if k not in {"url", "name", "arn", "dead_letter_target"}},
                    scope_key,
                    eid,
                    (
                        [{"kind": "dead_letters_to", "target": str(r["dead_letter_target"])}]
                        if r.get("dead_letter_target")
                        else []
                    )
                    + (
                        [{"kind": "encrypted_by", "target": str(r["kms_key_id"])}]
                        if r.get("kms_key_id")
                        else []
                    ),
                )
            )
        return complete

    if family == "sns":
        async with adapter._client("sns", region) as c:
            topics, complete = await adapter._paginate(c, "list_topics", "Topics", ctx, budget)
            topic_rows: list[dict[str, Any]] = []
            for topic in topics:
                ctx.check_cancel()
                budget.check()
                arn = str(topic.get("TopicArn"))
                try:
                    subs, ok = await adapter._paginate(
                        c, "list_subscriptions_by_topic", "Subscriptions", ctx, budget, TopicArn=arn
                    )
                    tags = await _tags_for(adapter, c, arn, service_hint="sns")
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, arn, exc)
                    subs, tags, ok = [], {}, False
                complete = complete and ok
                topic_rows.append(
                    {
                        "arn": arn,
                        "subscriptions": [
                            {
                                "arn": s.get("SubscriptionArn"),
                                "protocol": s.get("Protocol"),
                                "endpoint": s.get("Endpoint"),
                                "owner": s.get("Owner"),
                            }
                            for s in subs
                        ],
                        "tags": tags,
                    }
                )
        eid = await adapter._evidence(
            ctx, account, region, family, {"topics": topic_rows}, f"{len(topic_rows)} SNS topics in {region}"
        )
        for r in topic_rows:
            rels = [
                {"kind": "target", "target": str(s["endpoint"])}
                for s in r["subscriptions"]
                if s.get("endpoint") and s["endpoint"] != "PendingConfirmation"
            ]
            report.observations.append(
                adapter._obs(
                    r["arn"],
                    "aws/sns_topic",
                    {
                        "account": account,
                        "region": region,
                        "arn": r["arn"],
                        "name": r["arn"].rsplit(":", 1)[-1],
                    },
                    {"subscriptions": r["subscriptions"], "tags": r["tags"]},
                    scope_key,
                    eid,
                    rels,
                )
            )
        return complete

    if family == "apigateway":
        async with adapter._client("apigateway", region) as c:
            apis, complete = await adapter._paginate(c, "get_rest_apis", "items", ctx, budget)
            api_rows: list[dict[str, Any]] = []
            for api in apis:
                ctx.check_cancel()
                budget.check()
                aid = str(api.get("id"))
                try:
                    resources, ok = await adapter._paginate(
                        c, "get_resources", "items", ctx, budget, restApiId=aid
                    )
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, aid, exc)
                    resources, ok = [], False
                integrations: list[dict[str, Any]] = []
                for resource in resources:
                    for method in resource.get("resourceMethods") or {}:
                        try:
                            integration = await adapter._call(
                                c,
                                "get_integration",
                                restApiId=aid,
                                resourceId=resource.get("id"),
                                httpMethod=method,
                            )
                            integrations.append(
                                {
                                    "resource_id": resource.get("id"),
                                    "path": resource.get("path"),
                                    "method": method,
                                    "type": integration.get("type"),
                                    "uri": integration.get("uri"),
                                    "connection_type": integration.get("connectionType"),
                                    "connection_id": integration.get("connectionId"),
                                }
                            )
                        except Exception as exc:
                            if isinstance(exc, OpsError):
                                raise
                            await _partial_enrichment(
                                report, scope_key, f"{aid}/{resource.get('id')}/{method}", exc
                            )
                            ok = False
                complete = complete and ok
                api_rows.append(
                    {
                        "id": aid,
                        "name": api.get("name"),
                        "description": api.get("description"),
                        "created_at": _ts(api.get("createdDate")),
                        "endpoint_types": (api.get("endpointConfiguration") or {}).get("types"),
                        "integrations": integrations,
                        "tags": _tags(api.get("tags")),
                    }
                )
        # API Gateway v2 (HTTP and WebSocket) does not expose a botocore paginator
        # for every operation, so page explicitly with NextToken.
        async with adapter._client("apigatewayv2", region) as c2:
            v2_apis, v2_complete = await _token_pages(adapter, c2, "get_apis", "Items", ctx, budget)
            complete = complete and v2_complete
            for api in v2_apis:
                ctx.check_cancel()
                budget.check()
                aid = str(api.get("ApiId"))
                try:
                    integrations, ok = await _token_pages(
                        adapter, c2, "get_integrations", "Items", ctx, budget, ApiId=aid
                    )
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, aid, exc)
                    integrations, ok = [], False
                complete = complete and ok
                api_rows.append(
                    {
                        "id": aid,
                        "name": api.get("Name"),
                        "description": api.get("Description"),
                        "created_at": _ts(api.get("CreatedDate")),
                        "endpoint_types": (api.get("ProtocolType"),),
                        "integrations": [
                            {
                                "integration_id": i.get("IntegrationId"),
                                "type": i.get("IntegrationType"),
                                "uri": i.get("IntegrationUri"),
                                "connection_type": i.get("ConnectionType"),
                                "connection_id": i.get("ConnectionId"),
                            }
                            for i in integrations
                        ],
                        "tags": _tags(api.get("Tags")),
                        "api_version": "v2",
                    }
                )
        eid = await adapter._evidence(
            ctx,
            account,
            region,
            family,
            {"rest_apis": api_rows},
            f"{len(api_rows)} API Gateway REST APIs in {region}",
        )
        for r in api_rows:
            key = f"aws:{account}:{region}:apigateway:{r['id']}"
            rels = [
                {"kind": "integrates_with", "target": str(i["uri"])}
                for i in r["integrations"]
                if i.get("uri")
            ]
            report.observations.append(
                adapter._obs(
                    key,
                    "aws/apigateway_v2_api" if r.get("api_version") == "v2" else "aws/apigateway_rest_api",
                    {"account": account, "region": region, "id": r["id"], "name": r["name"]},
                    {k: v for k, v in r.items() if k != "id"},
                    scope_key,
                    eid,
                    rels,
                )
            )
        return complete

    if family == "cloudfront":
        async with adapter._client("cloudfront", _global_region(regions)) as c:
            dists, complete = await adapter._paginate(
                c, "list_distributions", "DistributionList.Items", ctx, budget
            )
            distribution_rows: list[dict[str, Any]] = []
            for d in dists:
                arn = str(d.get("ARN"))
                origins = [
                    {
                        "id": x.get("Id"),
                        "domain_name": x.get("DomainName"),
                        "origin_path": x.get("OriginPath"),
                    }
                    for x in ((d.get("Origins") or {}).get("Items") or [])
                ]
                try:
                    tags = await _tags_for(adapter, c, arn, service_hint="cloudfront")
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, arn, exc)
                    tags = {}
                    complete = False
                distribution_rows.append(
                    {
                        "arn": arn,
                        "id": d.get("Id"),
                        "domain_name": d.get("DomainName"),
                        "status": d.get("Status"),
                        "enabled": d.get("Enabled"),
                        "last_modified": _ts(d.get("LastModifiedTime")),
                        "origins": origins,
                        "tags": tags,
                    }
                )
        eid = await adapter._evidence(
            ctx,
            account,
            region,
            family,
            {"distributions": distribution_rows},
            f"{len(distribution_rows)} CloudFront distributions",
        )
        for r in distribution_rows:
            rels = [
                {"kind": "origin", "target": str(x["domain_name"])}
                for x in r["origins"]
                if x.get("domain_name")
            ]
            report.observations.append(
                adapter._obs(
                    r["arn"],
                    "aws/cloudfront_distribution",
                    {
                        "account": account,
                        "region": region,
                        "arn": r["arn"],
                        "id": r["id"],
                        "domain_name": r["domain_name"],
                    },
                    {k: v for k, v in r.items() if k not in {"arn", "id", "domain_name"}},
                    scope_key,
                    eid,
                    rels,
                )
            )
        return complete

    if family == "wafv2":
        scopes = ["REGIONAL"] + (["CLOUDFRONT"] if region == "us-east-1" else [])
        acl_rows: list[dict[str, Any]] = []
        async with adapter._client("wafv2", region) as c:
            for waf_scope in scopes:
                acls, ok = await _marker_pages(
                    adapter, c, "list_web_acls", "WebACLs", ctx, budget, Scope=waf_scope
                )
                complete = complete and ok
                for acl in acls:
                    ctx.check_cancel()
                    budget.check()
                    try:
                        full = (
                            await adapter._call(
                                c, "get_web_acl", Name=acl.get("Name"), Id=acl.get("Id"), Scope=waf_scope
                            )
                        ).get("WebACL") or acl
                        tags = await _tags_for(
                            adapter, c, str(full.get("ARN") or acl.get("ARN")), service_hint="wafv2"
                        )
                    except Exception as exc:
                        if isinstance(exc, OpsError):
                            raise
                        await _partial_enrichment(report, scope_key, str(acl.get("Id")), exc)
                        full, tags, complete = acl, {}, False
                    acl_rows.append(
                        {
                            "arn": full.get("ARN") or acl.get("ARN"),
                            "id": full.get("Id") or acl.get("Id"),
                            "name": full.get("Name") or acl.get("Name"),
                            "scope": waf_scope,
                            "description": full.get("Description"),
                            "capacity": full.get("Capacity"),
                            "managed_by_firewall_manager": full.get("ManagedByFirewallManager"),
                            "tags": tags,
                        }
                    )
        eid = await adapter._evidence(
            ctx,
            account,
            region,
            family,
            {"web_acls": acl_rows},
            f"{len(acl_rows)} WAFv2 web ACLs in {region}",
        )
        for r in acl_rows:
            key = str(r["arn"] or f"aws:{account}:{region}:wafv2:{r['scope']}:{r['id']}")
            report.observations.append(
                adapter._obs(
                    key,
                    "aws/wafv2_web_acl",
                    {"account": account, "region": region, "arn": r["arn"], "id": r["id"], "name": r["name"]},
                    {k: v for k, v in r.items() if k not in {"arn", "id", "name"}},
                    scope_key,
                    eid,
                )
            )
        return complete

    if family == "stepfunctions":
        async with adapter._client("stepfunctions", region) as c:
            sms, complete = await adapter._paginate(c, "list_state_machines", "stateMachines", ctx, budget)
            state_machine_rows: list[dict[str, Any]] = []
            for sm in sms:
                arn = str(sm.get("stateMachineArn"))
                try:
                    tags = await _tags_for(adapter, c, arn, service_hint="stepfunctions")
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, arn, exc)
                    tags = {}
                    complete = False
                state_machine_rows.append(
                    {
                        "arn": arn,
                        "name": sm.get("name"),
                        "type": sm.get("type"),
                        "created_at": _ts(sm.get("creationDate")),
                        "tags": tags,
                    }
                )
        eid = await adapter._evidence(
            ctx,
            account,
            region,
            family,
            {"state_machines": state_machine_rows},
            f"{len(state_machine_rows)} Step Functions state machines in {region}",
        )
        for r in state_machine_rows:
            report.observations.append(
                adapter._obs(
                    r["arn"],
                    "aws/stepfunctions_state_machine",
                    {"account": account, "region": region, "arn": r["arn"], "name": r["name"]},
                    {k: v for k, v in r.items() if k not in {"arn", "name"}},
                    scope_key,
                    eid,
                )
            )
        return complete

    if family == "cloudformation":
        # list_stacks only returns summaries; do not call GetTemplate or DescribeStacks, whose
        # parameters/outputs can contain application-sensitive values.
        async with adapter._client("cloudformation", region) as c:
            stacks, complete = await adapter._paginate(c, "list_stacks", "StackSummaries", ctx, budget)
            stack_rows: list[dict[str, Any]] = []
            for stack in stacks:
                sid = str(stack.get("StackId"))
                try:
                    resources, ok = await adapter._paginate(
                        c, "list_stack_resources", "StackResourceSummaries", ctx, budget, StackName=sid
                    )
                except Exception as exc:
                    if isinstance(exc, OpsError):
                        raise
                    await _partial_enrichment(report, scope_key, sid, exc)
                    resources, ok = [], False
                complete = complete and ok
                stack_rows.append(
                    {
                        "id": sid,
                        "name": stack.get("StackName"),
                        "status": stack.get("StackStatus"),
                        "created_at": _ts(stack.get("CreationTime")),
                        "updated_at": _ts(stack.get("LastUpdatedTime")),
                        "resources": [
                            {
                                "logical_id": x.get("LogicalResourceId"),
                                "physical_id": x.get("PhysicalResourceId"),
                                "type": x.get("ResourceType"),
                                "status": x.get("ResourceStatus"),
                            }
                            for x in resources
                        ],
                    }
                )
        eid = await adapter._evidence(
            ctx,
            account,
            region,
            family,
            {"stacks": stack_rows},
            f"{len(stack_rows)} CloudFormation stacks in {region}",
        )
        for r in stack_rows:
            rels = [
                {"kind": "contains", "target": str(x["physical_id"])}
                for x in r["resources"]
                if x.get("physical_id")
            ]
            report.observations.append(
                adapter._obs(
                    r["id"],
                    "aws/cloudformation_stack",
                    {"account": account, "region": region, "id": r["id"], "name": r["name"]},
                    {k: v for k, v in r.items() if k not in {"id", "name"}},
                    scope_key,
                    eid,
                    rels,
                )
            )
        return complete

    raise ValueError(f"unsupported edge family {family}")
