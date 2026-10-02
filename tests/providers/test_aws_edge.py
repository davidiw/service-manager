"""Contract tests for metadata-only AWS edge discovery (all calls are fakes)."""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

import pytest

from local_ops.providers.aws_edge import discover


@dataclass
class Report:
    observations: list[Any] = field(default_factory=list)
    unavailable: list[dict[str, Any]] = field(default_factory=list)


class Ctx:
    def check_cancel(self) -> None:
        pass


class Budget:
    def check(self) -> None:
        pass


class Adapter:
    def __init__(
        self,
        pages: dict[tuple[str, str], list[dict[str, Any]]],
        calls: dict[tuple[str, str], Any] | None = None,
    ):
        self.pages, self.calls, self.evidence = pages, calls or {}, []  # type: dict[Any, Any], dict[Any, Any], list[dict[str, Any]]
        self.call_params: list[tuple[str, str, dict[str, Any]]] = []
        self.call_indices: dict[tuple[str, str], int] = {}

    @asynccontextmanager
    async def _client(self, service: str, region: str):
        yield service

    async def _paginate(
        self, client: str, operation: str, key: str, ctx: Any, budget: Any, **kwargs: Any
    ) -> tuple[list[Any], bool]:
        result: list[Any] = []
        for page in self.pages.get((client, operation), []):
            value: Any = page
            for part in key.split("."):
                value = value.get(part, []) if isinstance(value, dict) else []
            result.extend(value or [])
        return result, True

    async def _call(self, client: str, operation: str, **kwargs: Any) -> dict[str, Any]:
        self.call_params.append((client, operation, kwargs))
        key = (client, operation)
        if key not in self.calls and key in self.pages:
            index = self.call_indices.get(key, 0)
            self.call_indices[key] = index + 1
            return self.pages[key][index] if index < len(self.pages[key]) else {}
        value = self.calls.get(key, {})
        return value(kwargs) if callable(value) else value

    async def _evidence(
        self, ctx: Any, account: str, region: str, family: str, payload: dict[str, Any], summary: str
    ) -> str:
        self.evidence.append(payload)
        return "e1"

    def _fkey(self, account: str, region: str, family: str) -> str:
        return f"p/{account}/{region}/{family}"

    def _obs(self, *args: Any) -> tuple[Any, ...]:
        return args


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("family", "service", "pages", "calls", "rtype"),
    [
        (
            "sqs",
            "sqs",
            {
                ("sqs", "list_queues"): [
                    {"QueueUrls": ["https://sqs/x/one"]},
                    {"QueueUrls": ["https://sqs/x/two"]},
                ]
            },
            {("sqs", "list_queue_tags"): {"Tags": {"env": "test"}}},
            "aws/sqs_queue",
        ),
        (
            "sns",
            "sns",
            {
                ("sns", "list_topics"): [
                    {"Topics": [{"TopicArn": "arn:aws:sns:r:1:a"}]},
                    {"Topics": [{"TopicArn": "arn:aws:sns:r:1:b"}]},
                ],
                ("sns", "list_subscriptions_by_topic"): [
                    {
                        "Subscriptions": [
                            {"SubscriptionArn": "s", "Protocol": "sqs", "Endpoint": "arn:aws:sqs:r:1:q"}
                        ]
                    }
                ],
            },
            {("sns", "list_tags_for_resource"): {"Tags": [{"Key": "x", "Value": "y"}]}},
            "aws/sns_topic",
        ),
        (
            "apigateway",
            "apigateway",
            {
                ("apigateway", "get_rest_apis"): [
                    {"items": [{"id": "a", "name": "a"}]},
                    {"items": [{"id": "b", "name": "b"}]},
                ],
                ("apigateway", "get_resources"): [
                    {"items": [{"id": "root", "path": "/", "resourceMethods": {"GET": {}}}]}
                ],
            },
            {
                ("apigateway", "get_integration"): {
                    "type": "AWS_PROXY",
                    "uri": "arn:aws:lambda:r:1:function:f",
                }
            },
            "aws/apigateway_rest_api",
        ),
        (
            "cloudfront",
            "cloudfront",
            {
                ("cloudfront", "list_distributions"): [
                    {
                        "DistributionList": {
                            "Items": [
                                {
                                    "ARN": "arn:aws:cloudfront::1:distribution/a",
                                    "Id": "a",
                                    "Origins": {"Items": [{"DomainName": "origin.example"}]},
                                }
                            ]
                        }
                    },
                    {
                        "DistributionList": {
                            "Items": [{"ARN": "arn:aws:cloudfront::1:distribution/b", "Id": "b"}]
                        }
                    },
                ]
            },
            {("cloudfront", "list_tags_for_resource"): {"Tags": {"Items": []}}},
            "aws/cloudfront_distribution",
        ),
        (
            "wafv2",
            "wafv2",
            {
                ("wafv2", "list_web_acls"): [
                    {
                        "WebACLs": [{"Id": "a", "Name": "a", "ARN": "arn:aws:wafv2:r:1:a"}],
                        "NextMarker": "next",
                    },
                    {"WebACLs": [{"Id": "b", "Name": "b", "ARN": "arn:aws:wafv2:r:1:b"}]},
                ]
            },
            {
                ("wafv2", "get_web_acl"): {"WebACL": {"Id": "a", "Name": "a", "ARN": "arn:aws:wafv2:r:1:a"}},
                ("wafv2", "list_tags_for_resource"): {"TagInfoForResource": {"TagList": []}},
            },
            "aws/wafv2_web_acl",
        ),
        (
            "stepfunctions",
            "stepfunctions",
            {
                ("stepfunctions", "list_state_machines"): [
                    {
                        "stateMachines": [
                            {"stateMachineArn": "arn:aws:states:r:1:stateMachine:a", "name": "a"}
                        ]
                    },
                    {
                        "stateMachines": [
                            {"stateMachineArn": "arn:aws:states:r:1:stateMachine:b", "name": "b"}
                        ]
                    },
                ]
            },
            {("stepfunctions", "list_tags_for_resource"): {"tags": []}},
            "aws/stepfunctions_state_machine",
        ),
        (
            "cloudformation",
            "cloudformation",
            {
                ("cloudformation", "list_stacks"): [
                    {"StackSummaries": [{"StackId": "arn:aws:cloudformation:r:1:stack/a", "StackName": "a"}]},
                    {"StackSummaries": [{"StackId": "arn:aws:cloudformation:r:1:stack/b", "StackName": "b"}]},
                ],
                ("cloudformation", "list_stack_resources"): [
                    {
                        "StackResourceSummaries": [
                            {
                                "LogicalResourceId": "Bucket",
                                "PhysicalResourceId": "bucket-a",
                                "ResourceType": "AWS::S3::Bucket",
                            }
                        ]
                    }
                ],
            },
            {},
            "aws/cloudformation_stack",
        ),
    ],
)
async def test_each_family_paginates_metadata_only(
    family: str, service: str, pages: dict[Any, Any], calls: dict[Any, Any], rtype: str
) -> None:
    adapter = Adapter(pages, calls)
    report = Report()
    complete = await discover(adapter, family, Ctx(), Budget(), report, None, "1", "us-east-1", ["us-east-1"])
    assert complete and len(report.observations) == 2
    if family == "wafv2":
        assert any(
            params.get("NextMarker") == "next"
            for client, op, params in adapter.call_params
            if (client, op) == ("wafv2", "list_web_acls")
        )
    assert all(o[1] == rtype for o in report.observations)
    text = repr(adapter.evidence)
    assert (
        "SecretString" not in text
        and "GetSecretValue" not in text
        and "Definition" not in text
        and "TemplateBody" not in text
    )


@pytest.mark.asyncio
async def test_sns_relationships_and_apigateway_omit_sensitive_integration_fields() -> None:
    adapter = Adapter(
        {
            ("sns", "list_topics"): [{"Topics": [{"TopicArn": "arn:aws:sns:r:1:a"}]}],
            ("sns", "list_subscriptions_by_topic"): [
                {"Subscriptions": [{"Endpoint": "arn:aws:lambda:r:1:function:f"}]}
            ],
            ("apigateway", "get_rest_apis"): [{"items": [{"id": "a"}]}],
            ("apigateway", "get_resources"): [{"items": [{"id": "x", "resourceMethods": {"POST": {}}}]}],
        },
        {
            ("sns", "list_tags_for_resource"): {"Tags": []},
            ("apigateway", "get_integration"): {
                "uri": "arn:aws:lambda:r:1:function:f",
                "credentials": "secret-role",
                "requestTemplates": {"x": "secret-payload"},
            },
        },
    )
    report = Report()
    await discover(adapter, "sns", Ctx(), Budget(), report, None, "1", "r", ["r"])
    await discover(adapter, "apigateway", Ctx(), Budget(), report, None, "1", "r", ["r"])
    assert {"kind": "target", "target": "arn:aws:lambda:r:1:function:f"} in report.observations[0][-1]
    evidence = repr(adapter.evidence)
    assert "secret-role" not in evidence and "secret-payload" not in evidence


def test_botocore_models_expose_only_metadata_operations_used() -> None:
    from botocore.session import get_session

    expected = {
        "sqs": {"ListQueues", "ListQueueTags", "GetQueueAttributes"},
        "sns": {"ListTopics", "ListSubscriptionsByTopic", "ListTagsForResource"},
        "apigateway": {"GetRestApis", "GetResources", "GetIntegration"},
        "apigatewayv2": {"GetApis", "GetIntegrations"},
        "cloudfront": {"ListDistributions", "ListTagsForResource"},
        "wafv2": {"ListWebACLs", "GetWebACL", "ListTagsForResource"},
        "stepfunctions": {"ListStateMachines", "ListTagsForResource"},
        "cloudformation": {"ListStacks", "ListStackResources"},
    }
    session = get_session()
    for service, operations in expected.items():
        assert operations <= set(session.get_service_model(service).operation_names)
    # These assertions catch a future accidental reversion to the similarly named
    # but invalid tag parameter names before a live adapter call is attempted.
    sqs_attrs = session.get_service_model("sqs").operation_model("GetQueueAttributes").input_shape
    sns_tags = session.get_service_model("sns").operation_model("ListTagsForResource").input_shape
    waf_tags = session.get_service_model("wafv2").operation_model("ListTagsForResource").input_shape
    cloudfront_tags = (
        session.get_service_model("cloudfront").operation_model("ListTagsForResource").input_shape
    )
    assert sqs_attrs and {"QueueUrl", "AttributeNames"} <= set(sqs_attrs.members)
    assert sns_tags and "ResourceArn" in sns_tags.members
    assert waf_tags and {"ResourceARN", "NextMarker"} <= set(waf_tags.members)
    assert cloudfront_tags and "Resource" in cloudfront_tags.members


async def test_cloudformation_excludes_deleted_stacks_and_resources() -> None:
    adapter = Adapter({
        ("cloudformation", "list_stacks"): [
            {"StackSummaries": [{"StackId": "deleted", "StackStatus": "DELETE_COMPLETE"}]},
            {"StackSummaries": [{"StackId": "active", "StackStatus": "CREATE_COMPLETE"}]},
        ],
        ("cloudformation", "list_stack_resources"): [{"StackResourceSummaries": [
            {"PhysicalResourceId": "gone", "ResourceStatus": "DELETE_COMPLETE"},
            {"PhysicalResourceId": "live", "ResourceStatus": "CREATE_COMPLETE"},
        ]}],
    })
    report = Report()
    assert await discover(adapter, "cloudformation", Ctx(), Budget(), report, None, "1", "us-east-1", ["us-east-1"])
    assert len(report.observations) == 1
    assert report.observations[0][0] == "active"
    assert report.observations[0][-1] == [{"kind": "contains", "target": "live"}]
    assert "deleted" not in str(adapter.evidence)
    assert "gone" not in str(adapter.evidence)
