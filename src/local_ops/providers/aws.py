"""AWS adapter: account-scoped discovery and diagnosis/audit reads over aiobotocore.

Every call is asynchronous (`async with session.create_client(...)`); nothing here uses blocking boto3.
The adapter verifies the STS account against the configured `expected_account_id` before any read, treats
credential/SSO failures as `auth_required` (it never switches profiles), and reports every scope it could
not complete (region not enabled, permission denied, page cap, budget) as explicit coverage, not silence.
AWS session credentials never enter evidence: nothing from the credential chain is serialized, and raw pages
pass through the context sanitizer before they are stored.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import logging
import re
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import jmespath
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from local_ops.config import ProviderConfig, ServerConfig
from local_ops.models import Coverage, Effect, ErrorCode, OpsError, UnavailableScope, iso, utcnow
from local_ops.providers.base import (
    AdapterDescription,
    Availability,
    DiscoveryReport,
    DiscoveryScope,
    EvidenceResult,
    Observation,
    SupportedOperation,
)
from local_ops.providers.demo import normalize_cloudtrail, normalize_k8s_audit

if TYPE_CHECKING:
    from local_ops.operations.base import Budget, OperationContext
    from local_ops.providers.credentials import CredentialResolver

MAX_PAGES_PER_FAMILY = 50
EVIDENCE_ITEM_BOUND = 200
REGIONAL_FAMILIES = ["eks", "ec2", "elb", "rds", "ecr", "backup", "acm", "lambda", "ecs", "events", "autoscaling", "secretsmanager", "kms", "logs", "cloudwatch", "dynamodb", "elasticache", "efs", "opensearch", "sqs", "sns", "apigateway", "wafv2", "stepfunctions", "cloudformation", "identitycenter"]
GLOBAL_FAMILIES = ["s3", "route53", "iam", "organizations", "billing", "cloudfront"]
_DISCOVERY: ContextVar[dict[str, Any] | None] = ContextVar("aws_discovery", default=None)
_SSO_PREFLIGHT_SESSION: ContextVar[str | None] = ContextVar("aws_sso_preflight_session", default=None)
RESUMABLE_FAMILIES = {"logs", "secretsmanager"}
ALL_FAMILIES = ["sts", "regions", *REGIONAL_FAMILIES, *GLOBAL_FAMILIES]
EKS_LOG_TYPES = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
CLOUDTRAIL_RETENTION_NOTE = "CloudTrail event history: management events, last 90 days, per account/region"
GLOBAL = "global"

_AUTH_CODES = {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException", "AuthFailure", "InvalidIdentityToken", "RequestExpired", "SignatureDoesNotMatch", "InvalidSignatureException", "IncompleteSignature", "InvalidToken", "TokenRefreshRequired", "CredentialsNotSupported"}
_PERMISSION_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Client.UnauthorizedOperation", "UnauthorizedAccess", "UnauthorizedException", "AuthorizationError", "AuthorizationErrorException", "Forbidden", "NotAuthorized", "NotAuthorizedException"}
_REGION_CODES = {"OptInRequired", "InvalidRegion", "UnsupportedRegion"}
_THROTTLE_CODES = {"Throttling", "ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded", "LimitExceededException", "RequestThrottled"}
_NOT_FOUND_CODES = {"ResourceNotFoundException", "NoSuchEntity", "NoSuchEntityException", "NotFoundException", "NoSuchBucket", "NoSuchHostedZone", "ClusterNotFoundException", "DBInstanceNotFound", "RepositoryNotFoundException", "InvalidInstanceID.NotFound"}

_CLOCK_SKEW_CODES = {"RequestExpired", "RequestTimeTooSkewed"}
_CLOCK_SKEW_MESSAGE_MARKERS = (
    "signature expired",
    "request has expired",
    "request expired",
    "request time too skewed",
    "not yet current",
)


def _is_clock_skew(code: str, message: str) -> bool:
    """Only identify clock skew when AWS provides expiry/skew evidence.

    InvalidSignatureException, IncompleteSignature, and SignatureDoesNotMatch
    also cover malformed signing inputs. They remain authentication failures
    unless AWS's message specifically identifies signature expiry or skew.
    """
    return code in _CLOCK_SKEW_CODES or any(marker in message.casefold() for marker in _CLOCK_SKEW_MESSAGE_MARKERS)


def _assumed_role_name(arn: Any) -> str | None:
    """Extract only the role-name segment from a canonical STS assumed-role ARN."""
    if not isinstance(arn, str):
        return None
    match = re.fullmatch(r"arn:[^:]+:sts::\d{12}:assumed-role/([^/]+)/[^/]+", arn)
    return match.group(1) if match else None


def _sso_auth_required_message(session_name: str) -> str:
    return f"AWS SSO session {session_name!r} is not authenticated; run aws sso login for that session and retry."


class _SsoPreflightLogFilter(logging.Filter):
    """Suppress only aiobotocore's credential-refresh traceback for this task.

    aiobotocore logs mandatory refresh failures with ``exc_info=True`` before
    propagating them.  The ContextVar means concurrent providers and unrelated
    SDK work retain their normal logging behavior.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        session_name = _SSO_PREFLIGHT_SESSION.get()
        if (
            session_name
            and record.levelno >= logging.WARNING
            and record.exc_info
            and type(record.exc_info[1]).__name__
            in {"UnauthorizedSSOTokenError", "SSOTokenLoadError", "TokenRetrievalError", "CredentialRetrievalError", "SSOError"}
        ):
            record.msg = _sso_auth_required_message(session_name)
            record.args = ()
            record.exc_info = None
            record.exc_text = None
        return True


_AIO_CREDENTIALS_LOGGER = logging.getLogger("aiobotocore.credentials")
if not any(isinstance(existing, _SsoPreflightLogFilter) for existing in _AIO_CREDENTIALS_LOGGER.filters):
    _AIO_CREDENTIALS_LOGGER.addFilter(_SsoPreflightLogFilter())


def classify_boto_error(exc: BaseException) -> tuple[str, str]:
    """Map a botocore/aiobotocore exception to a stable (reason, human message) pair. The message never
    contains credential material: botocore messages carry error codes and operation names only."""
    if isinstance(exc, OpsError):
        return exc.code.value, exc.message
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {}) if isinstance(exc.response, dict) else {}
        code = str(err.get("Code") or "")
        op = str(exc.operation_name or "")
        msg = str(err.get("Message") or "")
        base = f"{op} failed with {code or 'unknown error'}" + (f": {msg}" if msg else "")
        if _is_clock_skew(code, msg):
            return "clock_skew", "AWS rejected this request because its signature time is expired or skewed; synchronize this host's clock (for example, enable NTP) and retry."
        if code in _AUTH_CODES:
            return "auth_required", f"AWS credentials rejected ({code}); re-authenticate the configured profile/SSO session. {base}"
        if code in _PERMISSION_CODES:
            return "permission_denied", base
        if code in _REGION_CODES:
            return "region_not_enabled", base
        if code in _THROTTLE_CODES:
            return "throttled", base
        if code in _NOT_FOUND_CODES:
            return "not_found", base
        return "provider_error", base
    if isinstance(exc, NoCredentialsError | PartialCredentialsError | ProfileNotFound):
        return "auth_required", f"AWS credentials unavailable: {type(exc).__name__}: {exc}"
    name = type(exc).__name__
    if name in {"UnauthorizedSSOTokenError", "SSOTokenLoadError", "TokenRetrievalError", "CredentialRetrievalError", "SSOError", "RefreshWithMFAUnsupportedError", "InvalidConfigError"}:
        return "auth_required", f"AWS SSO/credential session is not usable ({name}); run the provider's login flow again. {exc}"
    if isinstance(exc, EndpointConnectionError):
        return "provider_unavailable", f"could not reach AWS endpoint: {exc}"
    if isinstance(exc, BotoCoreError):
        return "provider_error", f"{name}: {exc}"
    if isinstance(exc, asyncio.TimeoutError | TimeoutError | ConnectionError | OSError):
        return "provider_unavailable", f"{name}: {exc}"
    return "provider_error", f"{name}: {exc}"


class _AwsCallError(Exception):
    """Wraps a provider exception with the API operation that raised it."""

    def __init__(self, operation: str, exc: BaseException):
        super().__init__(f"{operation}: {exc}")
        self.operation = operation
        self.exc = exc


def _ts(v: Any) -> Any:
    if isinstance(v, datetime):
        return iso(v if v.tzinfo else v.replace(tzinfo=UTC))
    return v


def _parse_time(v: Any) -> datetime | None:
    if v is None or v == "":
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=UTC)
    if isinstance(v, int | float):
        return datetime.fromtimestamp(float(v), tz=UTC)
    s = str(v)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _tags(tag_list: Any) -> dict[str, str]:
    if isinstance(tag_list, dict):
        return {str(k): str(v) for k, v in tag_list.items()}
    out: dict[str, str] = {}
    for t in tag_list or []:
        if isinstance(t, dict) and "Key" in t:
            out[str(t["Key"])] = str(t.get("Value", ""))
    return out


def _key_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _global_client_region(regions: list[str]) -> str:
    first = regions[0] if regions else "us-east-1"
    if first.startswith("cn-") or first.startswith("us-gov-"):
        return first
    return "us-east-1"


def _eks_logging(cluster: dict[str, Any]) -> dict[str, bool]:
    enabled = dict.fromkeys(EKS_LOG_TYPES, False)
    for entry in ((cluster.get("logging") or {}).get("clusterLogging") or []):
        if entry.get("enabled"):
            for t in entry.get("types") or []:
                enabled[str(t)] = True
    return enabled


def _iam_role_class(path: Any) -> str:
    """Deterministic role classification from its path; never from role name heuristics."""
    p = str(path or "/")
    if p.startswith("/aws-reserved/sso.amazonaws.com/"):
        return "identity_center"
    if p.startswith("/aws-service-role/"):
        return "service_linked"
    return "standard"


def _trust_principals(trust_policy: Any) -> dict[str, list[str]]:
    """Parse AssumeRolePolicyDocument's Principal entries. AWS returns this document as either a
    URL-encoded JSON string or an already-decoded dict depending on SDK/API path; handle both. Never
    reads any other part of the policy document (no Action/Resource/Condition)."""
    import urllib.parse

    doc: Any = trust_policy
    if isinstance(doc, str):
        parsed: Any = None
        for candidate in (doc, urllib.parse.unquote(doc)):
            try:
                parsed = json.loads(candidate)
                break
            except (ValueError, TypeError):
                continue
        doc = parsed
    if not isinstance(doc, dict):
        return {"services": [], "aws": [], "federated": []}
    services: set[str] = set()
    aws_principals: set[str] = set()
    federated: set[str] = set()
    statements = doc.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements or []:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            aws_principals.add("*")
            continue
        if not isinstance(principal, dict):
            continue
        for key, bucket in (("Service", services), ("AWS", aws_principals), ("Federated", federated)):
            val = principal.get(key)
            if val is None:
                continue
            if isinstance(val, str):
                bucket.add(val)
            elif isinstance(val, list):
                bucket.update(str(v) for v in val)
    return {"services": sorted(services), "aws": sorted(aws_principals), "federated": sorted(federated)}


class AwsAdapter:
    kind = "aws"

    def __init__(self, config: ProviderConfig, server: ServerConfig, resolver: CredentialResolver | None, session_factory: Callable[[], Any] | None = None):
        self.config = config
        self.server = server
        self.provider_id = config.id
        self.resolver = resolver
        self.session_factory = session_factory
        self._session: Any = None
        self._identity: dict[str, Any] | None = None
        self._scrub: Callable[[Any], tuple[Any, dict[str, int]]] | None = None
        self._approved: bool = False

    # ---------------------------------------------------------------- plumbing
    async def session(self) -> Any:
        if self._session is None:
            if self.session_factory is not None:
                self._session = self.session_factory()
            else:
                self._session = await self._build_session()
        return self._session

    async def _build_session(self) -> Any:
        from aiobotocore.session import AioSession, get_session

        if self.resolver is None or not self.config.credential:
            raise OpsError(ErrorCode.AUTH_REQUIRED, f"aws provider {self.provider_id} has no credential configured")
        cred = await self.resolver.resolve(self.config.credential)
        if cred.profile:
            return AioSession(profile=cred.profile)
        if cred.env is not None:
            sess = get_session()
            sess.set_credentials(cred.env.get("AWS_ACCESS_KEY_ID", ""), cred.env.get("AWS_SECRET_ACCESS_KEY", ""), cred.env.get("AWS_SESSION_TOKEN"))
            return sess
        raise OpsError(ErrorCode.AUTH_REQUIRED, f"credential {self.config.credential!r} is not an AWS profile/SSO/static credential")

    def _client(self, service: str, region: str) -> Any:
        return self._session.create_client(service, region_name=region)

    async def _call(self, client: Any, operation: str, **kwargs: Any) -> dict[str, Any]:
        state = _DISCOVERY.get()
        for attempt in range(4):
            try:
                if state is None:
                    return await getattr(client, operation)(**kwargs)
                ctx, budget = state["ctx"], state["budget"]
                ctx.check_cancel()
                budget.check()
                async with asyncio.timeout(budget.remaining_seconds()):
                    async with state["semaphore"]:
                        ctx.check_cancel()
                        budget.check()
                        return await getattr(client, operation)(**kwargs)
            except TimeoutError as e:
                if state is not None:
                    raise OpsError(ErrorCode.LIMIT_REACHED, "AWS discovery budget exhausted") from e
                raise
            except (ClientError, BotoCoreError) as e:
                reason, _ = classify_boto_error(e)
                delay = 0.1 * (2 ** attempt)
                if state is not None and reason == "throttled" and attempt < 3 and state["budget"].remaining_seconds() > delay:
                    await asyncio.sleep(delay)
                    continue
                raise _AwsCallError(operation, e) from e
        raise AssertionError("unreachable retry state")

    async def _paginate(self, client: Any, operation: str, result_key: str, ctx: OperationContext, budget: Budget, *, max_pages: int | None = None, max_items: int | None = None, **kwargs: Any) -> tuple[list[Any], bool]:
        """Exhaust provider pagination within the deadline; diagnosis may request explicit limits."""
        items: list[Any] = []
        pages = 0
        try:
            it = aiter(client.get_paginator(operation).paginate(**kwargs))
            while True:
                if (max_pages is not None and pages >= max_pages) or (max_items is not None and len(items) >= max_items):
                    return (items[:max_items] if max_items is not None else items), False
                ctx.check_cancel()
                budget.check()
                try:
                    async with asyncio.timeout(budget.remaining_seconds()):
                        page = await anext(it)
                except StopAsyncIteration:
                    return items, True
                except TimeoutError as e:
                    raise OpsError(ErrorCode.LIMIT_REACHED, "AWS pagination budget exhausted") from e
                pages += 1
                items.extend(jmespath.search(result_key, page) or [])
        except (ClientError, BotoCoreError) as e:
            raise _AwsCallError(operation, e) from e

    async def _census_pages(self, client: Any, operation: str, result_key: str, ctx: OperationContext, budget: Budget, report: DiscoveryReport, **kwargs: Any) -> AsyncIterator[list[Any]]:
        """Page-boundary resume for flat, high-value inventories. No provider token leaves private state.

        The caller must normalize a yielded page before asking for the next. Proposed cursor advancement
        is committed by run_scan only after its observations are stored. Interrupted pages are replayed.
        A resumed suffix never authorizes missing-resource detection, even when it reaches the end.
        """
        state = _DISCOVERY.get()
        assert state is not None
        credential = ctx.config.credential(self.config.credential) if self.config.credential else None
        binding = {"provider": self.config.model_dump(mode="json"), "credential_reference": credential.model_dump(mode="json") if credential else None, "principal": ctx.principal.id, "identity": report.identity, "scope": state["scope"].model_dump(mode="json"), "scope_key": state["scope_key"], "operation": operation, "arguments": kwargs, "version": 1}
        key = hashlib.sha256(json.dumps(binding, sort_keys=True, default=str).encode()).hexdigest()
        saved = await ctx.db.discovery_checkpoint(key)
        cursor = (saved or {}).get("cursor")
        version = (saved or {}).get("version")
        token = cursor.get("next_token") if cursor else None
        state["resumed"] = bool(token)
        state["checkpoint_available"] = bool(token)
        update = {"key": key, "cursor": cursor, "expected_version": version}
        report.checkpoint_updates.append(update)
        token_field = "nextToken" if operation == "describe_log_groups" else "NextToken"
        seen_tokens: set[str] = set()
        while True:
            ctx.check_cancel()
            budget.check()
            params = {**kwargs, **({token_field: token} if token else {})}
            try:
                page = await self._call(client, operation, **params)
            except _AwsCallError as e:
                code = str(getattr(e.exc, "response", {}).get("Error", {}).get("Code", ""))
                if token and code in {"InvalidNextTokenException", "InvalidNextToken", "InvalidParameterException", "InvalidParameterValueException"}:
                    update["cursor"] = None
                    state["checkpoint_available"] = False
                    state["restart_reason"] = "provider_rejected_cursor"
                # Provider error messages may echo a rejected opaque token. Keep it private.
                safe = ClientError({"Error": {"Code": code or "ProviderError", "Message": "metadata paging failed; cursor withheld"}}, operation)
                raise _AwsCallError(operation, safe) from e
            yield jmespath.search(result_key, page) or []
            next_token = page.get(token_field)
            if next_token and (next_token == token or next_token in seen_tokens):
                update["cursor"] = None
                state["checkpoint_available"] = False
                raise _AwsCallError(operation, RuntimeError("provider repeated pagination token; must restart"))
            token = next_token
            update["cursor"] = {"next_token": token} if token else None
            state["checkpoint_available"] = bool(token)
            if not token:
                return
            seen_tokens.add(token)

    async def _fetch_identity(self) -> dict[str, Any]:
        session = await self.session()
        region = self.config.regions[0] if self.config.regions else "us-east-1"
        try:
            # aiobotocore resolves its credential provider while creating a
            # client, but signs requests lazily.  Force the one credential
            # refresh here so a missing SSO cache entry fails at the provider
            # boundary before STS/client retry machinery is involved.
            session_name = self._sso_session_name()
            log_context = _SSO_PREFLIGHT_SESSION.set(session_name)
            try:
                await self._preflight_credentials(session)
            finally:
                _SSO_PREFLIGHT_SESSION.reset(log_context)
            async with session.create_client("sts", region_name=region) as sts:
                resp = await self._call(sts, "get_caller_identity")
        except Exception as e:  # noqa: BLE001 - normalize all identity-boundary credential paths
            inner = e.exc if isinstance(e, _AwsCallError) else e
            if type(inner).__name__ in {"UnauthorizedSSOTokenError", "SSOTokenLoadError", "TokenRetrievalError", "CredentialRetrievalError", "SSOError"}:
                raise OpsError(
                    ErrorCode.AUTH_REQUIRED,
                    _sso_auth_required_message(self._sso_session_name()),
                    data={"reason": "auth_required", "provider_id": self.provider_id},
                ) from None
            raise
        ident = {"account": str(resp.get("Account")), "arn": resp.get("Arn"), "user_id": resp.get("UserId"), "account_alias": self.config.account_alias, "expected_account_id": self.config.expected_account_id, "expected_role": self.config.expected_role, "provider_id": self.provider_id}
        if self.config.expected_account_id and ident["account"] != self.config.expected_account_id:
            raise OpsError(ErrorCode.SCOPE_UNRESOLVED, f"account_mismatch: credential for provider {self.provider_id} resolves to a different AWS account than expected; refusing to read it", private_detail=f"expected={self.config.expected_account_id} actual={ident['account']}", data={"reason": "account_mismatch"})
        actual_role = _assumed_role_name(ident["arn"])
        if self.config.expected_role and (actual_role is None or not fnmatch.fnmatchcase(actual_role, self.config.expected_role)):
            raise OpsError(
                ErrorCode.SCOPE_UNRESOLVED,
                f"role_mismatch: credential for provider {self.provider_id} does not use the configured AWS role; refusing to read it",
                private_detail=f"expected={self.config.expected_role!r} actual={actual_role!r}",
                data={"reason": "role_mismatch"},
            )
        ident["approved"] = bool(self.config.expected_account_id)
        self._identity = ident
        return ident

    async def _preflight_credentials(self, session: Any) -> None:
        """Materialize the configured credentials once before creating STS.

        Fake sessions and alternate session factories need not implement this
        aiobotocore-specific hook.  Its result is deliberately discarded: no
        access key, secret, or token may leave the credential chain.
        """
        get_credentials = getattr(session, "get_credentials", None)
        if not callable(get_credentials):
            return
        credentials = await get_credentials()
        frozen = getattr(credentials, "get_frozen_credentials", None)
        if callable(frozen):
            result = frozen()
            if hasattr(result, "__await__"):
                await result

    def _sso_session_name(self) -> str:
        """Return a configured session selector without touching a token or its cache."""
        session = self._session
        scoped = getattr(session, "get_scoped_config", None)
        if callable(scoped):
            try:
                name = scoped().get("sso_session")
                if isinstance(name, str) and name:
                    return name
            except Exception:  # noqa: BLE001 - diagnostic fallback only
                pass
        credential = self.server.credential(self.config.credential) if self.config.credential else None
        return credential.profile if credential and credential.profile else self.config.credential or self.provider_id

    async def verified_identity(self) -> dict[str, Any]:
        if self._identity is None:
            await self._fetch_identity()
        assert self._identity is not None
        return self._identity

    def _identity_failure(self, exc: BaseException) -> tuple[str, str]:
        if isinstance(exc, OpsError) and exc.data.get("reason") in {"account_mismatch", "role_mismatch"}:
            return str(exc.data["reason"]), exc.message
        inner = exc.exc if isinstance(exc, _AwsCallError) else exc
        reason, msg = classify_boto_error(inner)
        if reason == "permission_denied":
            reason = "auth_required"
        return reason, msg

    def _raise_identity_error(self, exc: BaseException) -> OpsError:
        reason, msg = self._identity_failure(exc)
        code = {"auth_required": ErrorCode.AUTH_REQUIRED, "clock_skew": ErrorCode.AUTH_REQUIRED, "account_mismatch": ErrorCode.SCOPE_UNRESOLVED, "role_mismatch": ErrorCode.SCOPE_UNRESOLVED, "provider_unavailable": ErrorCode.PROVIDER_UNAVAILABLE}.get(reason, ErrorCode.PROVIDER_UNAVAILABLE)
        return OpsError(code, msg, data={"reason": reason, "provider_id": self.provider_id})

    # ---------------------------------------------------------------- description / availability
    def describe(self) -> AdapterDescription:
        ct_limits = ["CloudTrail event history is per account/region, management events only, 90 days", "Exactly one LookupAttribute is applied server-side; every other filter runs locally over a result set capped by max_pages/max_events"]
        ops = [
            SupportedOperation(name="discover", effect=Effect.READ, description="Account identity, enabled regions, and inventory families: " + ", ".join(REGIONAL_FAMILIES + GLOBAL_FAMILIES) + ".", provider_side_filters=["regions", "families", "repositories"], limitations=["Discovery pagination exhausts provider pages within the configured deadline; partial scopes never prove absence", "Log groups and Secrets Manager resume at committed page boundaries; other families restart", "IAM access-key identifiers are hashed; metadata only, no secret values", "Billing is a coverage signal, not a resource inventory"]),
            SupportedOperation(name="cloudtrail_events", effect=Effect.READ, description="CloudTrail management-event history (LookupEvents) per configured region.", provider_side_filters=["time_range", "one of: event_names[0] (EventName) > actors[0] (Username) > resource_names[0] (ResourceName) > event_source (EventSource)"], local_filters=["event_names", "actors", "resource_names", "event_source", "source_ips", "outcome"], limitations=ct_limits),
            SupportedOperation(name="cloudwatch_logs", effect=Effect.READ_WITH_BOOKKEEPING, description="CloudWatch Logs: FilterLogEvents when filter_pattern is given (plain read), otherwise a Logs Insights query job (read with bookkeeping: StartQuery creates a provider-side job).", provider_side_filters=["log_groups", "time_range", "filter_pattern", "query"], local_filters=[], limitations=["Insights queries are bounded by the operation budget; an unfinished job is stopped and reported as truncated", "Log group retention is reported when readable, otherwise unknown"]),
            SupportedOperation(name="cloudwatch_metrics", effect=Effect.READ, description="CloudWatch GetMetricData for an explicit list of metric queries.", provider_side_filters=["queries", "time_range", "period", "stat"], limitations=["At most 20 metric queries per call; datapoints bounded by max_events"]),
            SupportedOperation(name="guardduty_findings", effect=Effect.READ, description="Existing GuardDuty findings per region; never enables detectors.", provider_side_filters=["time_range (updatedAt)", "min_severity"], local_filters=["finding_types"], limitations=["Regions without a detector are reported as guardduty_not_enabled coverage gaps", "Findings are existing detections only; absence is not evidence of absence"]),
            SupportedOperation(name="kubernetes_audit", effect=Effect.READ, description="EKS kube-apiserver audit events delivered to CloudWatch Logs (/aws/eks/<cluster>/cluster).", provider_side_filters=["cluster_name", "time_range", "filter_pattern"], local_filters=["actors", "verbs", "namespaces", "resources"], limitations=["Requires EKS audit control-plane logging; disabled logging is a coverage gap, not a clean result", "S3 data events and EKS audit activity are not in CloudTrail event history"]),
            SupportedOperation(name="eks_log_coverage", effect=Effect.READ, description="EKS control-plane logging configuration and log-group retention per cluster.", provider_side_filters=["cluster_name", "regions"]),
        ]
        families = list(self.config.families) if self.config.families else list(ALL_FAMILIES)
        if "organizations" in families and not self.config.organizations_enumeration:
            families.remove("organizations")
        return AdapterDescription(
            provider_id=self.provider_id, kind=self.kind, description=self.config.description, operations=ops,
            required_credentials=[c for c in [self.config.credential] if c],
            credential_configured=bool(self.resolver and self.resolver.configured(self.config.credential)) or self.session_factory is not None,
            scope_constraints={"account_alias": self.config.account_alias, "expected_account_id": self.config.expected_account_id, "expected_role": self.config.expected_role, "regions": list(self.config.regions), "families": families, "organizations_enumeration": self.config.organizations_enumeration, "cloudtrail_lake_event_data_store": self.config.cloudtrail_lake_event_data_store},
            limitations=[
                "CloudTrail event history is per account/region, management events only, 90 days",
                "CloudTrail Lake / historical stores not queried unless cloudtrail_lake_event_data_store is set (then unsupported in this release: report as unavailable scope)",
                "S3 data events and EKS audit activity are not in event history",
                "Billing dimensions are cost aggregation, not an inventory",
                "Account identity is verified live via STS against expected_account_id and, when configured, expected_role; a familiar profile name is not proof of the approved principal",
            ],
            live_verified=self._identity is not None, families=families,
        )

    async def check_availability(self, *, live: bool = False) -> Availability:
        configured = self.session_factory is not None or bool(self.resolver and self.resolver.configured(self.config.credential))
        if not configured:
            return Availability(available=False, reason="credential_not_configured", detail=f"no usable AWS credential reference for provider {self.provider_id}")
        if not live:
            return Availability(available=True, reason="configured_not_live_checked", detail="STS identity not verified in this check")
        self._identity = None
        try:
            ident = await self._fetch_identity()
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001
            reason, msg = self._identity_failure(e)
            return Availability(available=False, reason=reason, detail=msg, checked_live=True)
        return Availability(available=True, identity=ident, checked_live=True)

    # ---------------------------------------------------------------- discovery
    def _selected_families(self, scope: DiscoveryScope) -> list[str]:
        requested = scope.families or self.config.families or ALL_FAMILIES
        fams = [f for f in ALL_FAMILIES if f in requested and (not self.config.families or f in self.config.families)]
        if "organizations" in fams and not self.config.organizations_enumeration:
            fams.remove("organizations")
        return fams

    def _selected_regions(self, scope: DiscoveryScope, report: DiscoveryReport | None = None) -> list[str]:
        if not scope.regions:
            return list(self.config.regions)
        allowed = [r for r in scope.regions if r in self.config.regions]
        if report is not None:
            for r in scope.regions:
                if r not in self.config.regions:
                    report.unavailable.append({"source": f"{self.provider_id}/{r}", "reason": "region_not_in_configured_scope", "detail": f"region {r} is not in the provider's configured regions"})
        return allowed

    def _fkey(self, account: str, region: str, family: str) -> str:
        """Scope key identifying provider, verified account, region/global and family. Old-format keys
        (pre-account) are never produced again; rows stored under them simply fall outside comparable
        scope for future scans (see DECISIONS.md)."""
        return f"{self.provider_id}/{account}/{region}/{family}"

    async def discover(self, ctx: OperationContext, scope: DiscoveryScope, budget: Budget) -> DiscoveryReport:
        from local_ops.providers import aws_data, aws_edge, aws_identity

        report = DiscoveryReport(provider_id=self.provider_id)
        self._scrub = ctx.sanitizer.scrub
        selected = self._selected_families(scope)
        regions = self._selected_regions(scope, report)
        cov: dict[str, Any] = {
            "supported_families": list(ALL_FAMILIES),
            "configured_families": list(self.config.families or ALL_FAMILIES),
            "requested_families": list(scope.families or self.config.families or ALL_FAMILIES),
            "regions_configured": list(self.config.regions),
            "regions_requested": list(scope.regions or self.config.regions),
            "regions_enabled": [], "region_denominator_known": False,
            "family_scopes": [], "resumable_families": sorted(RESUMABLE_FAMILIES),
            "unsupported_families": [f for f in (scope.families or self.config.families) if f not in ALL_FAMILIES],
        }
        report.aws_coverage = cov
        state: dict[str, Any] = {"ctx": ctx, "budget": budget, "scope": scope, "semaphore": asyncio.Semaphore(self.server.limits.provider_concurrency_per_provider)}
        context_token = _DISCOVERY.set(state)
        try:
            try:
                # Reverify on every discovery: a cached STS response is not current credential evidence.
                ident = await self._fetch_identity()
            except asyncio.CancelledError:
                report.unavailable.append({"source": self.provider_id, "reason": "cancelled"})
                report.truncated = True
                return report
            except Exception as e:  # noqa: BLE001
                reason, msg = self._identity_failure(e)
                if isinstance(e, OpsError) and e.code == ErrorCode.LIMIT_REACHED:
                    reason = "budget_exhausted"
                    report.truncated = True
                    report.partial_scopes.append(f"{self.provider_id}/identity")
                report.unavailable.append({"source": self.provider_id, "reason": reason, "detail": msg, "operation": "sts:GetCallerIdentity"})
                return report
            report.identity = ident
            account = str(ident["account"])
            approved = bool(ident.get("approved"))
            self._approved = approved
            cov["family_scopes"].append({"scope_key": self._fkey(account, GLOBAL, "sts"), "account": account, "region": GLOBAL, "family": "sts", "status": "complete", "absence_proven": False})
            if scope.accounts and account not in scope.accounts:
                report.unavailable.append({"source": self.provider_id, "reason": "account_not_requested"})
                return report
            if not approved:
                report.notes.append("No expected_account_id configured; account is unverified and observations cannot establish comparable completeness.")
            if "regions" in selected and regions:
                try:
                    regions = await self._check_enabled_regions(ctx, report, regions, budget, account, approved)
                except (OpsError, asyncio.CancelledError):
                    report.unavailable.append({"source": self.provider_id, "reason": "region_check_interrupted"})
            if not self.config.organizations_enumeration:
                report.notes.append("Organizations enumeration disabled; organization account denominator is unknown.")
            data_families = {"secretsmanager", "kms", "logs", "cloudwatch", "dynamodb", "elasticache", "efs", "opensearch"}
            edge_families = {"sqs", "sns", "apigateway", "cloudfront", "wafv2", "stepfunctions", "cloudformation"}
            identity_families = {"identitycenter"}
            plan = [(r, f) for r in regions for f in REGIONAL_FAMILIES] + [(GLOBAL, f) for f in GLOBAL_FAMILIES]
            interrupted: str | None = None
            for region, family in plan:
                scope_key = self._fkey(account, region, family)
                entry: dict[str, Any] = {"scope_key": scope_key, "account": account, "region": region, "family": family, "status": "not_attempted", "resumed": False, "checkpoint_available": False}
                cov["family_scopes"].append(entry)
                if family not in selected:
                    entry["reason"] = "not_selected" if family != "organizations" or self.config.organizations_enumeration else "organizations_disabled"
                    continue
                if interrupted:
                    entry["reason"] = interrupted
                    report.unavailable.append({"source": scope_key, "reason": interrupted, "detail": "not attempted"})
                    report.partial_scopes.append(scope_key)
                    continue
                state.update(scope_key=scope_key, resumed=False, checkpoint_available=False, restart_reason=None)
                before = len(report.unavailable)
                try:
                    ctx.check_cancel()
                    budget.check()
                    if family in data_families:
                        complete = await aws_data.discover(self, family, ctx, budget, report, scope, account, region, regions)
                    elif family in edge_families:
                        complete = await aws_edge.discover(self, family, ctx, budget, report, scope, account, region, regions)
                    elif family in identity_families:
                        complete = await aws_identity.discover(self, family, ctx, budget, report, scope, account, region, regions)
                    else:
                        complete = await getattr(self, f"_fam_{family}")(ctx, budget, report, scope, account, region, regions)
                    complete = complete and len(report.unavailable) == before
                    entry["status"] = "complete" if complete and approved and not state["resumed"] else "partial_restart"
                    if complete and approved and not state["resumed"]:
                        report.completed_scopes.append(scope_key)
                    else:
                        report.partial_scopes.append(scope_key)
                        if state["resumed"]:
                            entry["absence_proven"] = False
                            entry["reason"] = "resumed_suffix_not_comparable_for_absence"
                    if not complete:
                        report.truncated = True
                except asyncio.CancelledError:
                    interrupted = "cancelled"
                    entry.update(status="partial_resumable" if state["checkpoint_available"] else "partial_restart", reason=interrupted)
                    report.partial_scopes.append(scope_key)
                    report.truncated = True
                except Exception as e:  # noqa: BLE001
                    if isinstance(e, OpsError) and e.code == ErrorCode.LIMIT_REACHED:
                        reason, message = "budget_exhausted", e.message
                        interrupted = reason
                    else:
                        reason, message = classify_boto_error(e.exc if isinstance(e, _AwsCallError) else e)
                    entry.update(status=("partial_restart" if state.get("restart_reason") else ("partial_resumable" if state["checkpoint_available"] else "partial_restart") if reason in {"budget_exhausted", "throttled"} else "unavailable"), reason=state.get("restart_reason") or reason)
                    report.unavailable.append({"source": scope_key, "reason": reason, "detail": message, "region": region, "family": family, "operation": getattr(e, "operation", None)})
                    report.partial_scopes.append(scope_key)
                    report.truncated = True
                entry["resumed"] = state["resumed"]
                entry["checkpoint_available"] = state["checkpoint_available"]
            for family in cov["unsupported_families"]:
                report.unavailable.append({"source": f"{self.provider_id}/{family}", "reason": "unsupported_family"})
            cov["regions_scanned"] = sorted({e["region"] for e in cov["family_scopes"] if e["region"] != GLOBAL and e["status"] != "not_attempted"})
            cov["interruptions"] = [u for u in report.unavailable if u.get("reason") in {"budget_exhausted", "throttled", "cancelled"}]
            cov["authorization_failures"] = [u for u in report.unavailable if u.get("reason") in {"permission_denied", "auth_required", "account_mismatch"}]
            return report
        finally:
            _DISCOVERY.reset(context_token)

    async def _check_enabled_regions(self, ctx: OperationContext, report: DiscoveryReport, regions: list[str], budget: Budget, account: str, approved: bool) -> list[str]:
        scope_key = self._fkey(account, regions[0], "regions")
        try:
            async with self._client("ec2", regions[0]) as ec2:
                resp = await self._call(ec2, "describe_regions", AllRegions=False)
        except _AwsCallError as e:
            reason, msg = classify_boto_error(e.exc)
            report.unavailable.append({"source": scope_key, "reason": reason, "operation": e.operation, "detail": msg})
            report.notes.append("enabled-region check unavailable; scanning configured regions as given")
            return regions
        enabled = {r.get("RegionName") for r in resp.get("Regions", [])}
        report.aws_coverage["regions_enabled"] = sorted(r for r in enabled if r)
        report.aws_coverage["region_denominator_known"] = True
        report.aws_coverage["regions_not_configured"] = sorted(r for r in enabled if r and r not in self.config.regions)
        eid = await ctx.store_evidence(self.provider_id, "aws_regions", {"enabled_regions": sorted(x for x in enabled if x)}, summary=f"{len(enabled)} enabled regions")
        kept: list[str] = []
        for r in regions:
            if r in enabled:
                kept.append(r)
            else:
                report.unavailable.append({"source": f"{self.provider_id}/{account}/{r}", "reason": "region_not_enabled", "detail": f"region {r} is not enabled for this account", "evidence_id": eid})
        (report.completed_scopes if approved else report.partial_scopes).append(scope_key)
        return kept

    async def _evidence(self, ctx: OperationContext, account: str, region: str, family: str, payload: dict[str, Any], summary: str) -> str:
        bounded: dict[str, Any] = {"account": account, "region": region, "family": family}
        for k, v in payload.items():
            if isinstance(v, list):
                bounded[k] = v[:EVIDENCE_ITEM_BOUND]
                bounded[f"{k}_count"] = len(v)
            else:
                bounded[k] = v
        return await ctx.store_evidence(self.provider_id, f"aws_{family}", bounded, summary=summary)

    def _obs(self, key: str, rtype: str, identity: dict[str, Any], attributes: dict[str, Any], scope_key: str, eid: str, relationships: list[dict[str, str]] | None = None) -> Observation:
        # Observations are public-facing projections; scrub credential-shaped strings (e.g. a tag value
        # containing an access key id) before they leave the adapter, independent of evidence scrubbing.
        if self._scrub is not None:
            identity = self._scrub(identity)[0]
            attributes = self._scrub(attributes)[0]
        return Observation(provider_id=self.provider_id, resource_key=key, resource_type=rtype, identity=identity, attributes=attributes, scope_key=scope_key, evidence_id=eid, relationships=relationships or [])

    async def _bounded_map(self, values: list[Any], fn: Callable[[Any], Awaitable[Any]]) -> list[Any]:
        """Run independent read enrichments with a fixed worker count.

        Workers pull directly from the input iterator, so a large account does not create one
        task per resource.  Ordering follows the provider listing for deterministic evidence.
        """
        results: list[Any] = [None] * len(values)
        next_index = 0
        lock = asyncio.Lock()

        async def worker() -> None:
            nonlocal next_index
            while True:
                async with lock:
                    if next_index >= len(values):
                        return
                    index = next_index
                    next_index += 1
                results[index] = await fn(values[index])

        try:
            async with asyncio.TaskGroup() as group:
                for _ in range(min(len(values), self.server.limits.provider_concurrency_per_provider)):
                    group.create_task(worker())
        except ExceptionGroup as errors:
            # TaskGroup drains siblings; preserve the underlying classified provider/budget failure.
            raise errors.exceptions[0] from errors
        return results

    # ---- regional families
    async def _fam_eks(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "eks")
        async with self._client("eks", region) as eks:
            names, complete = await self._paginate(eks, "list_clusters", "clusters", ctx, budget)
            async def describe(name: str) -> dict[str, Any]:
                budget.check()
                return (await self._call(eks, "describe_cluster", name=name)).get("cluster") or {}
            clusters = await self._bounded_map(names, describe)
        eid = await self._evidence(ctx, account, region, "eks", {"clusters": clusters}, f"{len(clusters)} EKS clusters in {region}")
        for c in clusters:
            arn = c.get("arn") or f"arn:aws:eks:{region}:{account}:cluster/{c.get('name')}"
            vpc = c.get("resourcesVpcConfig") or {}
            logging = _eks_logging(c)
            rels = ([{"kind": "depends_on", "target": str(c.get("roleArn"))}] if c.get("roleArn") else []) + ([{"kind": "network_in", "target": str(vpc.get("vpcId"))}] if vpc.get("vpcId") else []) + [{"kind": "network_in", "target": str(x)} for x in (vpc.get("subnetIds") or []) + (vpc.get("securityGroupIds") or [])]
            control_plane_log_group = None
            if any(logging.values()):
                control_plane_log_group = f"/aws/eks/{c.get('name')}/cluster"
                rels.append({"kind": "logs_to", "target": f"arn:aws:logs:{region}:{account}:log-group:{control_plane_log_group}"})
            report.observations.append(self._obs(arn, "aws/eks_cluster", {"account": account, "region": region, "arn": arn, "name": c.get("name")}, {"version": c.get("version"), "platform_version": c.get("platformVersion"), "endpoint": c.get("endpoint"), "status": c.get("status"), "created_at": _ts(c.get("createdAt")), "logging": logging, "tags": c.get("tags") or {}, "role": c.get("roleArn"), "vpc_id": vpc.get("vpcId"), "subnet_ids": vpc.get("subnetIds") or [], "security_group_ids": vpc.get("securityGroupIds") or [], "endpoint_public_access": vpc.get("endpointPublicAccess"), "public_access_cidrs": vpc.get("publicAccessCidrs"), "control_plane_log_group": control_plane_log_group}, scope_key, eid, rels))
        return complete

    async def _fam_ec2(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "ec2")
        async with self._client("ec2", region) as ec2:
            reservations, complete = await self._paginate(ec2, "describe_instances", "Reservations", ctx, budget)
            instances = [i for r in reservations for i in (r.get("Instances") or [])]
            volumes, vcomplete = await self._paginate(ec2, "describe_volumes", "Volumes", ctx, budget)
            async def child(operation: str, key: str) -> tuple[list[dict[str, Any]], bool]:
                try:
                    return await self._paginate(ec2, operation, key, ctx, budget)
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{scope_key}/{operation}", "reason": reason, "operation": e.operation, "detail": msg})
                    return [], False
            vpcs, vc = await child("describe_vpcs", "Vpcs")
            subnets, sc = await child("describe_subnets", "Subnets")
            security_groups, gc = await child("describe_security_groups", "SecurityGroups")
            nat_gateways, nc = await child("describe_nat_gateways", "NatGateways")
        eid = await self._evidence(ctx, account, region, "ec2", {"instances": instances, "volumes": volumes, "vpcs": vpcs, "subnets": subnets, "security_groups": security_groups, "nat_gateways": nat_gateways}, f"{len(instances)} instances, {len(volumes)} volumes, {len(vpcs)} VPCs in {region}")
        for i in instances:
            iid = i.get("InstanceId")
            tags = _tags(i.get("Tags"))
            rels: list[dict[str, str]] = []
            if tags.get("eks:cluster-name"):
                rels.append({"kind": "member_of", "target": f"arn:aws:eks:{region}:{account}:cluster/{tags['eks:cluster-name']}"})
            if tags.get("aws:autoscaling:groupName"):
                rels.append({"kind": "owner", "target": f"aws:{account}:{region}:autoscaling:{tags['aws:autoscaling:groupName']}"})
            if i.get("SubnetId"):
                rels.append({"kind": "network_in", "target": f"arn:aws:ec2:{region}:{account}:subnet/{i['SubnetId']}"})
            if i.get("VpcId"):
                rels.append({"kind": "network_in", "target": f"arn:aws:ec2:{region}:{account}:vpc/{i['VpcId']}"})
            for g in (i.get("SecurityGroups") or []):
                if g.get("GroupId"):
                    rels.append({"kind": "network_in", "target": f"arn:aws:ec2:{region}:{account}:security-group/{g['GroupId']}"})
            for b in (i.get("BlockDeviceMappings") or []):
                vol_id = (b.get("Ebs") or {}).get("VolumeId")
                if vol_id:
                    rels.append({"kind": "uses_volume", "target": f"arn:aws:ec2:{region}:{account}:volume/{vol_id}"})
            profile_arn = (i.get("IamInstanceProfile") or {}).get("Arn")
            if profile_arn:
                rels.append({"kind": "uses_instance_profile", "target": str(profile_arn)})
            arn = f"arn:aws:ec2:{region}:{account}:instance/{iid}"
            report.observations.append(self._obs(arn, "aws/ec2_instance", {"account": account, "region": region, "arn": arn, "instance_id": iid}, {"name": tags.get("Name"), "type": i.get("InstanceType"), "state": (i.get("State") or {}).get("Name"), "tags": tags, "private_ip": i.get("PrivateIpAddress"), "public_ip": i.get("PublicIpAddress"), "private_dns_name": i.get("PrivateDnsName"), "public_dns_name": i.get("PublicDnsName"), "platform": i.get("Platform"), "platform_details": i.get("PlatformDetails"), "architecture": i.get("Architecture"), "iam_instance_profile": profile_arn, "image_id": i.get("ImageId"), "launch_time": _ts(i.get("LaunchTime")), "vpc_id": i.get("VpcId"), "subnet_id": i.get("SubnetId"), "availability_zone": (i.get("Placement") or {}).get("AvailabilityZone"), "security_groups": [g.get("GroupId") for g in (i.get("SecurityGroups") or [])], "volume_ids": [(b.get("Ebs") or {}).get("VolumeId") for b in (i.get("BlockDeviceMappings") or []) if b.get("Ebs")]}, scope_key, eid, rels))
        attached = sum(1 for v in volumes if v.get("Attachments"))
        for v in volumes:
            vid = str(v.get("VolumeId"))
            arn = f"arn:aws:ec2:{region}:{account}:volume/{vid}"
            report.observations.append(self._obs(arn, "aws/ebs_volume", {"account": account, "region": region, "arn": arn, "volume_id": vid}, {"size_gib": v.get("Size"), "state": v.get("State"), "volume_type": v.get("VolumeType"), "iops": v.get("Iops"), "throughput": v.get("Throughput"), "encrypted": v.get("Encrypted"), "kms_key_id": v.get("KmsKeyId"), "availability_zone": v.get("AvailabilityZone"), "created_at": _ts(v.get("CreateTime")), "tags": _tags(v.get("Tags")), "attachments": [{"instance_id": a.get("InstanceId"), "device": a.get("Device"), "state": a.get("State")} for a in (v.get("Attachments") or [])]}, scope_key, eid, [{"kind": "attached_to", "target": f"arn:aws:ec2:{region}:{account}:instance/{a.get('InstanceId')}"} for a in (v.get("Attachments") or []) if a.get("InstanceId")] + ([{"kind": "encrypted_by", "target": str(v.get("KmsKeyId"))}] if v.get("KmsKeyId") else [])))
        for v in vpcs:
            vid = str(v.get("VpcId"))
            report.observations.append(self._obs(f"arn:aws:ec2:{region}:{account}:vpc/{vid}", "aws/vpc", {"account": account, "region": region, "vpc_id": vid}, {"cidr_blocks": [a.get("CidrBlock") for a in (v.get("CidrBlockAssociationSet") or [])] or [v.get("CidrBlock")], "state": v.get("State"), "is_default": v.get("IsDefault"), "tags": _tags(v.get("Tags"))}, scope_key, eid))
        for s in subnets:
            sid = str(s.get("SubnetId"))
            report.observations.append(self._obs(f"arn:aws:ec2:{region}:{account}:subnet/{sid}", "aws/subnet", {"account": account, "region": region, "subnet_id": sid, "vpc_id": s.get("VpcId")}, {"cidr": s.get("CidrBlock"), "availability_zone": s.get("AvailabilityZone"), "available_ips": s.get("AvailableIpAddressCount"), "map_public_ip_on_launch": s.get("MapPublicIpOnLaunch"), "tags": _tags(s.get("Tags"))}, scope_key, eid, [{"kind": "member_of", "target": f"arn:aws:ec2:{region}:{account}:vpc/{s.get('VpcId')}"}] if s.get("VpcId") else []))
        for g in security_groups:
            gid = str(g.get("GroupId"))
            report.observations.append(self._obs(f"arn:aws:ec2:{region}:{account}:security-group/{gid}", "aws/security_group", {"account": account, "region": region, "group_id": gid, "vpc_id": g.get("VpcId"), "name": g.get("GroupName")}, {"description": g.get("Description"), "ingress_rules": len(g.get("IpPermissions") or []), "egress_rules": len(g.get("IpPermissionsEgress") or []), "tags": _tags(g.get("Tags"))}, scope_key, eid, [{"kind": "member_of", "target": f"arn:aws:ec2:{region}:{account}:vpc/{g.get('VpcId')}"}] if g.get("VpcId") else []))
        for nat in nat_gateways:
            nid = str(nat.get("NatGatewayId"))
            report.observations.append(self._obs(f"arn:aws:ec2:{region}:{account}:natgateway/{nid}", "aws/nat_gateway", {"account": account, "region": region, "nat_gateway_id": nid, "vpc_id": nat.get("VpcId"), "subnet_id": nat.get("SubnetId")}, {"state": nat.get("State"), "created_at": _ts(nat.get("CreateTime")), "connectivity_type": nat.get("ConnectivityType"), "tags": _tags(nat.get("Tags"))}, scope_key, eid, [{"kind": "network_in", "target": str(nat.get("SubnetId"))}] if nat.get("SubnetId") else []))
        report.observations.append(self._obs(f"aws:{account}:{region}:ec2:volumes", "aws/ebs_volume_summary", {"account": account, "region": region, "id": "volumes"}, {"count": len(volumes), "attached": attached, "unattached": len(volumes) - attached, "total_size_gib": sum(int(v.get("Size") or 0) for v in volumes), "unencrypted": sum(1 for v in volumes if v.get("Encrypted") is False), "complete": vcomplete}, scope_key, eid))
        return complete and vcomplete and vc and sc and gc and nc

    async def _fam_elb(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "elb")
        target_health_scope_key = f"{scope_key}/target_health"
        async with self._client("elbv2", region) as elb:
            lbs, c1 = await self._paginate(elb, "describe_load_balancers", "LoadBalancers", ctx, budget)
            tgs, c2 = await self._paginate(elb, "describe_target_groups", "TargetGroups", ctx, budget)
            listeners: dict[str, list[dict[str, Any]]] = {}
            c3 = True
            async def list_listeners(lb: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
                budget.check()
                ls, ok = await self._paginate(elb, "describe_listeners", "Listeners", ctx, budget, LoadBalancerArn=lb.get("LoadBalancerArn"))
                return str(lb.get("LoadBalancerArn")), ls, ok
            for arn, ls, ok in await self._bounded_map(lbs, list_listeners):
                listeners[arn] = ls
                c3 = c3 and ok
            health: dict[str, list[dict[str, Any]]] = {}
            c4 = True
            async def describe_health(tg: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
                budget.check()
                tg_arn = str(tg.get("TargetGroupArn"))
                try:
                    resp = await self._call(elb, "describe_target_health", TargetGroupArn=tg_arn)
                    return tg_arn, resp.get("TargetHealthDescriptions") or [], True
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{target_health_scope_key}/{tg_arn}", "reason": reason, "operation": e.operation, "detail": msg})
                    return tg_arn, [], False
            for tg_arn, descriptions, ok in await self._bounded_map(tgs, describe_health):
                health[tg_arn] = descriptions
                c4 = c4 and ok
        (report.completed_scopes if (c4 and self._approved) else report.partial_scopes).append(target_health_scope_key)
        eid = await self._evidence(ctx, account, region, "elb", {"load_balancers": lbs, "target_groups": tgs, "listeners": [ln for ls in listeners.values() for ln in ls], "target_health": [h for hs in health.values() for h in hs]}, f"{len(lbs)} load balancers, {len(tgs)} target groups in {region}")
        for lb in lbs:
            arn = str(lb.get("LoadBalancerArn"))
            security_groups = lb.get("SecurityGroups") or []
            subnet_ids = [az.get("SubnetId") for az in (lb.get("AvailabilityZones") or []) if az.get("SubnetId")]
            availability_zones = [az.get("ZoneName") for az in (lb.get("AvailabilityZones") or []) if az.get("ZoneName")]
            rels = ([{"kind": "dns", "target": str(lb.get("DNSName"))}] if lb.get("DNSName") else []) + [{"kind": "network_in", "target": f"arn:aws:ec2:{region}:{account}:security-group/{sg}"} for sg in security_groups] + [{"kind": "network_in", "target": f"arn:aws:ec2:{region}:{account}:subnet/{sid}"} for sid in subnet_ids]
            report.observations.append(self._obs(arn, "aws/load_balancer", {"account": account, "region": region, "arn": arn, "name": lb.get("LoadBalancerName")}, {"dns_name": lb.get("DNSName"), "scheme": lb.get("Scheme"), "type": lb.get("Type"), "state": (lb.get("State") or {}).get("Code"), "vpc_id": lb.get("VpcId"), "created_at": _ts(lb.get("CreatedTime")), "security_groups": security_groups, "availability_zones": availability_zones, "subnets": subnet_ids, "canonical_hosted_zone_id": lb.get("CanonicalHostedZoneId"), "listeners": [{"port": ln.get("Port"), "protocol": ln.get("Protocol"), "certificates": [c.get("CertificateArn") for c in (ln.get("Certificates") or [])], "default_target_groups": [a.get("TargetGroupArn") for a in (ln.get("DefaultActions") or []) if a.get("TargetGroupArn")]} for ln in listeners.get(arn, [])]}, scope_key, eid, rels))
        for tg in tgs:
            arn = str(tg.get("TargetGroupArn"))
            rels = [{"kind": "serves", "target": str(lb_arn)} for lb_arn in (tg.get("LoadBalancerArns") or [])]
            target_type = tg.get("TargetType")
            targets: list[dict[str, Any]] = []
            for d in health.get(arn, []):
                t = d.get("Target") or {}
                tid = t.get("Id")
                th = d.get("TargetHealth") or {}
                targets.append({"id": tid, "port": t.get("Port"), "availability_zone": t.get("AvailabilityZone"), "health_state": th.get("State"), "health_reason": th.get("Reason")})
                if not tid:
                    continue
                if target_type == "instance":
                    rels.append({"kind": "routes_to", "target": f"arn:aws:ec2:{region}:{account}:instance/{tid}"})
                elif target_type == "lambda":
                    rels.append({"kind": "routes_to", "target": str(tid)})
                elif target_type == "ip":
                    rels.append({"kind": "routes_to_ip", "target": str(tid)})
            report.observations.append(self._obs(arn, "aws/target_group", {"account": account, "region": region, "arn": arn, "name": tg.get("TargetGroupName")}, {"protocol": tg.get("Protocol"), "port": tg.get("Port"), "target_type": target_type, "vpc_id": tg.get("VpcId"), "health_check_path": tg.get("HealthCheckPath"), "load_balancer_arns": tg.get("LoadBalancerArns") or [], "targets": targets}, scope_key, eid, rels))
        return c1 and c2 and c3

    async def _fam_rds(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "rds")
        async with self._client("rds", region) as rds:
            dbs, complete = await self._paginate(rds, "describe_db_instances", "DBInstances", ctx, budget)
            try:
                clusters, clusters_complete = await self._paginate(rds, "describe_db_clusters", "DBClusters", ctx, budget)
            except _AwsCallError as e:
                reason, msg = classify_boto_error(e.exc)
                report.unavailable.append({"source": f"{scope_key}/db_clusters", "reason": reason, "operation": e.operation, "detail": msg})
                clusters, clusters_complete = [], False
        eid = await self._evidence(ctx, account, region, "rds", {"db_instances": dbs, "db_clusters": clusters}, f"{len(dbs)} RDS instances, {len(clusters)} DB clusters in {region}")
        for db in dbs:
            arn = db.get("DBInstanceArn") or f"arn:aws:rds:{region}:{account}:db:{db.get('DBInstanceIdentifier')}"
            ep = db.get("Endpoint") or {}
            subnet = db.get("DBSubnetGroup") or {}
            rels = ([{"kind": "dns", "target": str(ep.get("Address"))}] if ep.get("Address") else []) + [{"kind": "network_in", "target": str(s.get("SubnetIdentifier"))} for s in (subnet.get("Subnets") or []) if s.get("SubnetIdentifier")] + [{"kind": "network_in", "target": str(s.get("VpcSecurityGroupId"))} for s in (db.get("VpcSecurityGroups") or []) if s.get("VpcSecurityGroupId")] + ([{"kind": "encrypted_by", "target": str(db.get("KmsKeyId"))}] if db.get("KmsKeyId") else [])
            report.observations.append(self._obs(arn, "aws/rds_instance", {"account": account, "region": region, "arn": arn, "identifier": db.get("DBInstanceIdentifier")}, {"engine": db.get("Engine"), "engine_version": db.get("EngineVersion"), "class": db.get("DBInstanceClass"), "status": db.get("DBInstanceStatus"), "endpoint": f"{ep.get('Address')}:{ep.get('Port')}" if ep.get("Address") else None, "backup_retention_days": db.get("BackupRetentionPeriod"), "multi_az": db.get("MultiAZ"), "storage_encrypted": db.get("StorageEncrypted"), "kms_key_id": db.get("KmsKeyId"), "subnet_group": subnet.get("DBSubnetGroupName"), "subnet_ids": [s.get("SubnetIdentifier") for s in (subnet.get("Subnets") or [])], "security_group_ids": [s.get("VpcSecurityGroupId") for s in (db.get("VpcSecurityGroups") or [])], "publicly_accessible": db.get("PubliclyAccessible"), "allocated_storage_gib": db.get("AllocatedStorage"), "cluster_identifier": db.get("DBClusterIdentifier"), "created_at": _ts(db.get("InstanceCreateTime")), "tags": _tags(db.get("TagList"))}, scope_key, eid, rels))
        for cluster in clusters:
            arn = str(cluster.get("DBClusterArn") or f"arn:aws:rds:{region}:{account}:cluster:{cluster.get('DBClusterIdentifier')}")
            sg_ids = [s.get("VpcSecurityGroupId") for s in (cluster.get("VpcSecurityGroups") or [])]
            rels = [{"kind": "network_in", "target": str(s)} for s in sg_ids if s] + ([{"kind": "encrypted_by", "target": str(cluster.get("KmsKeyId"))}] if cluster.get("KmsKeyId") else [])
            report.observations.append(self._obs(arn, "aws/rds_cluster", {"account": account, "region": region, "arn": arn, "identifier": cluster.get("DBClusterIdentifier")}, {"engine": cluster.get("Engine"), "engine_version": cluster.get("EngineVersion"), "status": cluster.get("Status"), "endpoint": cluster.get("Endpoint"), "reader_endpoint": cluster.get("ReaderEndpoint"), "members": [m.get("DBInstanceIdentifier") for m in (cluster.get("DBClusterMembers") or [])], "storage_encrypted": cluster.get("StorageEncrypted"), "kms_key_id": cluster.get("KmsKeyId"), "security_group_ids": sg_ids, "created_at": _ts(cluster.get("ClusterCreateTime")), "tags": _tags(cluster.get("TagList"))}, scope_key, eid, rels))
        return complete and clusters_complete

    async def _fam_ecr(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "ecr")
        filtered = bool(scope.repositories)
        kwargs: dict[str, Any] = {"repositoryNames": list(scope.repositories)} if filtered else {}
        if filtered:
            # `scope.repositories` is a field shared across providers (e.g. GitHub's owner/repo strings);
            # whatever its shape, a filtered listing is a strict subset of the account's repositories and
            # must never be mistaken for the comparable, unfiltered scope that `scope_key` identifies.
            report.notes.append(f"ecr: repository filter applied ({len(scope.repositories)} requested); this is a narrower scan than the full account/region inventory and is reported as partial")
        async with self._client("ecr", region) as ecr:
            try:
                repos, complete = await self._paginate(ecr, "describe_repositories", "repositories", ctx, budget, **kwargs)
            except _AwsCallError as e:
                reason, msg = classify_boto_error(e.exc)
                if filtered and reason == "not_found":
                    # a filter shaped for a different provider (e.g. "owner/repo") matching no ECR
                    # repository is an empty, partial result, not a failure of the whole family.
                    report.notes.append(f"ecr: repository filter matched no repositories ({msg})")
                    repos, complete = [], False
                else:
                    raise
            images: dict[str, list[dict[str, Any]]] = {}
            images_complete = True
            async def list_images(repo: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
                budget.check()
                imgs, img_complete = await self._paginate(ecr, "describe_images", "imageDetails", ctx, budget, repositoryName=repo.get("repositoryName"))
                imgs.sort(key=lambda d: _parse_time(d.get("imagePushedAt")) or datetime.min.replace(tzinfo=UTC), reverse=True)
                return str(repo.get("repositoryName")), imgs, img_complete
            for name, imgs, img_complete in await self._bounded_map(repos, list_images):
                images[name] = imgs
                images_complete = images_complete and img_complete
        eid = await self._evidence(ctx, account, region, "ecr", {"repositories": repos, "images": [i for imgs in images.values() for i in imgs]}, f"{len(repos)} ECR repositories in {region}")
        for repo in repos:
            arn = repo.get("repositoryArn") or f"arn:aws:ecr:{region}:{account}:repository/{repo.get('repositoryName')}"
            name = str(repo.get("repositoryName"))
            imgs = images.get(name, [])
            report.observations.append(self._obs(arn, "aws/ecr_repository", {"account": account, "region": region, "arn": arn, "name": name, "uri": repo.get("repositoryUri")}, {"created_at": _ts(repo.get("createdAt")), "image_tag_mutability": repo.get("imageTagMutability"), "scan_on_push": (repo.get("imageScanningConfiguration") or {}).get("scanOnPush"), "image_count": len(imgs), "latest_tags": [t for i in imgs[:5] for t in (i.get("imageTags") or [])]}, scope_key, eid))
            for img in imgs:
                digest = str(img.get("imageDigest"))
                report.observations.append(self._obs(f"{arn}@{digest}", "aws/ecr_image", {"account": account, "region": region, "repository_arn": arn, "repository": name, "digest": digest}, {"tags": img.get("imageTags") or [], "pushed_at": _ts(img.get("imagePushedAt")), "size_bytes": img.get("imageSizeInBytes"), "media_type": img.get("imageManifestMediaType"), "artifact_media_type": img.get("artifactMediaType"), "last_pulled_at": _ts(img.get("lastRecordedPullTime"))}, scope_key, eid, [{"kind": "owner", "target": arn}]))
        return complete and images_complete and not filtered

    async def _fam_backup(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "backup")
        filtered = bool(scope.vaults)
        async with self._client("backup", region) as bk:
            vaults, complete = await self._paginate(bk, "list_backup_vaults", "BackupVaultList", ctx, budget)
            if scope.vaults:
                vaults = [v for v in vaults if v.get("BackupVaultName") in scope.vaults]
                report.notes.append(f"backup: vault filter applied ({len(scope.vaults)} requested); this is a narrower scan than the full account/region inventory and is reported as partial")
            points: dict[str, list[dict[str, Any]]] = {}
            async def list_points(vault: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
                budget.check()
                name = str(vault.get("BackupVaultName"))
                found, ok = await self._paginate(bk, "list_recovery_points_by_backup_vault", "RecoveryPoints", ctx, budget, BackupVaultName=name)
                return name, found, ok
            for name, found, ok in await self._bounded_map(vaults, list_points):
                points[name] = found
                complete = complete and ok
        eid = await self._evidence(ctx, account, region, "backup", {"vaults": vaults, "recovery_points": [p for ps in points.values() for p in ps]}, f"{len(vaults)} backup vaults in {region}")
        for v in vaults:
            arn = v.get("BackupVaultArn") or f"arn:aws:backup:{region}:{account}:backup-vault:{v.get('BackupVaultName')}"
            name = str(v.get("BackupVaultName"))
            report.observations.append(self._obs(arn, "aws/backup_vault", {"account": account, "region": region, "arn": arn, "name": name}, {"created_at": _ts(v.get("CreationDate")), "number_of_recovery_points": v.get("NumberOfRecoveryPoints"), "locked": v.get("Locked"), "recent_recovery_points": [{"arn": p.get("RecoveryPointArn"), "status": p.get("Status"), "resource_type": p.get("ResourceType"), "resource_arn": p.get("ResourceArn"), "created_at": _ts(p.get("CreationDate")), "size_bytes": p.get("BackupSizeInBytes")} for p in points.get(name, [])]}, scope_key, eid, [{"kind": "protects", "target": str(p.get("ResourceArn"))} for p in points.get(name, []) if p.get("ResourceArn")]))
        return complete and not filtered

    async def _fam_acm(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "acm")
        async with self._client("acm", region) as acm:
            summaries, complete = await self._paginate(acm, "list_certificates", "CertificateSummaryList", ctx, budget, Includes={"keyTypes": ["RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1"]})
            async def describe(summary: dict[str, Any]) -> dict[str, Any]:
                budget.check()
                return (await self._call(acm, "describe_certificate", CertificateArn=summary.get("CertificateArn"))).get("Certificate") or {}
            certs = await self._bounded_map(summaries, describe)
        eid = await self._evidence(ctx, account, region, "acm", {"certificates": certs}, f"{len(certs)} ACM certificates in {region}")
        for c in certs:
            arn = str(c.get("CertificateArn"))
            not_after = _ts(c.get("NotAfter"))
            report.observations.append(self._obs(arn, "aws/acm_certificate", {"account": account, "region": region, "arn": arn, "domain": c.get("DomainName")}, {"domain": c.get("DomainName"), "subject_alternative_names": c.get("SubjectAlternativeNames") or [], "status": c.get("Status"), "type": c.get("Type"), "not_before": _ts(c.get("NotBefore")), "not_after": not_after, "in_use_by": c.get("InUseBy") or [], "renewal_eligibility": c.get("RenewalEligibility"), "issuer": c.get("Issuer")}, scope_key, eid, [{"kind": "serves", "target": str(u)} for u in (c.get("InUseBy") or [])]))
            if not_after:
                report.expiries.append({"resource_key": arn, "kind": "certificate", "expires_at": not_after, "domain": c.get("DomainName"), "status": c.get("Status"), "region": region})
        return complete

    async def _fam_lambda(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "lambda")
        async with self._client("lambda", region) as lam:
            fns, complete = await self._paginate(lam, "list_functions", "Functions", ctx, budget)
        # Environment values are credentials as often as not; evidence keeps only the variable names.
        fns = [{**f, "Environment": {"VariableNames": sorted((f.get("Environment") or {}).get("Variables") or {})}} if "Environment" in f else f for f in fns]
        eid = await self._evidence(ctx, account, region, "lambda", {"functions": fns}, f"{len(fns)} Lambda functions in {region}")
        for f in fns:
            arn = str(f.get("FunctionArn"))
            vpc = f.get("VpcConfig") or {}
            log_group = (f.get("LoggingConfig") or {}).get("LogGroup")
            rels = ([{"kind": "depends_on", "target": str(f.get("Role"))}] if f.get("Role") else []) + ([{"kind": "network_in", "target": str(vpc.get("VpcId"))}] if vpc.get("VpcId") else []) + [{"kind": "network_in", "target": str(x)} for x in (vpc.get("SubnetIds") or []) + (vpc.get("SecurityGroupIds") or [])] + ([{"kind": "logs_to", "target": f"arn:aws:logs:{region}:{account}:log-group:{log_group}"}] if log_group else [])
            report.observations.append(self._obs(arn, "aws/lambda_function", {"account": account, "region": region, "arn": arn, "name": f.get("FunctionName")}, {"runtime": f.get("Runtime"), "package_type": f.get("PackageType"), "handler": f.get("Handler"), "role": f.get("Role"), "memory_mb": f.get("MemorySize"), "timeout_seconds": f.get("Timeout"), "last_modified": f.get("LastModified"), "code_sha256": f.get("CodeSha256"), "version": f.get("Version"), "vpc_id": vpc.get("VpcId"), "subnet_ids": vpc.get("SubnetIds") or [], "security_group_ids": vpc.get("SecurityGroupIds") or [], "architectures": f.get("Architectures") or [], "log_group": log_group}, scope_key, eid, rels))
        return complete

    async def _fam_ecs(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "ecs")
        services: list[dict[str, Any]] = []
        task_definitions: list[dict[str, Any]] = []
        async with self._client("ecs", region) as ecs:
            cluster_arns, complete = await self._paginate(ecs, "list_clusters", "clusterArns", ctx, budget)
            for carn in cluster_arns:
                service_arns, ok = await self._paginate(ecs, "list_services", "serviceArns", ctx, budget, cluster=carn)
                complete = complete and ok
                for i in range(0, len(service_arns), 10):
                    budget.check()
                    resp = await self._call(ecs, "describe_services", cluster=carn, services=service_arns[i : i + 10])
                    services.extend(resp.get("services") or [])
            definition_arns = sorted({str(s.get("taskDefinition")) for s in services if s.get("taskDefinition")})
            async def describe_task_definition(arn: str) -> dict[str, Any]:
                budget.check()
                return (await self._call(ecs, "describe_task_definition", taskDefinition=arn, include=["TAGS"])).get("taskDefinition") or {}
            task_definitions = await self._bounded_map(definition_arns, describe_task_definition)
        # Project DescribeTaskDefinition before evidence is persisted: its raw response can contain
        # environment values, commands, entrypoints and arbitrary log-option values.
        task_definitions = [{"taskDefinitionArn": td.get("taskDefinitionArn"), "family": td.get("family"), "revision": td.get("revision"), "status": td.get("status"), "taskRoleArn": td.get("taskRoleArn"), "executionRoleArn": td.get("executionRoleArn"), "containers": [{"name": c.get("name"), "image": c.get("image"), "log_group": ((c.get("logConfiguration") or {}).get("options") or {}).get("awslogs-group"), "secret_refs": [s.get("valueFrom") for s in (c.get("secrets") or []) if s.get("valueFrom")]} for c in (td.get("containerDefinitions") or [])]} for td in task_definitions]
        eid = await self._evidence(ctx, account, region, "ecs", {"clusters": cluster_arns, "services": services, "task_definitions": task_definitions}, f"{len(cluster_arns)} ECS clusters, {len(services)} services in {region}")
        for carn in cluster_arns:
            report.observations.append(self._obs(str(carn), "aws/ecs_cluster", {"account": account, "region": region, "arn": carn, "name": str(carn).rsplit("/", 1)[-1]}, {}, scope_key, eid))
        for s in services:
            arn = str(s.get("serviceArn"))
            report.observations.append(self._obs(arn, "aws/ecs_service", {"account": account, "region": region, "arn": arn, "name": s.get("serviceName"), "cluster_arn": s.get("clusterArn")}, {"status": s.get("status"), "desired_count": s.get("desiredCount"), "running_count": s.get("runningCount"), "pending_count": s.get("pendingCount"), "task_definition": s.get("taskDefinition"), "launch_type": s.get("launchType"), "created_at": _ts(s.get("createdAt")), "load_balancers": [{"target_group_arn": lb.get("targetGroupArn"), "container": lb.get("containerName"), "port": lb.get("containerPort")} for lb in (s.get("loadBalancers") or [])]}, scope_key, eid, [{"kind": "member_of", "target": str(s.get("clusterArn"))}] + ([{"kind": "uses_task_definition", "target": str(s["taskDefinition"])}] if s.get("taskDefinition") else []) + [{"kind": "served_by", "target": str(lb.get("targetGroupArn"))} for lb in (s.get("loadBalancers") or []) if lb.get("targetGroupArn")]))
        for td in task_definitions:
            arn = str(td.get("taskDefinitionArn"))
            containers = td.get("containers") or []
            rels = ([{"kind": "depends_on", "target": str(td.get("taskRoleArn"))}] if td.get("taskRoleArn") else []) + ([{"kind": "depends_on", "target": str(td.get("executionRoleArn"))}] if td.get("executionRoleArn") else []) + [{"kind": "logs_to", "target": str(c["log_group"])} for c in containers if c.get("log_group")] + [{"kind": "uses_image", "target": str(c["image"])} for c in containers if c.get("image")]
            report.observations.append(self._obs(arn, "aws/ecs_task_definition", {"account": account, "region": region, "arn": arn, "family": td.get("family"), "revision": td.get("revision")}, {"status": td.get("status"), "task_role": td.get("taskRoleArn"), "execution_role": td.get("executionRoleArn"), "containers": containers}, scope_key, eid, rels))
        return complete

    async def _fam_events(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "events")
        async with self._client("events", region) as ev:
            # ListEventBuses exposes NextToken but has no botocore paginator.
            buses: list[dict[str, Any]] = []
            token: str | None = None
            seen_tokens: set[str] = set()
            while True:
                ctx.check_cancel()
                budget.check()
                page = await self._call(ev, "list_event_buses", **({"NextToken": token} if token else {}))
                buses.extend(page.get("EventBuses") or [])
                token = page.get("NextToken")
                if not token:
                    break
                if token in seen_tokens:
                    raise RuntimeError("EventBridge repeated pagination token; must restart")
                seen_tokens.add(token)
            complete = True
            rules: list[dict[str, Any]] = []
            for bus in buses:
                found, ok = await self._paginate(ev, "list_rules", "Rules", ctx, budget, EventBusName=bus.get("Name"))
                rules.extend(found)
                complete = complete and ok
            async def list_rule_targets(rule: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool]:
                found, ok = await self._paginate(ev, "list_targets_by_rule", "Targets", ctx, budget, Rule=rule.get("Name"), EventBusName=rule.get("EventBusName"))
                return str(rule.get("Arn")), found, ok
            target_map: dict[str, list[dict[str, Any]]] = {}
            for arn, found, ok in await self._bounded_map(rules, list_rule_targets):
                target_map[arn] = found
                complete = complete and ok
        # Event input can contain credentials or customer payloads; retain only target identity/type.
        eid = await self._evidence(ctx, account, region, "events", {"buses": buses, "rules": rules, "targets": [{"rule_arn": arn, "id": t.get("Id"), "arn": t.get("Arn"), "role_arn": t.get("RoleArn")} for arn, ts in target_map.items() for t in ts]}, f"{len(rules)} EventBridge rules in {region}")
        for r in rules:
            arn = str(r.get("Arn"))
            target_items = target_map.get(arn, [])
            report.observations.append(self._obs(arn, "aws/eventbridge_rule", {"account": account, "region": region, "arn": arn, "name": r.get("Name")}, {"state": r.get("State"), "schedule_expression": r.get("ScheduleExpression"), "event_pattern": r.get("EventPattern"), "event_bus_name": r.get("EventBusName"), "description": r.get("Description"), "managed_by": r.get("ManagedBy"), "targets": [{"id": t.get("Id"), "arn": t.get("Arn"), "role_arn": t.get("RoleArn")} for t in target_items]}, scope_key, eid, [{"kind": "targets", "target": str(t.get("Arn"))} for t in target_items if t.get("Arn")] + [{"kind": "depends_on", "target": str(t.get("RoleArn"))} for t in target_items if t.get("RoleArn")]))
        return complete

    async def _fam_autoscaling(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, region, "autoscaling")
        async with self._client("autoscaling", region) as asg:
            groups, complete = await self._paginate(asg, "describe_auto_scaling_groups", "AutoScalingGroups", ctx, budget)
        eid = await self._evidence(ctx, account, region, "autoscaling", {"groups": groups}, f"{len(groups)} auto scaling groups in {region}")
        for g in groups:
            name = g.get("AutoScalingGroupName")
            arn = g.get("AutoScalingGroupARN") or f"aws:{account}:{region}:autoscaling:{name}"
            name_key = f"aws:{account}:{region}:autoscaling:{name}"
            tags = _tags(g.get("Tags"))
            rels = [{"kind": "serves", "target": str(t)} for t in (g.get("TargetGroupARNs") or [])]
            if tags.get("eks:cluster-name"):
                rels.append({"kind": "member_of", "target": f"arn:aws:eks:{region}:{account}:cluster/{tags['eks:cluster-name']}"})
            rels.extend({"kind": "contains", "target": f"arn:aws:ec2:{region}:{account}:instance/{i.get('InstanceId')}"} for i in (g.get("Instances") or []) if i.get("InstanceId"))
            report.observations.append(self._obs(arn, "aws/autoscaling_group", {"account": account, "region": region, "arn": arn, "name": name, "name_key": name_key}, {"min_size": g.get("MinSize"), "max_size": g.get("MaxSize"), "desired_capacity": g.get("DesiredCapacity"), "instance_count": len(g.get("Instances") or []), "instance_ids": [i.get("InstanceId") for i in (g.get("Instances") or [])], "launch_template": (g.get("LaunchTemplate") or (g.get("MixedInstancesPolicy") or {}).get("LaunchTemplate", {}).get("LaunchTemplateSpecification") or {}).get("LaunchTemplateName"), "launch_configuration": g.get("LaunchConfigurationName"), "availability_zones": g.get("AvailabilityZones") or [], "target_group_arns": g.get("TargetGroupARNs") or [], "tags": tags, "created_at": _ts(g.get("CreatedTime"))}, scope_key, eid, rels))
        return complete

    # ---- global families
    async def _fam_s3(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        async with self._client("s3", _global_client_region(regions)) as s3:
            # ListBuckets gained continuation support; request its maximum page size but follow every
            # continuation token so accounts above one response are still comparable.
            buckets, buckets_complete = await self._paginate(s3, "list_buckets", "Buckets", ctx, budget, MaxBuckets=10_000)
            locations: dict[str, str] = {}
            for b in buckets:
                budget.check()
                ctx.check_cancel()
                name = str(b.get("Name"))
                try:
                    loc = (await self._call(s3, "get_bucket_location", Bucket=name)).get("LocationConstraint")
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{self._fkey(account, GLOBAL, 's3')}/{name}", "reason": reason, "operation": e.operation, "detail": msg})
                    locations[name] = "unknown"
                    continue
                locations[name] = "us-east-1" if not loc else ("eu-west-1" if loc == "EU" else str(loc))
        eid = await self._evidence(ctx, account, GLOBAL, "s3", {"buckets": [{**b, "region": locations.get(str(b.get("Name")))} for b in buckets]}, f"{len(buckets)} S3 buckets")
        skipped = []
        for b in buckets:
            name = str(b.get("Name"))
            breg = locations.get(name, "unknown")
            in_scope = breg in regions
            if not in_scope:
                skipped.append(f"{name} ({breg})")
            report.observations.append(self._obs(f"arn:aws:s3:::{name}", "aws/s3_bucket", {"account": account, "region": breg, "arn": f"arn:aws:s3:::{name}", "name": name}, {"created_at": _ts(b.get("CreationDate")), "skipped": not in_scope, "skip_reason": None if in_scope else ("region_unknown" if breg == "unknown" else "region_not_in_scope")}, self._fkey(account, breg, "s3"), eid))
        if skipped:
            report.notes.append(f"s3: {len(skipped)} buckets outside the configured regions were listed but not inspected: {', '.join(skipped[:20])}")
        locations_complete = "unknown" not in locations.values()
        for r in regions:
            (report.completed_scopes if self._approved and buckets_complete and locations_complete else report.partial_scopes).append(self._fkey(account, r, "s3"))
        return buckets_complete and locations_complete

    async def _fam_route53(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, GLOBAL, "route53")
        async with self._client("route53", _global_client_region(regions)) as r53:
            zones, complete = await self._paginate(r53, "list_hosted_zones", "HostedZones", ctx, budget)
            records: dict[str, tuple[list[dict[str, Any]], bool]] = {}
            for z in zones:
                budget.check()
                zid = str(z.get("Id"))
                records[zid] = await self._paginate(r53, "list_resource_record_sets", "ResourceRecordSets", ctx, budget, HostedZoneId=zid)
        eid = await self._evidence(ctx, account, GLOBAL, "route53", {"zones": zones, "records": [r for rs, _ in records.values() for r in rs]}, f"{len(zones)} hosted zones")
        for z in zones:
            zid = str(z.get("Id"))
            zone_id = zid.rsplit("/", 1)[-1]
            zkey = f"arn:aws:route53:::hostedzone/{zone_id}"
            # Each zone has a separate comparable record scope.  A failed child listing never borrows
            # completeness from the hosted-zone listing.
            records_scope_key = f"{scope_key}/{zone_id}/records"
            recs, rcomplete = records.get(zid, ([], True))
            (report.completed_scopes if (rcomplete and self._approved) else report.partial_scopes).append(records_scope_key)
            if not rcomplete:
                report.notes.append(f"route53 records could not be fully listed for zone {z.get('Name')}")
            report.observations.append(self._obs(zkey, "aws/route53_zone", {"account": account, "region": GLOBAL, "arn": zkey, "zone_id": zone_id, "name": z.get("Name")}, {"private": (z.get("Config") or {}).get("PrivateZone"), "record_count": z.get("ResourceRecordSetCount"), "records_listed": len(recs), "records_complete": rcomplete, "comment": (z.get("Config") or {}).get("Comment")}, scope_key, eid))
            for r in recs:
                rname, rtype = str(r.get("Name")), str(r.get("Type"))
                values = [v.get("Value") for v in (r.get("ResourceRecords") or [])]
                alias = (r.get("AliasTarget") or {}).get("DNSName")
                rels = [{"kind": "member_of", "target": zkey}]
                if alias:
                    rels.append({"kind": "dns", "target": str(alias)})
                report.observations.append(self._obs(f"aws:{account}:{GLOBAL}:route53:{zone_id}:{rname}:{rtype}" + (f":{r['SetIdentifier']}" if r.get("SetIdentifier") else ""), "aws/route53_record", {"account": account, "region": GLOBAL, "zone_id": zone_id, "name": rname, "type": rtype, "set_identifier": r.get("SetIdentifier")}, {"ttl": r.get("TTL"), "values": values, "alias_target": alias, "routing": "alias" if alias else "simple" if not r.get("SetIdentifier") else "weighted/latency/failover/geo", "health_check_id": r.get("HealthCheckId")}, records_scope_key, eid, rels))
        return complete

    async def _fam_iam(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, GLOBAL, "iam")
        groups_scope_key = f"{scope_key}/groups"
        policy_refs_scope_key = f"{scope_key}/policy_refs"
        instance_profiles_scope_key = f"{scope_key}/instance_profiles"
        async with self._client("iam", _global_client_region(regions)) as iam:
            users, c1 = await self._paginate(iam, "list_users", "Users", ctx, budget)
            roles, c2 = await self._paginate(iam, "list_roles", "Roles", ctx, budget)
            try:
                groups, groups_listed_ok = await self._paginate(iam, "list_groups", "Groups", ctx, budget)
            except _AwsCallError as e:
                reason, msg = classify_boto_error(e.exc)
                report.unavailable.append({"source": groups_scope_key, "reason": reason, "operation": e.operation, "detail": msg})
                groups, groups_listed_ok = [], False
            try:
                profiles, profiles_complete = await self._paginate(iam, "list_instance_profiles", "InstanceProfiles", ctx, budget)
            except _AwsCallError as e:
                reason, msg = classify_boto_error(e.exc)
                report.unavailable.append({"source": instance_profiles_scope_key, "reason": reason, "operation": e.operation, "detail": msg})
                profiles, profiles_complete = [], False

            keys: dict[str, list[dict[str, Any]]] = {}
            policy_refs_complete = True

            async def inspect_user(u: dict[str, Any]) -> tuple[str, list[dict[str, Any]], bool, list[dict[str, Any]], list[str], bool]:
                budget.check()
                uname = str(u.get("UserName"))
                try:
                    meta, keys_complete = await self._paginate(iam, "list_access_keys", "AccessKeyMetadata", ctx, budget, UserName=uname)
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{scope_key}/access_keys/{uname}", "reason": reason, "operation": e.operation, "detail": msg})
                    meta, keys_complete = [], False
                entries: list[dict[str, Any]] = []
                for k in meta:
                    kid = str(k.get("AccessKeyId") or "")
                    try:
                        last = (await self._call(iam, "get_access_key_last_used", AccessKeyId=kid)).get("AccessKeyLastUsed") or {}
                    except _AwsCallError as e:
                        reason, msg = classify_boto_error(e.exc)
                        report.unavailable.append({"source": f"{scope_key}/access_keys/{uname}", "reason": reason, "operation": e.operation, "detail": msg})
                        last = {}
                        keys_complete = False
                    entries.append({"access_key_hash": _key_hash(kid), "access_key_suffix": kid[-4:], "status": k.get("Status"), "created_at": _ts(k.get("CreateDate")), "last_used_at": _ts(last.get("LastUsedDate")), "last_used_service": last.get("ServiceName"), "last_used_region": last.get("Region")})
                try:
                    attached, _ = await self._paginate(iam, "list_attached_user_policies", "AttachedPolicies", ctx, budget, UserName=uname)
                    inline_names, _ = await self._paginate(iam, "list_user_policies", "PolicyNames", ctx, budget, UserName=uname)
                    refs_ok = True
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{policy_refs_scope_key}/user/{uname}", "reason": reason, "operation": e.operation, "detail": msg})
                    attached, inline_names, refs_ok = [], [], False
                return uname, entries, keys_complete, attached, inline_names, refs_ok

            access_keys_complete = True
            user_refs: dict[str, dict[str, Any]] = {}
            for uname, entries, user_complete, attached, inline_names, refs_ok in await self._bounded_map(users, inspect_user):
                keys[uname] = entries
                access_keys_complete = access_keys_complete and user_complete
                policy_refs_complete = policy_refs_complete and refs_ok
                user_refs[uname] = {"attached": attached, "inline_names": inline_names, "refs_ok": refs_ok}

            async def inspect_role(r: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[str], bool]:
                budget.check()
                rname = str(r.get("RoleName"))
                try:
                    attached, _ = await self._paginate(iam, "list_attached_role_policies", "AttachedPolicies", ctx, budget, RoleName=rname)
                    inline_names, _ = await self._paginate(iam, "list_role_policies", "PolicyNames", ctx, budget, RoleName=rname)
                    refs_ok = True
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{policy_refs_scope_key}/role/{rname}", "reason": reason, "operation": e.operation, "detail": msg})
                    attached, inline_names, refs_ok = [], [], False
                return rname, attached, inline_names, refs_ok

            role_refs: dict[str, dict[str, Any]] = {}
            for rname, attached, inline_names, refs_ok in await self._bounded_map(roles, inspect_role):
                policy_refs_complete = policy_refs_complete and refs_ok
                role_refs[rname] = {"attached": attached, "inline_names": inline_names, "refs_ok": refs_ok}

            async def inspect_group(g: dict[str, Any]) -> tuple[str, dict[str, Any], list[dict[str, Any]], bool, list[dict[str, Any]], list[str], bool]:
                budget.check()
                gname = str(g.get("GroupName"))
                try:
                    detail = await self._call(iam, "get_group", GroupName=gname)
                    group_meta = detail.get("Group") or {}
                    members = [{"user_name": uu.get("UserName"), "arn": uu.get("Arn")} for uu in (detail.get("Users") or [])]
                    members_ok = True
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{groups_scope_key}/{gname}", "reason": reason, "operation": e.operation, "detail": msg})
                    group_meta, members, members_ok = {}, [], False
                try:
                    attached, _ = await self._paginate(iam, "list_attached_group_policies", "AttachedPolicies", ctx, budget, GroupName=gname)
                    inline_names, _ = await self._paginate(iam, "list_group_policies", "PolicyNames", ctx, budget, GroupName=gname)
                    refs_ok = True
                except _AwsCallError as e:
                    reason, msg = classify_boto_error(e.exc)
                    report.unavailable.append({"source": f"{policy_refs_scope_key}/group/{gname}", "reason": reason, "operation": e.operation, "detail": msg})
                    attached, inline_names, refs_ok = [], [], False
                return gname, group_meta, members, members_ok, attached, inline_names, refs_ok

            groups_complete = True
            group_rows: list[tuple[str, dict[str, Any], list[dict[str, Any]], bool, list[dict[str, Any]], list[str], bool]] = []
            member_groups: dict[str, list[tuple[str, str]]] = {}
            for gname, group_meta, members, members_ok, attached, inline_names, refs_ok in await self._bounded_map(groups, inspect_group):
                groups_complete = groups_complete and members_ok
                policy_refs_complete = policy_refs_complete and refs_ok
                group_rows.append((gname, group_meta, members, members_ok, attached, inline_names, refs_ok))
                garn = str(group_meta.get("Arn") or f"arn:aws:iam::{account}:group{group_meta.get('Path') or '/'}{gname}")
                for m in members:
                    if m.get("user_name"):
                        member_groups.setdefault(str(m["user_name"]), []).append((gname, garn))

            summary_ok = True
            try:
                summary = (await self._call(iam, "get_account_summary")).get("SummaryMap") or {}
            except _AwsCallError as e:
                reason, msg = classify_boto_error(e.exc)
                report.unavailable.append({"source": f"{scope_key}/account_summary", "reason": reason, "operation": e.operation, "detail": msg})
                summary = {}
                summary_ok = False
        eid = await self._evidence(ctx, account, GLOBAL, "iam", {"users": users, "roles": roles, "groups": groups, "instance_profiles": profiles, "access_keys": [{"user": u, **k} for u, ks in keys.items() for k in ks], "account_summary": summary}, f"{len(users)} IAM users, {len(roles)} roles, {len(groups)} groups")
        # Access keys, account summary, groups, policy references and instance profiles each have
        # their own comparable scope; a child failure must not cause previously observed data under
        # another scope to be marked missing.
        access_keys_scope_key = f"{scope_key}/access_keys"
        summary_scope_key = f"{scope_key}/account_summary"
        (report.completed_scopes if (access_keys_complete and self._approved) else report.partial_scopes).append(access_keys_scope_key)
        (report.completed_scopes if (summary_ok and self._approved) else report.partial_scopes).append(summary_scope_key)
        (report.completed_scopes if (groups_listed_ok and groups_complete and self._approved) else report.partial_scopes).append(groups_scope_key)
        (report.completed_scopes if (policy_refs_complete and self._approved) else report.partial_scopes).append(policy_refs_scope_key)
        (report.completed_scopes if (profiles_complete and self._approved) else report.partial_scopes).append(instance_profiles_scope_key)
        for u in users:
            arn = str(u.get("Arn"))
            uname = str(u.get("UserName"))
            refs = user_refs.get(uname, {"attached": [], "inline_names": [], "refs_ok": False})
            groups_for_user = member_groups.get(uname, [])
            rels = [{"kind": "member_of", "target": garn} for _, garn in groups_for_user] + [{"kind": "attached_policy", "target": str(p.get("PolicyArn"))} for p in refs["attached"] if p.get("PolicyArn")]
            report.observations.append(self._obs(arn, "aws/iam_user", {"account": account, "region": GLOBAL, "arn": arn, "name": uname, "user_id": u.get("UserId")}, {"created_at": _ts(u.get("CreateDate")), "password_last_used": _ts(u.get("PasswordLastUsed")), "path": u.get("Path"), "access_keys": keys.get(uname), "access_keys_inspected": uname in keys, "tags": _tags(u.get("Tags")), "attached_policies": [{"name": p.get("PolicyName"), "arn": p.get("PolicyArn")} for p in refs["attached"]], "inline_policy_names": sorted(refs["inline_names"]), "group_names": sorted(gn for gn, _ in groups_for_user), "policy_refs_complete": refs["refs_ok"], "console_access_observed": u.get("PasswordLastUsed") is not None}, scope_key, eid, rels))
            for k in keys.get(uname, []):
                report.observations.append(self._obs(f"aws:{account}:{GLOBAL}:iam_access_key:{k['access_key_hash']}", "aws/iam_access_key", {"account": account, "region": GLOBAL, "user_arn": arn, "user": uname, "access_key_hash": k["access_key_hash"], "access_key_suffix": k["access_key_suffix"]}, {kk: v for kk, v in k.items() if kk not in ("access_key_hash", "access_key_suffix")}, access_keys_scope_key, eid, [{"kind": "owner", "target": arn}]))
        for r in roles:
            arn = str(r.get("Arn"))
            rname = str(r.get("RoleName"))
            refs = role_refs.get(rname, {"attached": [], "inline_names": [], "refs_ok": False})
            rels = [{"kind": "attached_policy", "target": str(p.get("PolicyArn"))} for p in refs["attached"] if p.get("PolicyArn")]
            report.observations.append(self._obs(arn, "aws/iam_role", {"account": account, "region": GLOBAL, "arn": arn, "name": rname, "role_id": r.get("RoleId")}, {"created_at": _ts(r.get("CreateDate")), "last_used_at": _ts((r.get("RoleLastUsed") or {}).get("LastUsedDate")), "last_used_region": (r.get("RoleLastUsed") or {}).get("Region"), "path": r.get("Path"), "max_session_duration": r.get("MaxSessionDuration"), "trust_policy": r.get("AssumeRolePolicyDocument"), "description": r.get("Description"), "tags": _tags(r.get("Tags")), "attached_policies": [{"name": p.get("PolicyName"), "arn": p.get("PolicyArn")} for p in refs["attached"]], "inline_policy_names": sorted(refs["inline_names"]), "policy_refs_complete": refs["refs_ok"], "role_class": _iam_role_class(r.get("Path")), "trust_principals": _trust_principals(r.get("AssumeRolePolicyDocument"))}, scope_key, eid, rels))
        for gname, group_meta, members, members_ok, attached, inline_names, refs_ok in group_rows:
            garn = str(group_meta.get("Arn") or f"arn:aws:iam::{account}:group{group_meta.get('Path') or '/'}{gname}")
            rels = [{"kind": "has_member", "target": str(m.get("arn"))} for m in members if m.get("arn")] + [{"kind": "attached_policy", "target": str(p.get("PolicyArn"))} for p in attached if p.get("PolicyArn")]
            report.observations.append(self._obs(garn, "aws/iam_group", {"account": account, "region": GLOBAL, "arn": garn, "name": gname, "group_id": group_meta.get("GroupId")}, {"created_at": _ts(group_meta.get("CreateDate")), "path": group_meta.get("Path"), "member_user_names": sorted(str(m.get("user_name")) for m in members if m.get("user_name")), "members_complete": members_ok, "attached_policies": [{"name": p.get("PolicyName"), "arn": p.get("PolicyArn")} for p in attached], "inline_policy_names": sorted(inline_names), "policy_refs_complete": refs_ok}, groups_scope_key, eid, rels))
        for p in profiles:
            arn = str(p.get("Arn"))
            role_arns = [ro.get("Arn") for ro in (p.get("Roles") or []) if ro.get("Arn")]
            rels = [{"kind": "contains_role", "target": str(ra)} for ra in role_arns]
            report.observations.append(self._obs(arn, "aws/iam_instance_profile", {"account": account, "region": GLOBAL, "arn": arn, "name": p.get("InstanceProfileName"), "instance_profile_id": p.get("InstanceProfileId")}, {"created_at": _ts(p.get("CreateDate")), "path": p.get("Path"), "role_arns": role_arns}, instance_profiles_scope_key, eid, rels))
        if summary:
            report.observations.append(self._obs(f"aws:{account}:{GLOBAL}:iam:summary", "aws/iam_account_summary", {"account": account, "region": GLOBAL, "id": "summary"}, {"summary": {str(k): v for k, v in summary.items()}, "root_mfa_enabled": bool(summary.get("AccountMFAEnabled")), "root_access_keys_present": bool(summary.get("AccountAccessKeysPresent"))}, summary_scope_key, eid))
        return c1 and c2

    async def _fam_organizations(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, GLOBAL, "organizations")
        async with self._client("organizations", _global_client_region(regions)) as org:
            accounts, complete = await self._paginate(org, "list_accounts", "Accounts", ctx, budget)
        eid = await self._evidence(ctx, account, GLOBAL, "organizations", {"accounts": accounts}, f"{len(accounts)} organization accounts")
        for a in accounts:
            arn = str(a.get("Arn"))
            report.observations.append(self._obs(arn, "aws/org_account", {"account": account, "region": GLOBAL, "arn": arn, "account_id": a.get("Id"), "name": a.get("Name")}, {"status": a.get("Status"), "email": a.get("Email"), "joined_at": _ts(a.get("JoinedTimestamp")), "joined_method": a.get("JoinedMethod"), "is_this_account": str(a.get("Id")) == account}, scope_key, eid))
        return complete

    async def _fam_billing(self, ctx: OperationContext, budget: Budget, report: DiscoveryReport, scope: DiscoveryScope, account: str, region: str, regions: list[str]) -> bool:
        scope_key = self._fkey(account, GLOBAL, "billing")
        end = utcnow().date()
        start = end - timedelta(days=30)
        results: list[dict[str, Any]] = []
        token: str | None = None
        complete = True
        async with self._client("ce", _global_client_region(regions)) as ce:
            while True:
                budget.check()
                kwargs: dict[str, Any] = {"TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()}, "Granularity": "MONTHLY", "Metrics": ["UnblendedCost"], "GroupBy": [{"Type": "DIMENSION", "Key": "LINKED_ACCOUNT"}, {"Type": "DIMENSION", "Key": "SERVICE"}]}
                if token:
                    kwargs["NextPageToken"] = token
                resp = await self._call(ce, "get_cost_and_usage", **kwargs)
                results.extend(resp.get("ResultsByTime") or [])
                token = resp.get("NextPageToken")
                if not token:
                    break
        totals: dict[tuple[str, str], dict[str, Any]] = {}
        for rt in results:
            for g in rt.get("Groups") or []:
                keys = g.get("Keys") or ["unknown"]
                linked_account, svc = (str(keys[0]), str(keys[1])) if len(keys) > 1 else (account, str(keys[0]))
                m = (g.get("Metrics") or {}).get("UnblendedCost") or {}
                try:
                    amount = float(m.get("Amount") or 0)
                except (TypeError, ValueError):
                    amount = 0.0
                t = totals.setdefault((linked_account, svc), {"amount": 0.0, "unit": m.get("Unit") or "USD"})
                t["amount"] += amount
        eid = await self._evidence(ctx, account, GLOBAL, "billing", {"results_by_time": results, "period": {"start": start.isoformat(), "end": end.isoformat()}}, f"cost by service over {start.isoformat()}..{end.isoformat()}: {len(totals)} account/service pairs")
        for (linked_account, svc), t in sorted(totals.items()):
            slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in svc).strip("-")
            report.observations.append(self._obs(f"aws:{linked_account}:{GLOBAL}:billing:{slug}", "aws/billing_service_cost", {"account": linked_account, "region": GLOBAL, "id": slug, "service": svc}, {"billing_source_account": account, "amount": round(t["amount"], 4), "unit": t["unit"], "period_start": start.isoformat(), "period_end": end.isoformat(), "granularity": "MONTHLY", "note": "cost aggregation by LINKED_ACCOUNT and SERVICE dimensions; not a resource inventory"}, scope_key, eid))
        return complete

    # ---------------------------------------------------------------- evidence queries
    def _query_regions(self, query: dict[str, Any]) -> list[str]:
        sc = query.get("scope") or {}
        regions = sc.get("regions") or ([sc["region"]] if sc.get("region") else None) or self.config.regions
        return [r for r in regions if r in self.config.regions] or list(self.config.regions)

    def _time_range(self, query: dict[str, Any], default_seconds: int = 3600) -> tuple[datetime, datetime]:
        tr = query.get("time_range") or {}
        end = _parse_time(tr.get("end")) or utcnow()
        start = _parse_time(tr.get("start")) or (end - timedelta(seconds=default_seconds))
        return start, end

    def _base_coverage(self, query: dict[str, Any], regions: list[str], account: str, start: datetime, end: datetime) -> Coverage:
        return Coverage(requested_sources=[self.provider_id], accounts_expected=[self.config.expected_account_id or account], accounts_reached=[account], regions_requested=list(regions), time_range_requested={"start": iso(start), "end": iso(end)})

    def _region_failure(self, cov: Coverage, region: str, e: _AwsCallError) -> None:
        reason, msg = classify_boto_error(e.exc)
        cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}", reason=reason, detail=f"{e.operation}: {msg}"))
        if reason in ("permission_denied", "auth_required"):
            cov.permission_failures.append(f"{self.provider_id}/{region}: {e.operation} ({reason})")
        else:
            cov.collection_gaps.append(f"{self.provider_id}/{region}: {e.operation} ({reason})")

    async def query(self, ctx: OperationContext, query: dict[str, Any], budget: Budget) -> EvidenceResult:
        qtype = query.get("query_type")
        handlers = {"cloudtrail_events": self._q_cloudtrail, "cloudwatch_logs": self._q_cloudwatch_logs, "cloudwatch_metrics": self._q_cloudwatch_metrics, "guardduty_findings": self._q_guardduty, "kubernetes_audit": self._q_kubernetes_audit, "eks_log_coverage": self._q_eks_log_coverage}
        handler = handlers.get(str(qtype))
        if handler is None:
            raise OpsError(ErrorCode.UNSUPPORTED_OPERATION, f"aws adapter does not support query_type {qtype!r}")
        try:
            ident = await self.verified_identity()
        except asyncio.CancelledError:
            raise
        except OpsError as e:
            if e.data.get("reason") == "account_mismatch":
                raise
            raise self._raise_identity_error(e) from e
        except Exception as e:  # noqa: BLE001
            raise self._raise_identity_error(e) from e
        self._session = await self.session()
        return await handler(ctx, query, budget, ident["account"])

    async def _identity_center_user_names(self, ctx: OperationContext) -> dict[str, str]:
        """Best-effort Identity Center `user_id -> display name` map, built only from observations already
        released to the requesting principal -- never fetched here, and never from AWS. No family in this
        codebase discovers `aws/identitystore_user` observations yet, so this is normally empty; the moment
        one does (publishing `identity.user_id` and `attributes.user_name`/`attributes.display_name`),
        CloudTrail normalization starts resolving Identity Center sign-in events automatically."""
        audience = ctx.principal.id if ctx.principal else None
        obs = await ctx.db.observations(provider_id=self.provider_id, audience=audience)
        names: dict[str, str] = {}
        for o in obs:
            if o.get("resource_type") != "aws/identitystore_user":
                continue
            uid = (o.get("identity") or {}).get("user_id")
            name = (o.get("attributes") or {}).get("user_name") or (o.get("attributes") or {}).get("display_name")
            if uid and name:
                names[uid] = name
        return names

    async def _q_cloudtrail(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        max_pages = int(limits.get("max_pages", 20))
        max_events = int(limits.get("max_events", 500))
        regions = self._query_regions(query)
        start, end = self._time_range(query, default_seconds=24 * 3600)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["management"]
        cov.source_retention_known = True
        cov.source_retention_note = CLOUDTRAIL_RETENTION_NOTE
        lookup: dict[str, str] | None = None
        used: str | None = None
        if filters.get("event_names"):
            lookup, used = {"AttributeKey": "EventName", "AttributeValue": str(filters["event_names"][0])}, "event_names[0]"
        elif filters.get("actors"):
            lookup, used = {"AttributeKey": "Username", "AttributeValue": str(filters["actors"][0])}, "actors[0]"
        elif filters.get("resource_names"):
            lookup, used = {"AttributeKey": "ResourceName", "AttributeValue": str(filters["resource_names"][0])}, "resource_names[0]"
        elif filters.get("event_source"):
            lookup, used = {"AttributeKey": "EventSource", "AttributeValue": str(filters["event_source"])}, "event_source"
        elif isinstance(filters.get("read_only"), bool):
            # ReadOnly=false keeps only mutating calls and sign-ins: the audit-relevant subset of a busy account
            lookup, used = {"AttributeKey": "ReadOnly", "AttributeValue": "true" if filters["read_only"] else "false"}, "read_only"
        cov.filters_provider_side = ["time_range"] + ([f"{used} ({lookup['AttributeKey']})"] if lookup and used else [])
        local: list[str] = []
        names = {str(x) for x in (filters.get("event_names") or [])}
        actors = [str(x) for x in (filters.get("actors") or [])]
        res_names = [str(x) for x in (filters.get("resource_names") or [])]
        event_source = filters.get("event_source")
        source_ips = {str(x) for x in (filters.get("source_ips") or [])}
        outcome = filters.get("outcome")
        if len(names) > 1 or (names and used != "event_names[0]"):
            local.append("event_names")
        if len(actors) > 1 or (actors and used != "actors[0]"):
            local.append("actors")
        if len(res_names) > 1 or (res_names and used != "resource_names[0]"):
            local.append("resource_names")
        if event_source and used != "event_source":
            local.append("event_source")
        if source_ips:
            local.append("source_ips")
        if outcome:
            local.append("outcome")
        read_only = filters.get("read_only") if isinstance(filters.get("read_only"), bool) else None
        if read_only is not None and used != "read_only":
            local.append("read_only")
        cov.filters_local = local

        def keep(e: dict[str, Any]) -> bool:
            ui = e.get("userIdentity") or {}
            actor_strs = [str(ui.get("userName") or ""), str(ui.get("arn") or ""), str(ui.get("principalId") or ""), str(((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName") or ""), str((ui.get("onBehalfOf") or {}).get("userId") or "")]
            if names and e.get("eventName") not in names:
                return False
            if actors and not any(a == s or (a and a in s) for a in actors for s in actor_strs):
                return False
            if res_names:
                rs = [str(r.get("ARN") or r.get("ResourceName") or "") for r in (e.get("resources") or [])] + [str(v) for v in (e.get("requestParameters") or {}).values() if isinstance(v, str)]
                if not any(rn == s or rn in s for rn in res_names for s in rs):
                    return False
            if event_source and e.get("eventSource") != event_source:
                return False
            if source_ips and str(e.get("sourceIPAddress")) not in source_ips:
                return False
            if outcome and (("failure" if e.get("errorCode") else "success") != outcome):
                return False
            if read_only is not None and used != "read_only" and str(e.get("readOnly")).lower() != str(read_only).lower():
                return False
            return True

        events: list[dict[str, Any]] = []
        eids: list[str] = []
        upstream_total = 0
        truncated = False
        identity_center_user_names = await self._identity_center_user_names(ctx)
        if self.config.cloudtrail_lake_event_data_store:
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/cloudtrail-lake/{self.config.cloudtrail_lake_event_data_store}", reason="unsupported_in_this_release", detail="CloudTrail Lake event data store is configured but Lake queries are not implemented; only 90-day event history was read"))
        for region in regions:
            ctx.check_cancel()
            raw: list[dict[str, Any]] = []
            token: str | None = None
            pages = 0
            region_complete = True
            try:
                async with self._client("cloudtrail", region) as ct:
                    while True:
                        budget.check()
                        kwargs: dict[str, Any] = {"StartTime": start, "EndTime": end, "MaxResults": 50}
                        if lookup:
                            kwargs["LookupAttributes"] = [lookup]
                        if token:
                            kwargs["NextToken"] = token
                        resp = await self._call(ct, "lookup_events", **kwargs)
                        raw.extend(resp.get("Events") or [])
                        pages += 1
                        token = resp.get("NextToken")
                        if not token:
                            break
                        # max_pages/max_events bound each region: a busy region must not starve the next one
                        if pages >= max_pages or len(raw) >= max_events:
                            region_complete = False
                            break
            except OpsError as e:
                if e.code != ErrorCode.LIMIT_REACHED:
                    raise
                region_complete = False
                cov.collection_gaps.append(f"{self.provider_id}/{region}: budget exhausted after {pages} pages")
            except _AwsCallError as e:
                self._region_failure(cov, region, e)
                continue
            upstream_total += len(raw)
            eid = await ctx.store_evidence(self.provider_id, "cloudtrail_events", {"account": account, "region": region, "lookup_attribute": lookup, "start": iso(start), "end": iso(end), "pages": pages, "events": raw}, summary=f"{len(raw)} CloudTrail events in {region}" + ("" if region_complete else " (capped)"))
            eids.append(eid)
            for ev in raw:
                try:
                    parsed = json.loads(ev.get("CloudTrailEvent") or "{}")
                except (TypeError, ValueError):
                    parsed = {}
                if not isinstance(parsed, dict) or not parsed:
                    parsed = {"eventID": ev.get("EventId"), "eventName": ev.get("EventName"), "eventTime": _ts(ev.get("EventTime")), "eventSource": ev.get("EventSource"), "userIdentity": {"userName": ev.get("Username")}, "resources": [{"ARN": r.get("ResourceName"), "resourceType": r.get("ResourceType")} for r in (ev.get("Resources") or [])], "readOnly": ev.get("ReadOnly")}
                if isinstance(parsed.get("eventTime"), datetime):
                    parsed["eventTime"] = _ts(parsed["eventTime"])
                if local and not keep(parsed):
                    continue
                events.append(normalize_cloudtrail(parsed, self.provider_id, eid, account, region, identity_center_user_names))
            if region_complete:
                cov.completed_scopes.append(f"{self.provider_id}/{region}")
                cov.regions_completed.append(region)
            else:
                truncated = True
                # LookupEvents returns newest first, so a capped region covers only the most recent part of the window
                oldest = min((_ts(ev.get("EventTime")) for ev in raw if ev.get("EventTime")), default=None)
                cov.collection_gaps.append(f"{self.provider_id}/{region}: upstream result set capped at {pages} pages / {len(raw)} events; covered {oldest or 'nothing'} .. {iso(end)} of requested {iso(start)} .. {iso(end)}")
        events.sort(key=lambda e: str(e.get("occurred_at") or ""))
        if events:
            cov.time_range_observed = {"first_event": events[0]["occurred_at"], "last_event": events[-1]["occurred_at"]}
        cov.truncated = truncated
        cov.pagination_complete = not truncated
        scope_parts = [f"CloudTrail event history for account {account}: management events only, per region, 90-day window; one server-side attribute ({cov.filters_provider_side[-1] if lookup else 'none'})."]
        if local:
            scope_parts.append(f"Local filters ({', '.join(local)}) ran over " + ("a capped upstream result set" if truncated else "the complete upstream result set") + f" of {upstream_total} events; absence of a match is not evidence of absence" + (" because the upstream set was capped." if truncated else " outside the server-side attribute and time range."))
        elif truncated:
            scope_parts.append("The upstream result set was capped; later events in the window were not read.")
        if cov.unavailable_scopes:
            scope_parts.append("Regions/stores listed as unavailable were not read.")
        scope_parts.append("No conclusion is implied about sources or scopes that were not completed.")
        cov.conclusion_scope = " ".join(scope_parts)
        return EvidenceResult(items=list(events), events=events, coverage=cov, cursor=None, raw_evidence_ids=eids, query_description={"query_type": "cloudtrail_events", "account": account, "regions": regions, "lookup_attribute": lookup, "local_filters": local, "start": iso(start), "end": iso(end), "max_pages": max_pages, "max_events": max_events, "upstream_events": upstream_total, "effect": Effect.READ.value})

    async def _q_cloudwatch_logs(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        sc = query.get("scope") or {}
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        log_groups = [str(g) for g in (sc.get("log_groups") or [])]
        if not log_groups:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "cloudwatch_logs requires scope.log_groups")
        max_pages = int(limits.get("max_pages", 20))
        max_events = int(limits.get("max_events", 500))
        max_duration = int(limits.get("max_duration_seconds", 120))
        regions = self._query_regions(query)
        start, end = self._time_range(query)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["logs"]
        items: list[dict[str, Any]] = []
        eids: list[str] = []
        truncated = False
        pattern = filters.get("filter_pattern")
        query_string = str(filters.get("query") or "fields @timestamp, @message | sort @timestamp desc | limit 200")
        mode = "filter_log_events" if pattern is not None else "logs_insights"
        effect = Effect.READ if pattern is not None else Effect.READ_WITH_BOOKKEEPING
        cov.filters_provider_side = ["log_groups", "time_range", "filter_pattern" if pattern is not None else "query"]
        jobs: list[dict[str, Any]] = []
        for region in regions:
            ctx.check_cancel()
            region_complete = True
            try:
                async with self._client("logs", region) as logs:
                    retention = await self._log_group_retention(logs, log_groups)
                    if pattern is not None:
                        raw_events: list[dict[str, Any]] = []
                        for group in log_groups:
                            token: str | None = None
                            pages = 0
                            while True:
                                budget.check()
                                kwargs: dict[str, Any] = {"logGroupName": group, "startTime": int(start.timestamp() * 1000), "endTime": int(end.timestamp() * 1000), "filterPattern": str(pattern), "limit": min(10_000, max_events)}
                                if token:
                                    kwargs["nextToken"] = token
                                try:
                                    resp = await self._call(logs, "filter_log_events", **kwargs)
                                except _AwsCallError as e:
                                    if classify_boto_error(e.exc)[0] == "not_found":
                                        cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}/{group}", reason="log_group_not_found", detail=f"{group} does not exist in {region}"))
                                        break
                                    raise
                                for ev in resp.get("events") or []:
                                    raw_events.append({"region": region, "log_group": group, "log_stream": ev.get("logStreamName"), "timestamp": _ts(datetime.fromtimestamp(int(ev.get("timestamp") or 0) / 1000, tz=UTC)), "message": ev.get("message"), "event_id": ev.get("eventId")})
                                pages += 1
                                token = resp.get("nextToken")
                                if not token:
                                    break
                                if pages >= max_pages or len(raw_events) >= max_events:
                                    region_complete = False
                                    break
                        eid = await ctx.store_evidence(self.provider_id, "cloudwatch_logs", {"account": account, "region": region, "mode": mode, "log_groups": log_groups, "filter_pattern": pattern, "retention": retention, "events": raw_events[:max_events]}, summary=f"{len(raw_events)} log events from {len(log_groups)} groups in {region}")
                        eids.append(eid)
                        items.extend({**e, "evidence_ref": eid} for e in raw_events[:max_events])
                    else:
                        budget.check()
                        try:
                            started = await self._call(logs, "start_query", logGroupNames=log_groups, startTime=int(start.timestamp()), endTime=int(end.timestamp()), queryString=query_string, limit=min(10_000, max_events))
                        except _AwsCallError as e:
                            if classify_boto_error(e.exc)[0] == "not_found":
                                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}", reason="log_group_not_found", detail=f"{e.operation}: one of {log_groups} does not exist in {region}"))
                                continue
                            raise
                        qid = str(started.get("queryId"))
                        job: dict[str, Any] = {"region": region, "query_id": qid, "status": "Running", "effect": Effect.READ_WITH_BOOKKEEPING.value, "bookkeeping": "StartQuery created a CloudWatch Logs Insights query job; it was polled with GetQueryResults"}
                        jobs.append(job)
                        t0 = utcnow()
                        results: list[Any] = []
                        stats: dict[str, Any] = {}
                        status = "Running"
                        while True:
                            resp = await self._call(logs, "get_query_results", queryId=qid)
                            status = str(resp.get("status") or "Unknown")
                            if status in ("Complete", "Failed", "Cancelled", "Timeout", "Unknown"):
                                results = list(resp.get("results") or [])
                                stats = dict(resp.get("statistics") or {})
                                break
                            elapsed = (utcnow() - t0).total_seconds()
                            if elapsed >= max_duration or budget.remaining_seconds() <= 1.5:
                                try:
                                    await self._call(logs, "stop_query", queryId=qid)
                                    job["bookkeeping"] += "; StopQuery was issued because the budget ran out"
                                except _AwsCallError:
                                    pass
                                status = "Stopped(budget)"
                                results = list(resp.get("results") or [])
                                region_complete = False
                                break
                            await asyncio.sleep(1)
                        job["status"] = status
                        job["statistics"] = stats
                        if status != "Complete":
                            region_complete = False
                            if status in ("Failed", "Cancelled", "Timeout", "Unknown"):
                                cov.collection_gaps.append(f"{self.provider_id}/{region}: Insights query ended with status {status}")
                        rows = [{"region": region, "log_groups": log_groups, **{str(f.get("field")): f.get("value") for f in row if isinstance(f, dict)}} for row in results]
                        eid = await ctx.store_evidence(self.provider_id, "cloudwatch_logs_insights", {"account": account, "region": region, "mode": mode, "log_groups": log_groups, "query_string": query_string, "query_id": qid, "status": status, "statistics": stats, "retention": retention, "results": rows[:max_events]}, summary=f"Insights query {status}: {len(rows)} rows in {region}")
                        eids.append(eid)
                        items.extend({**r, "evidence_ref": eid} for r in rows[:max_events])
                        if len(rows) > max_events:
                            region_complete = False
                    if retention:
                        cov.source_retention_known = True
                        cov.source_retention_note = "; ".join(f"{g}: {'never expires' if d is None else f'{d} days'}" for g, d in retention.items())
            except OpsError as e:
                if e.code != ErrorCode.LIMIT_REACHED:
                    raise
                region_complete = False
                cov.collection_gaps.append(f"{self.provider_id}/{region}: budget exhausted")
            except _AwsCallError as e:
                self._region_failure(cov, region, e)
                continue
            if region_complete:
                cov.completed_scopes.append(f"{self.provider_id}/{region}")
                cov.regions_completed.append(region)
            else:
                truncated = True
        cov.truncated = truncated
        cov.pagination_complete = not truncated
        cov.conclusion_scope = f"CloudWatch Logs ({mode}) over {log_groups} in {regions}; " + ("results were capped or the query job did not complete, so absence of a line is not evidence. " if truncated else "the result set is complete for the time range and pattern/query. ") + "No conclusion is implied about sources or scopes that were not completed."
        return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=eids, query_description={"query_type": "cloudwatch_logs", "mode": mode, "effect": effect.value, "account": account, "regions": regions, "log_groups": log_groups, "filter_pattern": pattern, "query_string": None if pattern is not None else query_string, "start": iso(start), "end": iso(end), "jobs": jobs}, notes=["Logs Insights StartQuery creates a provider-side query job (read_with_bookkeeping); no log data is modified."] if pattern is None else [])

    async def _log_group_retention(self, logs: Any, groups: list[str]) -> dict[str, int | None]:
        out: dict[str, int | None] = {}
        for g in groups[:10]:
            try:
                resp = await self._call(logs, "describe_log_groups", logGroupNamePrefix=g, limit=5)
            except _AwsCallError:
                continue
            for lg in resp.get("logGroups") or []:
                if lg.get("logGroupName") == g:
                    out[g] = lg.get("retentionInDays")
        return out

    async def _q_cloudwatch_metrics(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        sc = query.get("scope") or {}
        limits = query.get("limits") or {}
        queries = list(sc.get("queries") or [])
        if not queries:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "cloudwatch_metrics requires scope.queries")
        if len(queries) > 20:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "cloudwatch_metrics accepts at most 20 queries per call")
        max_pages = int(limits.get("max_pages", 20))
        max_datapoints = min(int(limits.get("max_events", 500)), 100_800)
        regions = self._query_regions(query)
        start, end = self._time_range(query)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["metrics"]
        cov.filters_provider_side = ["queries", "time_range", "period", "stat"]
        mdq = []
        for i, q in enumerate(queries):
            dims = q.get("dimensions") or {}
            dim_list = [{"Name": str(k), "Value": str(v)} for k, v in dims.items()] if isinstance(dims, dict) else [{"Name": str(d.get("Name") or d.get("name")), "Value": str(d.get("Value") or d.get("value"))} for d in dims]
            mdq.append({"Id": str(q.get("id") or f"q{i}"), "MetricStat": {"Metric": {"Namespace": str(q.get("namespace")), "MetricName": str(q.get("metric_name")), "Dimensions": dim_list}, "Period": int(q.get("period") or 300), "Stat": str(q.get("stat") or "Average")}, "ReturnData": True})
        items: list[dict[str, Any]] = []
        eids: list[str] = []
        truncated = False
        for region in regions:
            ctx.check_cancel()
            results: dict[str, dict[str, Any]] = {}
            token: str | None = None
            pages = 0
            region_complete = True
            try:
                async with self._client("cloudwatch", region) as cw:
                    while True:
                        budget.check()
                        kwargs: dict[str, Any] = {"MetricDataQueries": mdq, "StartTime": start, "EndTime": end, "MaxDatapoints": max_datapoints, "ScanBy": "TimestampDescending"}
                        if token:
                            kwargs["NextToken"] = token
                        resp = await self._call(cw, "get_metric_data", **kwargs)
                        for r in resp.get("MetricDataResults") or []:
                            slot = results.setdefault(str(r.get("Id")), {"id": r.get("Id"), "label": r.get("Label"), "timestamps": [], "values": [], "status_code": r.get("StatusCode"), "messages": []})
                            slot["timestamps"].extend(_ts(t) for t in (r.get("Timestamps") or []))
                            slot["values"].extend(r.get("Values") or [])
                            slot["status_code"] = r.get("StatusCode")
                            slot["messages"].extend(m.get("Value") for m in (r.get("Messages") or []))
                        pages += 1
                        token = resp.get("NextToken")
                        if not token:
                            break
                        if pages >= max_pages:
                            region_complete = False
                            break
            except OpsError as e:
                if e.code != ErrorCode.LIMIT_REACHED:
                    raise
                region_complete = False
            except _AwsCallError as e:
                self._region_failure(cov, region, e)
                continue
            eid = await ctx.store_evidence(self.provider_id, "cloudwatch_metrics", {"account": account, "region": region, "queries": mdq, "start": iso(start), "end": iso(end), "results": list(results.values())}, summary=f"{len(results)} metric series in {region}")
            eids.append(eid)
            for r in results.values():
                items.append({"region": region, **r, "datapoints": len(r["values"]), "evidence_ref": eid})
            if region_complete:
                cov.completed_scopes.append(f"{self.provider_id}/{region}")
                cov.regions_completed.append(region)
            else:
                truncated = True
        cov.truncated = truncated
        cov.pagination_complete = not truncated
        cov.conclusion_scope = "CloudWatch metric data for the listed queries only; a missing series means no datapoints were returned for that query, not that the resource is absent. No conclusion is implied about sources or scopes that were not completed."
        return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=eids, query_description={"query_type": "cloudwatch_metrics", "effect": Effect.READ.value, "account": account, "regions": regions, "queries": mdq, "start": iso(start), "end": iso(end)})

    async def _q_guardduty(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        max_events = int(limits.get("max_events", 500))
        max_pages = int(limits.get("max_pages", 20))
        regions = self._query_regions(query)
        tr = query.get("time_range") or {}
        start, end = self._time_range(query, default_seconds=30 * 24 * 3600)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["security_findings"]
        cov.filters_provider_side = ["time_range (updatedAt)"] + (["min_severity"] if filters.get("min_severity") is not None else [])
        types = {str(t) for t in (filters.get("finding_types") or [])}
        if types:
            cov.filters_local = ["finding_types"]
        criteria: dict[str, Any] = {"Criterion": {}}
        if tr.get("start") or tr.get("end"):
            criteria["Criterion"]["updatedAt"] = {"GreaterThanOrEqual": int(start.timestamp() * 1000), "LessThanOrEqual": int(end.timestamp() * 1000)}
        if filters.get("min_severity") is not None:
            criteria["Criterion"]["severity"] = {"GreaterThanOrEqual": int(float(filters["min_severity"]))}
        items: list[dict[str, Any]] = []
        eids: list[str] = []
        truncated = False
        for region in regions:
            ctx.check_cancel()
            try:
                async with self._client("guardduty", region) as gd:
                    detectors, _ = await self._paginate(gd, "list_detectors", "DetectorIds", ctx, budget, max_pages=5)
                    if not detectors:
                        cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}", reason="guardduty_not_enabled", detail=f"no GuardDuty detector in {region}; nothing was enabled"))
                        cov.disabled_logging.append(f"guardduty:{region}")
                        continue
                    region_complete = True
                    findings: list[dict[str, Any]] = []
                    for det in detectors:
                        kwargs: dict[str, Any] = {"DetectorId": det, "SortCriteria": {"AttributeName": "updatedAt", "OrderBy": "DESC"}}
                        if criteria["Criterion"]:
                            kwargs["FindingCriteria"] = criteria
                        ids, ok = await self._paginate(gd, "list_findings", "FindingIds", ctx, budget, max_pages=max_pages, max_items=max_events, **kwargs)
                        region_complete = region_complete and ok
                        for i in range(0, len(ids), 50):
                            budget.check()
                            resp = await self._call(gd, "get_findings", DetectorId=det, FindingIds=ids[i : i + 50])
                            findings.extend(resp.get("Findings") or [])
            except OpsError as e:
                if e.code != ErrorCode.LIMIT_REACHED:
                    raise
                truncated = True
                cov.collection_gaps.append(f"{self.provider_id}/{region}: budget exhausted")
                continue
            except _AwsCallError as e:
                self._region_failure(cov, region, e)
                continue
            if types:
                findings = [f for f in findings if str(f.get("Type")) in types]
            eid = await ctx.store_evidence(self.provider_id, "guardduty_findings", {"account": account, "region": region, "detectors": detectors, "criteria": criteria, "findings": findings}, summary=f"{len(findings)} GuardDuty findings in {region}")
            eids.append(eid)
            for f in findings:
                items.append({**{k: (_ts(v) if isinstance(v, datetime) else v) for k, v in f.items()}, "region": region, "evidence_ref": eid})
            if region_complete:
                cov.completed_scopes.append(f"{self.provider_id}/{region}")
                cov.regions_completed.append(region)
            else:
                truncated = True
        if items:
            times = sorted(str(i.get("UpdatedAt") or "") for i in items)
            cov.time_range_observed = {"first_event": times[0], "last_event": times[-1]}
        cov.truncated = truncated
        cov.pagination_complete = not truncated
        cov.source_retention_known = True
        cov.source_retention_note = "GuardDuty findings are retained for 90 days after last update; regions without a detector have no findings at all (not a clean result)"
        cov.conclusion_scope = "Existing GuardDuty findings only. Regions reported as guardduty_not_enabled have no detection coverage; absence of findings there is not evidence of absence. No conclusion is implied about sources or scopes that were not completed."
        return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=eids, query_description={"query_type": "guardduty_findings", "effect": Effect.READ.value, "account": account, "regions": regions, "criteria": criteria, "max_events": max_events})

    async def _describe_cluster(self, ctx: OperationContext, cov: Coverage, cluster: str, regions: list[str]) -> tuple[str, dict[str, Any]] | None:
        for region in regions:
            try:
                async with self._client("eks", region) as eks:
                    resp = await self._call(eks, "describe_cluster", name=cluster)
                return region, resp.get("cluster") or {}
            except _AwsCallError as e:
                if classify_boto_error(e.exc)[0] == "not_found":
                    continue
                self._region_failure(cov, region, e)
                return None
        cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/eks/{cluster}", reason="cluster_not_found", detail=f"EKS cluster {cluster} not found in {regions}"))
        return None

    async def _q_kubernetes_audit(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        sc = query.get("scope") or {}
        filters = query.get("filters") or {}
        limits = query.get("limits") or {}
        cluster = str(sc.get("cluster_name") or "")
        if not cluster:
            raise OpsError(ErrorCode.INVALID_ARGUMENT, "kubernetes_audit requires scope.cluster_name")
        max_pages = int(limits.get("max_pages", 20))
        max_events = int(limits.get("max_events", 500))
        regions = self._query_regions(query)
        start, end = self._time_range(query)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["kubernetes_audit"]
        cov.filters_provider_side = ["cluster_name", "time_range"] + (["filter_pattern"] if filters.get("filter_pattern") else [])
        local = [k for k in ("actors", "verbs", "namespaces", "resources") if filters.get(k)]
        cov.filters_local = local
        found = await self._describe_cluster(ctx, cov, cluster, regions)
        if found is None:
            cov.conclusion_scope = f"EKS cluster {cluster} could not be described; no audit evidence was read."
            return EvidenceResult(coverage=cov, query_description={"query_type": "kubernetes_audit", "cluster": cluster, "effect": Effect.READ.value})
        region, c = found
        cov.regions_requested = [region]
        arn = str(c.get("arn") or f"arn:aws:eks:{region}:{account}:cluster/{cluster}")
        logging = _eks_logging(c)
        qd: dict[str, Any] = {"query_type": "kubernetes_audit", "effect": Effect.READ.value, "account": account, "region": region, "cluster": cluster, "cluster_arn": arn, "logging": logging, "log_group": f"/aws/eks/{cluster}/cluster", "stream_prefix": "kube-apiserver-audit", "start": iso(start), "end": iso(end)}
        if not logging.get("audit"):
            cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}/eks/{cluster}/audit", reason="audit_log_source_not_available", detail=f"EKS control-plane audit logging is disabled for cluster {cluster}; no audit events are delivered to CloudWatch"))
            cov.disabled_logging.append(cluster)
            cov.clusters_covered = []
            cov.conclusion_scope = f"Audit logging is disabled for EKS cluster {cluster}: there is no audit log source, so nothing can be concluded about API activity on this cluster. This is a coverage gap, not a clean result."
            return EvidenceResult(coverage=cov, query_description=qd, notes=["Enable EKS control-plane audit logging to obtain kube-apiserver audit events; this adapter never changes logging configuration."])
        group = f"/aws/eks/{cluster}/cluster"
        raw: list[dict[str, Any]] = []
        token: str | None = None
        pages = 0
        complete = True
        retention: dict[str, int | None] = {}
        try:
            async with self._client("logs", region) as logs:
                retention = await self._log_group_retention(logs, [group])
                while True:
                    budget.check()
                    ctx.check_cancel()
                    kwargs: dict[str, Any] = {"logGroupName": group, "logStreamNamePrefix": "kube-apiserver-audit", "startTime": int(start.timestamp() * 1000), "endTime": int(end.timestamp() * 1000), "limit": min(10_000, max_events)}
                    if filters.get("filter_pattern"):
                        kwargs["filterPattern"] = str(filters["filter_pattern"])
                    if token:
                        kwargs["nextToken"] = token
                    resp = await self._call(logs, "filter_log_events", **kwargs)
                    raw.extend(resp.get("events") or [])
                    pages += 1
                    token = resp.get("nextToken")
                    if not token:
                        break
                    if pages >= max_pages or len(raw) >= max_events:
                        complete = False
                        break
        except OpsError as e:
            if e.code != ErrorCode.LIMIT_REACHED:
                raise
            complete = False
            cov.collection_gaps.append(f"{self.provider_id}/{region}: budget exhausted after {pages} pages")
        except _AwsCallError as e:
            if classify_boto_error(e.exc)[0] == "not_found":
                cov.unavailable_scopes.append(UnavailableScope(source=f"{self.provider_id}/{region}/eks/{cluster}/audit", reason="audit_log_group_not_found", detail=f"audit logging is enabled but log group {group} does not exist in {region}"))
                cov.conclusion_scope = f"EKS audit logging is enabled for {cluster} but its CloudWatch log group is missing; no audit evidence was read."
                return EvidenceResult(coverage=cov, query_description=qd)
            self._region_failure(cov, region, e)
            cov.conclusion_scope = f"Audit log group for {cluster} could not be read; no conclusion."
            return EvidenceResult(coverage=cov, query_description=qd)
        eid = await ctx.store_evidence(self.provider_id, "kubernetes_audit", {"account": account, "region": region, "cluster": cluster, "cluster_arn": arn, "log_group": group, "pages": pages, "retention": retention, "events": raw[:max_events]}, summary=f"{len(raw)} EKS audit log events for {cluster}")
        actors = [str(a) for a in (filters.get("actors") or [])]
        verbs = {str(v) for v in (filters.get("verbs") or [])}
        namespaces = {str(n) for n in (filters.get("namespaces") or [])}
        resources = {str(r) for r in (filters.get("resources") or [])}
        events: list[dict[str, Any]] = []
        unparsed = 0
        for ev in raw[:max_events]:
            try:
                rec = json.loads(ev.get("message") or "")
            except (TypeError, ValueError):
                unparsed += 1
                continue
            if not isinstance(rec, dict):
                unparsed += 1
                continue
            obj = rec.get("objectRef") or {}
            user = str((rec.get("user") or {}).get("username") or "")
            if actors and not any(a == user or a in user for a in actors):
                continue
            if verbs and str(rec.get("verb")) not in verbs:
                continue
            if namespaces and str(obj.get("namespace")) not in namespaces:
                continue
            if resources and str(obj.get("resource")) not in resources:
                continue
            events.append(normalize_k8s_audit(rec, self.provider_id, eid, cluster=arn))
        events.sort(key=lambda e: str(e.get("occurred_at") or ""))
        if events:
            cov.time_range_observed = {"first_event": events[0]["occurred_at"], "last_event": events[-1]["occurred_at"]}
        cov.clusters_covered = [arn]
        if complete:
            cov.completed_scopes.append(f"{self.provider_id}/{region}/eks/{cluster}/audit")
            cov.regions_completed.append(region)
        cov.truncated = not complete
        cov.pagination_complete = complete
        if group in retention:
            cov.source_retention_known = True
            cov.source_retention_note = f"{group}: " + ("never expires" if retention[group] is None else f"{retention[group]} days retention")
        if unparsed:
            cov.collection_gaps.append(f"{unparsed} log events were not valid JSON audit records")
        cov.conclusion_scope = f"EKS kube-apiserver audit events for cluster {cluster} delivered to CloudWatch; " + ("the upstream result set was capped, so " if not complete else "") + ("local filters ran over " + ("a capped" if not complete else "the complete") + " upstream result set; " if local else "") + "absence of an event is only meaningful inside the completed window. No conclusion is implied about sources or scopes that were not completed."
        return EvidenceResult(items=list(events), events=events, coverage=cov, raw_evidence_ids=[eid], query_description={**qd, "pages": pages, "local_filters": local})

    async def _q_eks_log_coverage(self, ctx: OperationContext, query: dict[str, Any], budget: Budget, account: str) -> EvidenceResult:
        sc = query.get("scope") or {}
        regions = self._query_regions(query)
        start, end = self._time_range(query)
        cov = self._base_coverage(query, regions, account, start, end)
        cov.event_categories = ["logging_configuration"]
        cov.filters_provider_side = ["cluster_name", "regions"]
        items: list[dict[str, Any]] = []
        eids: list[str] = []
        only = str(sc.get("cluster_name") or "")
        for region in regions:
            ctx.check_cancel()
            clusters: list[dict[str, Any]] = []
            retention: dict[str, int | None] = {}
            try:
                async with self._client("eks", region) as eks:
                    if only:
                        try:
                            clusters = [(await self._call(eks, "describe_cluster", name=only)).get("cluster") or {}]
                        except _AwsCallError as e:
                            if classify_boto_error(e.exc)[0] == "not_found":
                                continue
                            raise
                    else:
                        names, ok = await self._paginate(eks, "list_clusters", "clusters", ctx, budget)
                        if not ok:
                            cov.truncated = True
                        for n in names:
                            budget.check()
                            clusters.append((await self._call(eks, "describe_cluster", name=n)).get("cluster") or {})
                if clusters:
                    async with self._client("logs", region) as logs:
                        retention = await self._log_group_retention(logs, [f"/aws/eks/{c.get('name')}/cluster" for c in clusters])
            except OpsError as e:
                if e.code != ErrorCode.LIMIT_REACHED:
                    raise
                cov.truncated = True
                continue
            except _AwsCallError as e:
                self._region_failure(cov, region, e)
                continue
            eid = await ctx.store_evidence(self.provider_id, "eks_log_coverage", {"account": account, "region": region, "clusters": [{"name": c.get("name"), "arn": c.get("arn"), "logging": c.get("logging")} for c in clusters], "retention": retention}, summary=f"logging configuration for {len(clusters)} EKS clusters in {region}")
            eids.append(eid)
            for c in clusters:
                name = str(c.get("name"))
                logging = _eks_logging(c)
                group = f"/aws/eks/{name}/cluster"
                arn = str(c.get("arn") or f"arn:aws:eks:{region}:{account}:cluster/{name}")
                items.append({"cluster": name, "cluster_arn": arn, "region": region, "logging": logging, "audit_enabled": logging["audit"], "authenticator_enabled": logging["authenticator"], "log_group": group, "log_group_exists": group in retention, "retention_days": retention.get(group), "evidence_ref": eid})
                cov.clusters_covered.append(arn)
                if not logging["audit"]:
                    cov.disabled_logging.append(name)
            cov.completed_scopes.append(f"{self.provider_id}/{region}")
            cov.regions_completed.append(region)
        cov.conclusion_scope = "EKS control-plane logging configuration as currently set; clusters listed in disabled_logging have no audit log source and represent a coverage gap. No conclusion is implied about sources or scopes that were not completed."
        return EvidenceResult(items=items, coverage=cov, raw_evidence_ids=eids, query_description={"query_type": "eks_log_coverage", "effect": Effect.READ.value, "account": account, "regions": regions, "cluster_name": only or None})
