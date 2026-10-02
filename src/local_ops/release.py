"""Sanitization, disclosure projections and provenance.

Collected provider data is private until released. This module scrubs credential-shaped material at
ingestion, builds released projections (optionally redacted), and decides whether derived data may be
disclosed to a principal.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterable
from typing import Any

from local_ops.models import canonical_json

# Patterns for credential-shaped strings. Automated scrubbing is a floor, not a guarantee.
#
# `basic_auth_url` covers any `scheme://user:pass@` userinfo (not only http/https): Postgres, Redis,
# AMQP, Mongo `+srv` variants and the like all carry credentials the same way. The password class
# deliberately allows `@` and matches greedily so, on backtracking, it finds the *last* `@` before the
# host/path — a password containing `@` (e.g. `https://user:p@ss@host`) no longer leaks `ss@host`.
#
# `auth_header`/`cookie_header` cover header-shaped lines (`Authorization:`, `Proxy-Authorization:`,
# `Cookie:`, `Set-Cookie:`) as they appear in raw request/response text, independent of the dict-based
# field-name redaction below (which covers the same names when the data is structured).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)(aws_secret_access_key|secretaccesskey)[\"'\s:=]+[A-Za-z0-9/+=]{40}")),
    ("aws_session_token", re.compile(r"(?i)(aws_session_token|sessiontoken)[\"'\s:=]+[A-Za-z0-9/+=]{100,}")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("onepassword_token", re.compile(r"\bops_[A-Za-z0-9_\-]{20,}\b")),
    ("pagerduty_token", re.compile(r"(?i)(token token=)[A-Za-z0-9_\-+]{15,}")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{16,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("signed_url", re.compile(r"(?i)([?&](?:X-Amz-Signature|X-Amz-Credential|X-Amz-Security-Token|Signature|sig|token)=)(?!\[REDACTED:)[^&\s\"']+")),
    ("password_assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|token)\b[\"']?\s*[:=]\s*[\"']?(?!\[REDACTED:)([^\s\"',;]{6,})")),
    ("auth_header", re.compile(r"(?i)\b(authorization|proxy-authorization)([\"']?\s*[:=]\s*[\"']?)(?:basic|bearer|digest|token|negotiate|hoba|mutual|aws4-hmac-sha256)\s+[^\r\n]+")),
    ("cookie_header", re.compile(r"(?i)\b(set-cookie|cookie)(\s*:\s*)(?!\s*\[REDACTED:)[^\r\n]+")),
    ("basic_auth_url", re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)(?!\[REDACTED:)([^/\s:@]+):([^/\s]+)@")),
    ("local_ops_key", re.compile(r"\blop_[A-Za-z0-9._\-]+_[A-Za-z0-9_\-]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")),
    ("hex_secret_like", re.compile(r"(?i)\b(secret|key|token)[\"']?\s*[:=]\s*[\"']?[0-9a-f]{32,}\b")),
]
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")
# A Secrets Manager ARN is a resource identifier. Its final `secret:<name>` component is metadata,
# not a `secret=<value>` assignment. This deliberately follows the documented secret-name character
# grammar instead of accepting arbitrary non-whitespace data.
_SECRETS_MANAGER_ARN = re.compile(
    r"\barn:(?:aws|aws-us-gov|aws-cn):secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+"
)

SECRET_FIELD_NAMES = {
    "password", "passwd", "secret", "secretstring", "secretbinary", "token", "access_token", "refresh_token", "id_token",
    "accesskeyid", "secretaccesskey", "sessiontoken", "private_key", "privatekey", "client_secret", "authorization",
    "cookie", "set-cookie", "x-api-key", "api_key", "apikey", "credentials", "pass", "pwd", "data",  # k8s Secret.data
}

# Field-name matching below is normalized (lowercase, `-`/`_` stripped) and compound: it flags any name
# *containing* one of these keywords, not only an exact match, so `db_password`, `X-Auth-Token`,
# `private_token`, `client-secret`, `aws_secret_key` and `secret_key`/`access_key` are all caught.
_SECRET_KEYWORDS: tuple[str, ...] = (
    "password", "passwd", "secret", "token", "apikey", "privatekey", "credential", "authorization",
    "cookie", "accesskey", "secretkey",
)

# Non-secret reference/metadata fields the compound-keyword match above would otherwise flag, but that
# diagnosis needs verbatim. The exact names are Kubernetes API conventions whose *value* is a reference
# to a Secret object (fetched separately, with its own authorization) or plain metadata, never a
# credential literal: `secretName`/`secretRef`/`secretKeyRef` name which Secret/key to use without
# inlining it; `serviceAccountToken` (as a pod volume *projection config* block) holds audience/path/
# expiry, not a materialized token; `tokenType`/`tokenExpirationSeconds` describe a token, they are not
# one. Kept small and exact so it cannot accidentally swallow an unrelated field.
_NON_SECRET_FIELD_EXACT = {
    "secretname", "secretref", "secretkeyref", "serviceaccounttoken", "tokentype", "tokenexpirationseconds",
}
# Keywords for which a trailing `*_id` names a reference/correlation id ("which token was used"), not
# the secret value itself. Deliberately narrow: `password_id`/`secret_id`/`apikey_id` stay flagged
# (fail closed) because, unlike `token_id`, they are not an established non-secret convention.
_ID_SAFE_KEYWORDS = frozenset({"token"})
# Likewise for a trailing `*_hash`/`*_suffix`: this codebase's own safe-disclosure convention (D14) is
# to keep a one-way hash or a short suffix for identification, never the credential (AWS access key
# observations: `access_key_hash`, `access_key_suffix`). Narrow to `accesskey` on purpose —
# `password_hash`/`secret_hash` stay flagged (fail closed); nothing in this codebase relies on
# disclosing those.
_HASH_SUFFIX_SAFE_KEYWORDS = frozenset({"accesskey"})
# A *container* named for one of these holds secret values (`db_credentials: {user, pass}`), so it is
# redacted wholesale. `token`/`accesskey` are excluded: their containers are records about a credential
# (AWS `access_keys`, token projection config) whose leaves are checked individually.
_CONTAINER_SECRET_KEYWORDS = frozenset({"password", "passwd", "secret", "apikey", "privatekey", "credential", "authorization", "cookie", "secretkey"})
# These are maps of provider-facing metadata.  Their entries have dynamic names which can happen
# to contain a secret-looking word (for example the provider id `onepassword-main` or the AWS
# family `secretsmanager`).  Suppress field-name classification only for the immediate entry;
# recurse normally into the value so an actual nested `password`/`token` field is still redacted.
_STRUCTURAL_METADATA_MAP_FIELDS = frozenset({"identities", "enumerationscope", "authorizationfailures"})
# An entry of a structural map named exactly like a secret field (`password`, `secret`, ...) is still
# redacted wholesale: the exemption is for provider ids and family names that merely contain a keyword.
_EXACT_SECRET_ENTRY_NAMES = frozenset({n.replace("-", "").replace("_", "").lower() for n in SECRET_FIELD_NAMES} | _CONTAINER_SECRET_KEYWORDS)
# Environment-variable names (`STRIPE_KEY`, `DB_PASS`, `SIGNING_SALT`) carry secrets under conventions the
# camelCase keywords above miss. An all-caps name with any of these underscore-separated parts is a secret.
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_ENV_SECRET_PARTS = frozenset({
    "KEY", "APIKEY", "PASS", "PASSWD", "PASSWORD", "PWD", "SECRET", "TOKEN", "SALT", "PEPPER", "HMAC", "PRIVATE",
    "SIGNING", "DSN", "CREDENTIAL", "CREDENTIALS", "PAT", "COOKIE",
})
# `KEY` followed by one of these names a reference to a key (`KEY_ID`, `PUBLIC_KEY_PATH`), not the key itself.
_ENV_KEY_REFERENCE_PARTS = frozenset({"ID", "PATH", "FILE", "NAME", "ARN", "ALIAS"})
# `NAME=value` in free text (a log line echoing its environment, `export STRIPE_KEY=...`).
_ENV_ASSIGNMENT_RE = re.compile(r"\b([A-Z][A-Z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s\"',;]+)")
_MAX_EMBEDDED_JSON = 1_000_000
_FIELD_SEP_RE = re.compile(r"[-_]")
_REDACTED = "[REDACTED:{}]"


def _normalize_field(name: str) -> str:
    return _FIELD_SEP_RE.sub("", name.lower())


def _is_secrets_manager_arn_name_assignment(text: str, match: re.Match[str]) -> bool:
    """Whether this apparent ``secret:<value>`` assignment is exactly an ARN resource component.

    The test is intentionally scoped to the `password_assignment` pattern. Other patterns (known
    literals, access keys, signed URLs, and so on) must still sanitize a credential-shaped secret name.
    """
    if match.group(1).lower() != "secret":
        return False
    for arn in _SECRETS_MANAGER_ARN.finditer(text):
        component_start = arn.start() + arn.group(0).rfind(":secret:") + 1
        if match.start() == component_start and match.end() == arn.end():
            return True
    return False


def _is_secret_field_name(name: str | None, value: Any) -> bool:
    """Decide whether a field *name* implies its value is itself a credential and should be redacted
    wholesale, as opposed to scrubbed in place like any other string. `data` (k8s Secret.data) is
    handled by its own caller-side heuristic, not here.

    The compound/substring keyword match (as opposed to the exact-name sets, which apply regardless)
    only fires for a leaf-shaped value (`str`/`bytes`/`bytearray`). A *container* whose name merely
    contains a keyword — e.g. AWS `access_keys`, a list of `{access_key_hash, access_key_suffix, ...}`
    records — is not itself a credential; its own leaf fields are checked individually once `scrub`
    recurses into it. Without this, a field name collision would wholesale-redact a whole structure
    and destroy the non-secret fields nested inside it.
    """
    if not name:
        return False
    norm = _normalize_field(name)
    if norm == "data":
        return False
    if norm in {_normalize_field(s) for s in SECRET_FIELD_NAMES}:
        return True
    if norm in _NON_SECRET_FIELD_EXACT:
        return False
    if isinstance(value, dict):
        return any(kw in norm for kw in _CONTAINER_SECRET_KEYWORDS)
    if not isinstance(value, (str, bytes, bytearray)):
        return False
    if _is_secret_env_name(name):
        return True
    # `*_last_used` (AWS IAM: `password_last_used`, `access_key_last_used`) is a timestamp of when a
    # credential was last used, never the credential; the suffix alone decides this one regardless of
    # which keyword matched, since "last used" only ever means "when", in or out of this codebase.
    if norm.endswith("count") or norm.endswith("url") or norm.endswith("lastused") or norm.startswith("expires"):
        return False
    hits = {kw for kw in _SECRET_KEYWORDS if kw in norm}
    if not hits:
        return False
    if norm.endswith("id") and hits <= _ID_SAFE_KEYWORDS:
        return False
    if norm.endswith(("hash", "suffix")) and hits <= _HASH_SUFFIX_SAFE_KEYWORDS:
        return False
    return True


def _is_secret_env_name(name: str) -> bool:
    if not _ENV_NAME_RE.match(name):
        return False
    parts = name.split("_")
    for i, part in enumerate(parts):
        if part not in _ENV_SECRET_PARTS:
            continue
        if part == "KEY" and i + 1 < len(parts) and parts[i + 1] in _ENV_KEY_REFERENCE_PARTS:
            continue
        return True
    return False


def _embedded_json(text: str) -> Any:
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")) or len(text) > _MAX_EMBEDDED_JSON:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, (dict, list)) else None


def _redact_private_key_spans(items: list[Any]) -> tuple[list[Any], int]:
    """Redact a PEM private key whose BEGIN/END markers land in different list elements (e.g.
    Kubernetes/Loki container logs stored as a list of lines). BEGIN and END on the *same* element are
    left to the `private_key` text pattern. Fails closed: a BEGIN with no matching END in the rest of
    the list redacts through the end of the list, not just to the next line."""
    out = list(items)
    n = len(out)
    count = 0
    i = 0
    while i < n:
        item = out[i]
        if isinstance(item, str) and _PEM_BEGIN.search(item) and not _PEM_END.search(item):
            j = i
            end_found = False
            while j < n:
                if isinstance(out[j], str) and _PEM_END.search(out[j]):
                    end_found = True
                    break
                j += 1
            last = j if end_found else n - 1
            for k in range(i, last + 1):
                out[k] = _REDACTED.format("private_key")
            count += 1
            i = last + 1
            continue
        i += 1
    return out, count


class Sanitizer:
    """Scrubs credential-shaped strings and known secret literals. Known literals are registered in
    memory by credential resolution so a resolved secret can never appear in evidence."""

    def __init__(self) -> None:
        self._known: list[str] = []

    def register_secret(self, literal: str | None) -> None:
        if literal and len(literal) >= 8 and literal not in self._known:
            self._known.append(literal)

    def scrub_text(self, text: str) -> tuple[str, dict[str, int]]:
        removed: dict[str, int] = {}
        out = text
        for lit in self._known:
            if lit in out:
                removed["known_secret"] = removed.get("known_secret", 0) + out.count(lit)
                out = out.replace(lit, _REDACTED.format("known_secret"))

        for name, pat in _PATTERNS:
            def _sub(m: re.Match[str], _name: str = name, _text: str = out) -> str:
                if _name == "password_assignment" and _is_secrets_manager_arn_name_assignment(_text, m):
                    return m.group(0)
                removed[_name] = removed.get(_name, 0) + 1
                if _name == "password_assignment":
                    return f"{m.group(1)}={_REDACTED.format(_name)}"
                if _name == "basic_auth_url":
                    return f"{m.group(1)}{_REDACTED.format('basic_auth')}@"
                if _name == "signed_url":
                    return f"{m.group(1)}{_REDACTED.format(_name)}"
                if _name in ("pagerduty_token",):
                    return f"{m.group(1)}{_REDACTED.format(_name)}"
                if _name in ("aws_secret_access_key", "aws_session_token", "hex_secret_like"):
                    return f"{m.group(1)}={_REDACTED.format(_name)}"
                if _name == "auth_header":
                    return f"{m.group(1)}{m.group(2)}{_REDACTED.format(_name)}"
                if _name == "cookie_header":
                    return f"{m.group(1)}{m.group(2)}{_REDACTED.format(_name)}"
                return _REDACTED.format(_name)
            out = pat.sub(_sub, out)
        def _env_sub(m: re.Match[str]) -> str:
            if not _is_secret_env_name(m.group(1)) or m.group(2).startswith("[REDACTED"):
                return m.group(0)
            removed["env_assignment"] = removed.get("env_assignment", 0) + 1
            return f"{m.group(1)}={_REDACTED.format('env_assignment')}"
        out = _ENV_ASSIGNMENT_RE.sub(_env_sub, out)
        # Fail closed: a BEGIN marker for a private key with no matching END anywhere in this string
        # (a truncated/streamed key, or one whose END is simply missing) still redacts to end of
        # string, rather than leaving the key material exposed because the END-anchored pattern above
        # never matched.
        m = _PEM_BEGIN.search(out)
        if m and not _PEM_END.search(out[m.start():]):
            removed["private_key"] = removed.get("private_key", 0) + 1
            out = out[: m.start()] + _REDACTED.format("private_key")
        return out, removed

    def scrub(self, value: Any, *, field_name: str | None = None) -> tuple[Any, dict[str, int]]:
        """Deep-scrub a JSON-like structure. Secret-named fields are replaced wholesale; dict keys are
        scrubbed too (a credential used as a key, e.g. `{"ghp_...": "x"}`, is redacted like any other
        credential-shaped string); `bytes`/`bytearray`/`tuple`/`set` are scrubbed like their `str`/
        `list` equivalents instead of passing through untouched."""
        removed: dict[str, int] = {}

        def merge(r: dict[str, int]) -> None:
            for k, v in r.items():
                removed[k] = removed.get(k, 0) + v

        def is_b64_secret_data(name: str | None, v: Any) -> bool:
            return bool(name and name.lower() == "data" and isinstance(v, dict) and v and all(isinstance(x, str) for x in v.values()) and _looks_b64_map(v))

        def walk(v: Any, name: str | None, *, suppress_field_name: bool = False) -> Any:
            if not suppress_field_name and _is_secret_field_name(name, v):
                merge({"secret_field:" + str(name).lower(): 1})
                return _REDACTED.format("field:" + str(name).lower())
            if is_b64_secret_data(name, v):
                merge({"secret_field:data": 1})
                return _REDACTED.format("field:data")
            if isinstance(v, str):
                embedded = _embedded_json(v)
                if embedded is not None:  # e.g. a last-applied-configuration annotation holding a pod spec
                    walked = walk(embedded, name)
                    if walked != embedded:
                        v = json.dumps(walked, separators=(",", ":"), default=str)
                s, r = self.scrub_text(v)
                merge(r)
                return s
            if isinstance(v, (bytes, bytearray)):
                text = v.decode("utf-8", errors="replace")
                s, r = self.scrub_text(text)
                if not r:
                    return v
                merge(r)
                return s.encode("utf-8") if isinstance(v, bytes) else bytearray(s.encode("utf-8"))
            if isinstance(v, dict):
                # A `{name, value}` pair (Kubernetes/ECS env entries) names its value: judge the value by that name.
                pair = {str(k).lower(): k for k in v}
                if "name" in pair and "value" in pair and isinstance(v[pair["name"]], str) and _is_secret_field_name(v[pair["name"]], v[pair["value"]]):
                    merge({"secret_field:" + v[pair["name"]].lower(): 1})
                    v = {**v, pair["value"]: _REDACTED.format("field:" + v[pair["name"]].lower())}
                result: dict[str, Any] = {}
                entry_names_are_metadata = (
                    not suppress_field_name
                    and _normalize_field(name) in _STRUCTURAL_METADATA_MAP_FIELDS
                    if name
                    else False
                )
                for k, val in v.items():
                    key_str = str(k)
                    new_key, kr = self.scrub_text(key_str)
                    if kr:
                        merge(kr)
                        if new_key in result:  # preserve uniqueness on collision
                            suffix = 2
                            candidate = f"{new_key}#{suffix}"
                            while candidate in result:
                                suffix += 1
                                candidate = f"{new_key}#{suffix}"
                            new_key = candidate
                    result[new_key] = walk(
                        val,
                        key_str,
                        suppress_field_name=entry_names_are_metadata and isinstance(val, (dict, list, tuple)) and _normalize_field(key_str) not in _EXACT_SECRET_ENTRY_NAMES,
                    )
                return result
            if isinstance(v, (list, tuple)):
                items = list(v)
                if any(isinstance(x, str) for x in items):
                    items, pk_count = _redact_private_key_spans(items)
                    if pk_count:
                        merge({"private_key": pk_count})
                entry_names_are_metadata = (
                    not suppress_field_name
                    and _normalize_field(name) in _STRUCTURAL_METADATA_MAP_FIELDS
                    if name
                    else False
                )
                scrubbed = [walk(x, name, suppress_field_name=entry_names_are_metadata) for x in items]
                return tuple(scrubbed) if isinstance(v, tuple) else scrubbed
            if isinstance(v, set):
                return {walk(x, name) for x in v}
            return v

        return walk(value, field_name), removed


def _looks_b64_map(v: dict[str, str]) -> bool:
    return all(re.fullmatch(r"[A-Za-z0-9+/=\n]*", x or "") for x in v.values())


def bound_payload(value: Any, max_bytes: int) -> tuple[Any, bool]:
    """Truncate oversized string leaves / lists until the canonical JSON fits. Marks truncation."""
    encoded = canonical_json(value)
    if len(encoded.encode()) <= max_bytes:
        return value, False
    v = copy.deepcopy(value)

    def shrink(x: Any, budget: int) -> Any:
        if isinstance(x, str):
            return x[:budget] + "…[truncated]" if len(x) > budget else x
        if isinstance(x, list):
            keep = max(1, budget // 200)
            return [shrink(i, 200) for i in x[:keep]] + ([f"…[{len(x) - keep} more items truncated]"] if len(x) > keep else [])
        if isinstance(x, dict):
            return {k: shrink(val, max(50, budget // max(1, len(x)))) for k, val in x.items()}
        return x

    return shrink(v, max(1000, max_bytes // 4)), True


def apply_redaction(candidate: dict[str, Any], paths: Iterable[str]) -> tuple[dict[str, Any], list[str]]:
    """Redact dotted JSON paths (e.g. `data.items.3.message`). Returns projection and applied paths."""
    proj = copy.deepcopy(candidate)
    applied: list[str] = []
    for path in paths:
        parts = [p for p in path.split(".") if p]
        if not parts:
            continue
        cur: Any = proj
        ok = True
        for p in parts[:-1]:
            if isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
                cur = cur[int(p)]
            elif isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                ok = False
                break
        if not ok:
            continue
        last = parts[-1]
        if isinstance(cur, list) and last.isdigit() and int(last) < len(cur):
            cur[int(last)] = "[REDACTED by reviewer]"
            applied.append(path)
        elif isinstance(cur, dict) and last in cur:
            cur[last] = "[REDACTED by reviewer]"
            applied.append(path)
    return proj, applied


def derived_disclosable(contributing_evidence_released_to: Iterable[Iterable[str]], requester: str) -> bool:
    """Derived data may be disclosed only when every contributing evidence fragment has been released
    to the requester. An empty contribution set means nothing is withheld."""
    for audiences in contributing_evidence_released_to:
        if requester not in set(audiences):
            return False
    return True
