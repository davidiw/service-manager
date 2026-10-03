"""Regression tests for the gaps closed in `local_ops.release.Sanitizer` (D15 floor, D17/D18
disclosure scrubbing). Each case below pairs a positive leak (now redacted) with a negative case that a
non-secret Kubernetes/observability field or an ordinary string survives untouched, since
`Sanitizer.scrub` is the only control between provider data and the assistant in review_requests/YOLO
modes.
"""

from __future__ import annotations

import time

from local_ops.release import Sanitizer

PASSWORD = "hunter2hunter2"
HEX_SECRET = "0123456789abcdef0123456789abcdef"
GITHUB_TOKEN = "ghp_" + "a" * 36


def _fresh() -> Sanitizer:
    return Sanitizer()


# --- PEM private key spanning multiple list elements (k8s/Loki log lines) -------------------------


def test_private_key_spanning_list_elements_is_redacted() -> None:
    s = _fresh()
    lines = [
        "starting up",
        "-----BEGIN RSA PRIVATE KEY-----",
        "MIIBogIBAAJBAKreal looking base64 content",
        "moreBase64Data==",
        "-----END RSA PRIVATE KEY-----",
        "shutdown complete",
    ]
    out, removed = s.scrub({"lines": lines})
    assert removed.get("private_key", 0) >= 1
    assert "MIIBogIBAAJBAKreal looking base64 content" not in out["lines"]
    assert out["lines"][0] == "starting up"
    assert out["lines"][-1] == "shutdown complete"
    for line in out["lines"][1:-1]:
        assert "BEGIN" not in line and "base64" not in line.lower() or "REDACTED" in line


def test_private_key_spanning_list_with_no_end_fails_closed_to_end_of_list() -> None:
    s = _fresh()
    lines = ["intro", "-----BEGIN RSA PRIVATE KEY-----", "truncated content, no end ever", "trailer"]
    out, removed = s.scrub({"lines": lines})
    assert removed.get("private_key", 0) == 1
    assert out["lines"][0] == "intro"
    assert "truncated content" not in out["lines"][2]
    assert "trailer" not in out["lines"][3]  # fail closed: redacted through end of list


def test_lone_begin_with_no_end_in_a_single_string_is_redacted() -> None:
    s = _fresh()
    text = "prefix -----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJB truncated, no end"
    out, removed = s.scrub_text(text)
    assert removed.get("private_key", 0) == 1
    assert "MIIBogIBAAJB" not in out
    assert out.startswith("prefix ")


def test_begin_and_end_in_same_list_element_still_redacted() -> None:
    s = _fresh()
    lines = ["-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"]
    out, removed = s.scrub({"lines": lines})
    assert removed.get("private_key", 0) == 1
    assert "abc" not in out["lines"][0]


# --- JSON-quoted keys: quote between key and colon --------------------------------------------------


def test_json_quoted_password_and_api_key_are_redacted() -> None:
    s = _fresh()
    text = f'{{"password":"{PASSWORD}","api_key":"{HEX_SECRET}"}}'
    out, removed = s.scrub_text(text)
    assert PASSWORD not in out
    assert HEX_SECRET not in out
    assert removed.get("password_assignment", 0) == 2


# --- non-http URL userinfo: any scheme, password may contain @ -------------------------------------


def test_non_http_scheme_userinfo_is_redacted() -> None:
    s = _fresh()
    for url in (
        "postgres://u:secretpass@host/db",
        "redis://user:secretpass@localhost:6379/0",
        "amqp://guest:secretpass@rabbit:5672/",
        "mongodb+srv://u:secretpass@cluster0.mongodb.net",
    ):
        out, removed = s.scrub_text(url)
        assert "secretpass" not in out, url
        assert removed.get("basic_auth_url", 0) == 1, url


def test_password_containing_at_sign_does_not_leak_remainder() -> None:
    s = _fresh()
    out, removed = s.scrub_text("https://user:p@ss@host/path")
    assert removed.get("basic_auth_url", 0) == 1
    assert "ss@host" not in out
    assert out.endswith("@host/path")


# --- Authorization / Proxy-Authorization / Cookie / Set-Cookie / X-Api-Key header lines -------------


def test_authorization_basic_header_is_redacted() -> None:
    s = _fresh()
    out, removed = s.scrub_text("Authorization: Basic dXNlcjpwYXNzd29yZA==")
    assert "dXNlcjpwYXNzd29yZA==" not in out
    assert removed.get("auth_header", 0) == 1


def test_proxy_authorization_digest_and_token_schemes_are_redacted() -> None:
    s = _fresh()
    for line in (
        "Proxy-Authorization: Digest realm=x, nonce=abcdefabcdef",
        "Authorization: Token abc123def456",
    ):
        out, removed = s.scrub_text(line)
        assert removed.get("auth_header", 0) == 1, line
        assert "abc123def456" not in out
        assert "nonce=abcdefabcdef" not in out


def test_x_api_key_header_is_redacted() -> None:
    s = _fresh()
    out, removed = s.scrub_text("X-Api-Key: abcdef0123456789")
    assert "abcdef0123456789" not in out
    assert sum(removed.values()) >= 1


def test_cookie_and_set_cookie_headers_are_redacted() -> None:
    s = _fresh()
    out1, r1 = s.scrub_text("Cookie: sessionid=abc123def456")
    assert "abc123def456" not in out1
    assert r1.get("cookie_header", 0) == 1
    out2, r2 = s.scrub_text("Set-Cookie: session=abc123; Path=/; HttpOnly")
    assert "abc123" not in out2
    assert r2.get("cookie_header", 0) == 1


# --- dict keys that are themselves credentials ------------------------------------------------------


def test_dict_key_that_is_itself_a_credential_is_redacted() -> None:
    s = _fresh()
    out, removed = s.scrub({GITHUB_TOKEN: "x", "other": "y"})
    assert GITHUB_TOKEN not in out
    assert out["other"] == "y"
    assert removed.get("github_token", 0) == 1


def test_colliding_scrubbed_keys_preserve_uniqueness() -> None:
    s = _fresh()
    out, removed = s.scrub({GITHUB_TOKEN: 1, "ghp_" + "b" * 36: 2})
    assert len(out) == 2
    keys = list(out.keys())
    assert keys[0] != keys[1]
    assert sorted(out.values()) == [1, 2]


# --- bytes / bytearray / tuple / set values ----------------------------------------------------------


def test_bytes_value_containing_a_secret_is_redacted() -> None:
    s = _fresh()
    out, removed = s.scrub(f"password={PASSWORD}".encode())
    assert isinstance(out, bytes)
    assert PASSWORD.encode() not in out
    assert sum(removed.values()) >= 1


def test_bytearray_value_without_a_secret_is_unchanged() -> None:
    s = _fresh()
    v = bytearray(b"plain binary payload")
    out, removed = s.scrub(v)
    assert bytes(out) == bytes(v)
    assert removed == {}


def test_tuple_value_is_scrubbed_like_a_list() -> None:
    s = _fresh()
    out, removed = s.scrub(("plain", f"password={PASSWORD}"))
    assert isinstance(out, tuple)
    assert PASSWORD not in out[1]
    assert sum(removed.values()) >= 1


def test_set_value_is_scrubbed() -> None:
    s = _fresh()
    out, removed = s.scrub({"plain-value", f"password={PASSWORD}"})
    assert isinstance(out, set)
    assert all(PASSWORD not in x for x in out)
    assert sum(removed.values()) >= 1


# --- compound secret field names (normalized, substring match) ---------------------------------------


def test_compound_secret_field_names_are_redacted_wholesale() -> None:
    s = _fresh()
    d = {
        "db_password": "x",
        "X-Auth-Token": "y",
        "private_token": "z",
        "client-secret": "w",
        "aws_secret_key": "q",
        "secret_key": "r",
        "access_key": "v",
    }
    out, removed = s.scrub(d)
    for k in d:
        assert out[k].startswith("[REDACTED:field:")
    assert len(removed) == len(d)


# --- allowlisted k8s/observability reference & metadata fields: not wholesale-redacted ----------------


def test_k8s_secret_reference_fields_are_not_redacted() -> None:
    s = _fresh()
    d = {
        "secretName": "db-credentials",
        "secretRef": {"name": "db-credentials"},
        "secretKeyRef": {"name": "db-credentials", "key": "password"},
    }
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


def test_service_account_token_projection_config_is_not_redacted() -> None:
    s = _fresh()
    d = {"serviceAccountToken": {"audience": "api", "expirationSeconds": 3600, "path": "token"}}
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


def test_token_type_and_token_expiration_seconds_are_not_redacted() -> None:
    s = _fresh()
    d = {"token_type": "Bearer", "tokenExpirationSeconds": 3600}
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


def test_count_url_expires_and_id_suffixed_fields_are_not_redacted() -> None:
    s = _fresh()
    d = {
        "retry_count": 5,
        "token_count": 2,
        "webhook_url": "https://example.com/hook",
        "expires_at": "2030-01-01T00:00:00Z",
        "request_id": "abc-123",
        "token_id": "tok_ref_42",
    }
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


def test_aws_iam_metadata_fields_about_a_credential_are_not_redacted() -> None:
    """AWS IAM observations (`local_ops.providers.aws`) carry metadata *about* a credential — when it
    was last used, a one-way hash, a 4-char suffix — never the credential value itself. These field
    names happen to contain a secret keyword (`password`, `accesskey`) as a qualifier, not because the
    value is secret; diagnosis needs them verbatim (`test_iam_access_keys_are_hashed_and_evidence_scrubbed`
    in tests/providers/test_aws.py)."""
    s = _fresh()
    d = {
        "password_last_used": "2026-09-30T00:00:00Z",
        "access_key_last_used": "2026-09-01T00:00:00Z",
        "access_key_hash": "a" * 64,
        "access_key_suffix": "MPLE",
        "access_keys": [{"access_key_hash": "b" * 64, "access_key_suffix": "WXYZ", "status": "Active", "last_used_service": "s3", "last_used_region": "us-east-1"}],
        "root_access_keys_present": True,
    }
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


def test_url_field_with_embedded_userinfo_is_still_caught_by_pattern_scrub() -> None:
    s = _fresh()
    d = {"db_url": "postgres://u:secretpass@host/db"}
    out, removed = s.scrub(d)
    # the field name ("*_url") is exempt from wholesale redaction, but the value itself is still
    # pattern-scrubbed because it actually contains userinfo.
    assert "secretpass" not in out["db_url"]
    assert removed.get("basic_auth_url", 0) == 1


def test_log_line_mentioning_password_without_a_value_is_not_redacted() -> None:
    s = _fresh()
    text = "authentication failed: password was rejected for user alice"
    out, removed = s.scrub_text(text)
    assert out == text
    assert removed == {}


def test_k8s_data_field_with_non_b64_values_is_not_wholesale_redacted() -> None:
    s = _fresh()
    # "data" is treated as secret only when it looks like k8s Secret.data (a dict of base64 strings);
    # an ordinary "data" field (e.g. a ConfigMap-shaped payload or a plain record) is left alone here,
    # falling back to per-string pattern scrubbing.
    d = {"data": {"replicas": "not-base64-and-has-dashes!!"}}
    out, removed = s.scrub(d)
    assert out == d
    assert removed == {}


# --- existing behaviour preserved: registered secrets, idempotency ------------------------------------


def test_registered_secret_literal_is_redacted_wherever_it_appears() -> None:
    s = Sanitizer()
    s.register_secret("super-secret-literal-value")
    out, removed = s.scrub({"nested": {"deep": "contains super-secret-literal-value inline"}})
    assert "super-secret-literal-value" not in out["nested"]["deep"]
    assert removed.get("known_secret", 0) == 1


def test_scrub_is_idempotent_and_does_not_redact_placeholders() -> None:
    s = _fresh()
    samples = [
        f"password={PASSWORD}",
        "postgres://u:secretpass@host/db",
        "Authorization: Basic dXNlcjpwYXNz",
        "Cookie: a=b",
        "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
        "?X-Amz-Signature=" + "a" * 20,
        "aws_secret_access_key=" + "a" * 40,
        "secret: " + "a" * 40,
    ]
    for text in samples:
        once, _ = s.scrub_text(text)
        twice, removed_twice = s.scrub_text(once)
        assert once == twice, text
        assert removed_twice == {}, text


# --- no catastrophic backtracking on adversarial input -------------------------------------------------


def test_new_patterns_do_not_catastrophically_backtrack() -> None:
    s = _fresh()
    adversarial = [
        "a:" * 500_000,
        "@" * 1_000_000,
        "a@" * 500_000,
        "http://" + "a:" * 400_000 + "b",
        "authorization: basic " + "a" * 999_980,
        "cookie: " + "a" * 999_993,
    ]
    for text in adversarial:
        start = time.monotonic()
        s.scrub_text(text)
        elapsed = time.monotonic() - start
        assert elapsed < 0.5, (len(text), elapsed)


def test_secret_named_container_is_redacted_wholesale() -> None:
    """`db_credentials: {user, pass}` holds secret values, so the container goes; records *about* a
    credential (AWS `access_keys`) and Kubernetes Secret references are walked field by field."""
    s = Sanitizer()
    out, _ = s.scrub({"db_credentials": {"user": "bob", "pass": "hunter2xyz"}, "pass": "x1234567"})
    assert "hunter2xyz" not in str(out) and "x1234567" not in str(out)
    out, _ = s.scrub({"access_keys": [{"access_key_suffix": "WXYZ", "status": "Active"}], "secretKeyRef": {"name": "db", "key": "password"}})
    assert out == {"access_keys": [{"access_key_suffix": "WXYZ", "status": "Active"}], "secretKeyRef": {"name": "db", "key": "password"}}


def test_environment_variable_secrets_are_redacted() -> None:
    """Env vars carry secrets under all-caps conventions (`STRIPE_KEY`, `DB_PASS`), as name->value maps
    (Lambda) or `{name, value}` pairs (Kubernetes/ECS), including inside JSON-valued annotations."""
    import json

    s = Sanitizer()
    out, _ = s.scrub({"Variables": {"STRIPE_KEY": "sk_live_abcdefgh", "DB_PASS": "p", "SIGNING_SALT": "s", "JWT_HMAC": "h", "PRIVATE": "q", "LOG_LEVEL": "info"}})
    assert out["Variables"]["LOG_LEVEL"] == "info"
    assert all(v.startswith("[REDACTED") for k, v in out["Variables"].items() if k != "LOG_LEVEL")
    out, _ = s.scrub({"env": [{"name": "DB_PASSWORD", "value": "hunter2"}, {"name": "LOG_LEVEL", "value": "debug"}]})
    assert out["env"][0]["value"].startswith("[REDACTED") and out["env"][1]["value"] == "debug"
    annotation = json.dumps({"spec": {"containers": [{"env": [{"name": "API_SECRET", "value": "abc123"}]}]}})
    out, _ = s.scrub({"annotations": {"kubectl.kubernetes.io/last-applied-configuration": annotation}})
    assert "abc123" not in str(out)


def test_aws_tags_and_plain_json_strings_are_not_redacted() -> None:
    s = Sanitizer()
    assert s.scrub({"Tags": [{"Key": "Name", "Value": "web"}]})[0] == {"Tags": [{"Key": "Name", "Value": "web"}]}
    assert s.scrub({"note": '{"replicas": 3}'})[0] == {"note": '{"replicas": 3}'}


def test_env_assignments_in_free_text_and_env_reference_names() -> None:
    s = Sanitizer()
    assert "hunter2long" not in s.scrub_text("DB_PASS=hunter2long started")[0]
    assert "sk_live_abc" not in s.scrub_text("export STRIPE_KEY=sk_live_abc")[0]
    plain = "LOG_LEVEL=debug SESSION_TIMEOUT=30 AUTH_MODE=oidc KMS_KEY_ID=abc PUBLIC_KEY_PATH=/x"
    assert s.scrub_text(plain)[0] == plain
    out, _ = s.scrub({"SESSION_TIMEOUT": "30", "AUTH_MODE": "oidc", "KEY_ID": "k", "API_KEY": "zzz"})
    assert out == {"SESSION_TIMEOUT": "30", "AUTH_MODE": "oidc", "KEY_ID": "k", "API_KEY": "[REDACTED:field:api_key]"}


# --- D30 review BLOCK 2b: compound/env-style key assignments in free text --------------------------


def test_compound_key_assignments_in_free_text_are_redacted() -> None:
    """The old `password_assignment` pattern required `\\b(password|...)\\b` around the exact keyword;
    `_` is a word character, so a compound name like `db_password:`/`POSTGRES_PASSWORD:` never matched.
    `_KEY_VALUE_RE`/`_freeform_key_is_secret` catch these via segment-aware matching instead."""
    s = Sanitizer()
    cases = {
        "POSTGRES_PASSWORD: hunter2hunter2": "hunter2hunter2",
        "db_password: Sup3rS3cretValue": "Sup3rS3cretValue",
        "apiToken: abcdefabcdef123": "abcdefabcdef123",
        "STRIPE_KEY: sk_live_abc": "sk_live_abc",
        "jwt_signing_key: zzz": "zzz",
        "rpc_auth: user:pass": "user:pass",
        "password: x": "x",
    }
    for text, secret in cases.items():
        out, removed = s.scrub_text(text)
        assert secret not in out, text
        assert removed, text


def test_hcl_style_equals_assignment_is_redacted() -> None:
    s = Sanitizer()
    out, removed = s.scrub_text('db_password = "x"')
    assert out == 'db_password = "[REDACTED:password_assignment]"'
    assert removed.get("password_assignment") == 1


def test_slack_and_discord_webhook_urls_are_redacted_regardless_of_key_name() -> None:
    s = Sanitizer()
    out, removed = s.scrub_text("SLACK_WEBHOOK: https://hooks.slack.com/services/T/B/X")
    assert "T/B/X" not in out and removed
    out2, removed2 = s.scrub_text("see https://discord.com/api/webhooks/123/abcDEF for the callback")
    assert "123/abcDEF" not in out2 and removed2


def test_compound_key_assignments_do_not_over_redact_non_secrets() -> None:
    """`keyspace`/`token_type`/`auth_mode`/`webhook_url` describe or reference something, they are not
    the credential itself -- the same bar the structured field-name scrub already applies."""
    s = Sanitizer()
    for text in ("keyspace: foo", "token_type: bearer", "AUTH_MODE=oidc", "webhook_url: https://example.com/hook"):
        out, removed = s.scrub_text(text)
        assert out == text, text
        assert removed == {}, text


def test_benign_prefix_before_a_real_secret_on_the_same_line_does_not_swallow_it() -> None:
    """A regex that treats *any* identifier followed by ':'/'=' as a candidate key, with a greedy
    to-end-of-line value, would let a benign leading word ('RuntimeError:', a traceback's exception-type
    prefix) consume a real `token=...`/`password=...` later on the same line as its own, unredacted
    value -- `re.sub` never re-scans inside an already-matched span. Requiring the candidate key to
    itself contain a keyword fragment keeps a plain word like 'RuntimeError' from ever matching, so the
    scan reaches the real assignment afterward."""
    s = Sanitizer()
    text = "RuntimeError: simulated provider failure (token=secret-should-not-leak-value)"
    out, removed = s.scrub_text(text)
    assert "secret-should-not-leak-value" not in out
    assert removed.get("password_assignment") == 1

    out2, removed2 = s.scrub_text("provider broken unavailable: password=hunter2hunter2 rejected")
    assert "hunter2hunter2" not in out2
    assert removed2.get("password_assignment") == 1


def test_service_specific_credential_records_pass_but_generic_credential_suffix_does_not() -> None:
    s = Sanitizer()
    records, _ = s.scrub({"service_specific_credentials": [{"service_name": "bedrock.amazonaws.com", "credential_id_hash": "sha256:abc", "credential_id_suffix": "ABCD", "password": "x"}]})
    rec = records["service_specific_credentials"][0]
    assert rec["credential_id_hash"] == "sha256:abc" and rec["credential_id_suffix"] == "ABCD"
    assert rec["password"].startswith("[REDACTED")
    generic, _ = s.scrub({"db_credential_suffix": "hunter2", "db_credentials": {"user": "a", "pass": "b"}})
    assert generic["db_credential_suffix"].startswith("[REDACTED")
    assert str(generic["db_credentials"]).startswith("[REDACTED")
