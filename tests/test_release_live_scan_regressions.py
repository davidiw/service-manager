"""Regression coverage for disclosure failures found in the first live census."""

from __future__ import annotations

from local_ops.release import Sanitizer


def test_secrets_manager_arns_remain_distinct_resource_metadata() -> None:
    sanitizer = Sanitizer()
    alpha = "arn:aws:secretsmanager:us-east-1:123456789012:secret:alpha-ABC123"
    bravo = "arn:aws:secretsmanager:us-east-1:123456789012:secret:bravo-DEF456"

    scrubbed, removed = sanitizer.scrub({"resource_keys": [alpha, bravo]})

    assert scrubbed["resource_keys"] == [alpha, bravo]
    assert removed == {}


def test_real_secret_assignments_and_registered_literals_stay_redacted() -> None:
    sanitizer = Sanitizer()
    sanitizer.register_secret("registered-secret-literal")

    scrubbed, removed = sanitizer.scrub(
        {
            "message": "password=actual-secret-value registered-secret-literal",
            "credential": {"password": "nested-secret-value"},
        }
    )

    assert "actual-secret-value" not in str(scrubbed)
    assert "registered-secret-literal" not in str(scrubbed)
    assert "nested-secret-value" not in str(scrubbed)
    assert removed["password_assignment"] == 1
    assert removed["known_secret"] == 1


def test_credential_shaped_secret_names_in_arns_still_redact() -> None:
    sanitizer = Sanitizer()
    access_key = "AKIA" + "A" * 16
    registered_literal = "registered-secret-literal"
    sanitizer.register_secret(registered_literal)

    access_key_arn, _ = sanitizer.scrub_text(
        f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{access_key}"
    )
    registered_arn, _ = sanitizer.scrub_text(
        f"arn:aws:secretsmanager:us-east-1:123456789012:secret:{registered_literal}"
    )

    assert access_key not in access_key_arn
    assert registered_literal not in registered_arn


def test_structural_metadata_maps_keep_provider_and_coverage_details() -> None:
    sanitizer = Sanitizer()
    payload = {
        "summary": {
            "identities": {
                "onepassword-main": {
                    "auth": "onepassword_cli",
                    "password": "must-not-leak",
                },
                "password": "must-not-leak",
            },
            "enumeration_scope": {
                "secretsmanager": {
                    "status": "complete",
                    "token": "must-not-leak",
                }
            },
        },
        "aws_coverage": {
            "authorization_failures": [
                {
                    "family": "secretsmanager",
                    "code": "AccessDenied",
                    "message": "ListSecrets was denied",
                    "secret": "must-not-leak",
                }
            ]
        },
    }

    scrubbed, _ = sanitizer.scrub(payload)

    assert scrubbed["summary"]["identities"]["onepassword-main"]["auth"] == "onepassword_cli"
    assert scrubbed["summary"]["enumeration_scope"]["secretsmanager"]["status"] == "complete"
    failure = scrubbed["aws_coverage"]["authorization_failures"][0]
    assert failure["family"] == "secretsmanager"
    assert failure["code"] == "AccessDenied"
    assert failure["message"] == "ListSecrets was denied"
    assert "must-not-leak" not in str(scrubbed)


def test_structural_map_entry_named_exactly_like_a_secret_is_still_redacted() -> None:
    sanitizer = Sanitizer()
    scrubbed, removed = sanitizer.scrub({"identities": {"password": {"value": "hunter2xyz"}, "onepassword-main": {"auth": "cli"}}, "enumeration_scope": {"secret": {"note": "plain-canary"}}})
    assert "hunter2xyz" not in str(scrubbed) and "plain-canary" not in str(scrubbed)
    assert scrubbed["identities"]["onepassword-main"] == {"auth": "cli"}
    assert removed
