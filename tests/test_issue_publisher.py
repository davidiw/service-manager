from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("issue_publisher", Path(__file__).parents[1] / "scripts" / "publish-catalog-issues.py")
assert SPEC and SPEC.loader
publisher = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publisher
SPEC.loader.exec_module(publisher)


def packet(
    tmp_path: Path,
    issues: list[dict[str, str]] | None = None,
    repository: str = "MoveIndustries/service-manager-catalog",
) -> Path:
    root = tmp_path / "packet"
    root.mkdir()
    (root / "one.md").write_text("one body")
    (root / "two.md").write_text("two body")
    entries = issues if issues is not None else [
        {"id": "first-issue", "title": "First", "body_file": "one.md"},
        {"id": "second-issue", "title": "Second", "body_file": "two.md"},
    ]
    (root / "manifest.json").write_text(json.dumps({"repository": repository, "issues": entries}))
    return root


def completed(argv: list[str], stdout: str = "", stderr: str = "", code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(argv, code, stdout, stderr)


def test_preview_is_offline_and_lists_packet(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(publisher.subprocess, "run", lambda *a, **k: pytest.fail("network command"))
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog"]) == 0
    assert "first-issue\tFirst" in capsys.readouterr().out


def test_apply_skips_closed_existing_marker_and_ignores_unrelated_and_pr(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    calls: list[list[str]] = []
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if "--paginate" in argv:
            return completed(
                argv,
                json.dumps(
                    [
                        [
                            {
                                "body": "x <!-- local-ops-plan:first-issue -->",
                                "state": "closed",
                                "html_url": "https://github.com/MoveIndustries/service-manager-catalog/issues/1",
                            },
                            {"body": "<!-- local-ops-plan:second-issue -->", "pull_request": {}},
                        ],
                        [{"body": "unrelated"}],
                    ]
                ),
            )
        if "repos/MoveIndustries/service-manager-catalog" in argv:
            return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')
        return completed(argv, "https://github.com/MoveIndustries/service-manager-catalog/issues/9\n")
    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 0
    out = capsys.readouterr().out
    assert "skipped first-issue https://github.com/MoveIndustries/service-manager-catalog/issues/1" in out
    assert "created second-issue" in out
    assert len([call for call in calls if call[:3] == ["gh", "issue", "create"]]) == 1


@pytest.mark.parametrize(
    "repo_response",
    [
        '{"full_name": "MoveIndustries/service-manager-catalog", "private": false, "has_issues": true}',
        '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": false}',
    ],
)
def test_apply_refuses_public_or_issue_disabled_repo(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], repo_response: str) -> None:
    monkeypatch.setattr(publisher.subprocess, "run", lambda argv, **kwargs: completed(argv, repo_response))
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    assert "refusing" in capsys.readouterr().err


@pytest.mark.parametrize("full_name", [None, "other-owner/other-repo"])
def test_apply_refuses_missing_or_mismatched_repository_identity_before_listing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], full_name: str | None
) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return completed(argv, json.dumps({"full_name": full_name, "private": True, "has_issues": True}))

    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    assert "identity does not match" in capsys.readouterr().err
    assert len(calls) == 1


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/other-owner/other-repo/issues/1",
        "https://github.com/MoveIndustries/service-manager-catalog/issues/1?x=1",
        "https://github.com/MoveIndustries/service-manager-catalog/issues/0",
    ],
)
def test_apply_refuses_malformed_existing_marker_url_before_create(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], url: str
) -> None:
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        if "--paginate" in argv:
            return completed(argv, json.dumps([[{"body": "<!-- local-ops-plan:first-issue -->", "html_url": url}]]))
        return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')

    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    assert "without a URL" in capsys.readouterr().err
    assert not any(call[:3] == ["gh", "issue", "create"] for call in calls)


def test_duplicate_markers_and_invalid_paths_refuse(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = packet(tmp_path)
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "api" in argv and "--paginate" not in argv:
            return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')
        return completed(
            argv,
            '[['
            '{"body":"<!-- local-ops-plan:first-issue -->","html_url":"https://github.com/MoveIndustries/service-manager-catalog/issues/1"},'
            '{"body":"<!-- local-ops-plan:first-issue -->","html_url":"https://github.com/MoveIndustries/service-manager-catalog/issues/2"}'
            ']]',
        )
    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    assert "duplicate existing" in capsys.readouterr().err
    (root / "manifest.json").write_text(json.dumps({"repository": "MoveIndustries/service-manager-catalog", "issues": [{"id": "bad", "title": "Bad", "body_file": "../outside.md"}]}))
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog"]) == 1
    assert "unsafe" in capsys.readouterr().err
    outside = tmp_path / "outside.md"
    outside.write_text("outside")
    (root / "escape.md").symlink_to(outside)
    (root / "manifest.json").write_text(json.dumps({"repository": "MoveIndustries/service-manager-catalog", "issues": [{"id": "bad", "title": "Bad", "body_file": "escape.md"}]}))
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog"]) == 1
    assert "symlink" in capsys.readouterr().err


def test_wrong_repo_and_partial_failure_stops_after_prior_result(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = packet(tmp_path)
    assert publisher.main([str(root), "--repo", "elsewhere/repo"]) == 1
    assert "exactly match" in capsys.readouterr().err
    creates = 0
    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal creates
        if "api" in argv and "--paginate" not in argv:
            return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')
        if "--paginate" in argv:
            return completed(argv, '[]')
        creates += 1
        return completed(argv, "https://github.com/MoveIndustries/service-manager-catalog/issues/1\n" if creates == 1 else "", "failed", 0 if creates == 1 else 1)
    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    captured = capsys.readouterr()
    assert "created first-issue https://github.com/MoveIndustries/service-manager-catalog/issues/1" in captured.out
    assert "GitHub issue creation failed" in captured.err
    assert captured.err == "error: GitHub issue creation failed; stopping without retry\n"
    assert creates == 2


@pytest.mark.parametrize("repo", ["owner/repo?state=all", "owner/repo#fragment", "owner/repo/extra"])
def test_apply_rejects_non_repository_api_targets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str], repo: str) -> None:
    monkeypatch.setattr(publisher.subprocess, "run", lambda *args, **kwargs: pytest.fail("network command"))
    assert publisher.main([str(packet(tmp_path, repository=repo)), "--repo", repo, "--apply"]) == 1
    assert "exact owner/repository" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("", "empty body"),
        ("  \n", "empty body"),
        ("text\n<!-- local-ops-plan:other-issue -->", "already contains"),
    ],
)
def test_packet_rejects_empty_or_pre_marked_bodies(tmp_path: Path, capsys: pytest.CaptureFixture[str], body: str, message: str) -> None:
    root = packet(tmp_path)
    (root / "one.md").write_text(body)
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog"]) == 1
    assert message in capsys.readouterr().err


def test_packet_handles_invalid_body_encoding(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = packet(tmp_path)
    (root / "one.md").write_bytes(b"\xff")
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog"]) == 1
    assert "body could not be read" in capsys.readouterr().err


def test_packet_handles_invalid_manifest_encoding(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    root = packet(tmp_path)
    (root / "manifest.json").write_bytes(b"\xff")
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog"]) == 1
    assert "invalid manifest.json" in capsys.readouterr().err


def test_timeout_after_one_create_keeps_prior_progress_and_hides_provider_output(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    creates = 0

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal creates
        if "--paginate" in argv:
            return completed(argv, "[]")
        if "repos/MoveIndustries/service-manager-catalog" in argv:
            return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')
        creates += 1
        if creates == 1:
            return completed(argv, "https://github.com/MoveIndustries/service-manager-catalog/issues/1\n")
        raise subprocess.TimeoutExpired(argv, 30, stderr="secret provider diagnostics")

    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(packet(tmp_path)), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    captured = capsys.readouterr()
    assert "created first-issue https://github.com/MoveIndustries/service-manager-catalog/issues/1" in captured.out
    assert "unknown outcome; stopping without retry" in captured.err
    assert "secret provider diagnostics" not in captured.err
    assert creates == 2


def test_wrong_create_url_stops_later_writes_after_prior_progress(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = packet(tmp_path)
    (root / "three.md").write_text("three body")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "repository": "MoveIndustries/service-manager-catalog",
                "issues": [
                    {"id": "first-issue", "title": "First", "body_file": "one.md"},
                    {"id": "second-issue", "title": "Second", "body_file": "two.md"},
                    {"id": "third-issue", "title": "Third", "body_file": "three.md"},
                ],
            }
        )
    )
    creates = 0

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal creates
        if "--paginate" in argv:
            return completed(argv, "[]")
        if "repos/MoveIndustries/service-manager-catalog" in argv:
            return completed(argv, '{"full_name": "MoveIndustries/service-manager-catalog", "private": true, "has_issues": true}')
        creates += 1
        url = (
            "https://github.com/MoveIndustries/service-manager-catalog/issues/1\n"
            if creates == 1
            else "https://github.com/other-owner/other-repo/issues/2\n"
        )
        return completed(argv, url)

    monkeypatch.setattr(publisher.subprocess, "run", run)
    assert publisher.main([str(root), "--repo", "MoveIndustries/service-manager-catalog", "--apply"]) == 1
    captured = capsys.readouterr()
    assert "created first-issue https://github.com/MoveIndustries/service-manager-catalog/issues/1" in captured.out
    assert "outside the requested repository" in captured.err
    assert creates == 2
