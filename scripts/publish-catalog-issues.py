#!/usr/bin/env python3
"""Publish a reviewed catalog issue packet through the operator's ``gh`` login.

The default mode is an offline preview.  ``--apply`` is deliberately required
before this script makes any GitHub request or creates an issue.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
REPOSITORY_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?\Z"
)
EXISTING_MARKER_RE = re.compile(r"<!-- local-ops-plan:([a-z0-9]+(?:-[a-z0-9]+)*) -->")


class PacketError(ValueError):
    """A packet cannot safely be published."""


@dataclass(frozen=True)
class Issue:
    issue_id: str
    title: str
    body_path: Path
    body: str


@dataclass(frozen=True)
class Packet:
    repository: str
    issues: tuple[Issue, ...]


def marker(issue_id: str) -> str:
    return f"<!-- local-ops-plan:{issue_id} -->"


def _issue_url_for_repo(url: str, repo: str) -> bool:
    parsed = urlsplit(url)
    expected_owner, expected_name = repo.casefold().split("/", maxsplit=1)
    path = parsed.path.split("/")
    return (
        parsed.scheme == "https"
        and parsed.netloc == "github.com"
        and not parsed.query
        and not parsed.fragment
        and not parsed.username
        and not parsed.password
        and len(path) == 5
        and path[0] == ""
        and path[1].casefold() == expected_owner
        and path[2].casefold() == expected_name
        and path[3] == "issues"
        and path[4].isdigit()
        and int(path[4]) > 0
    )


def _body_path(root: Path, value: object) -> Path:
    if not isinstance(value, str) or not value:
        raise PacketError("body_file must be a non-empty relative path")
    candidate = Path(value)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise PacketError(f"unsafe body_file path: {value!r}")
    path = root / candidate
    if path.is_symlink():
        raise PacketError(f"body_file must not be a symlink: {value!r}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise PacketError(f"body_file escapes packet or does not exist: {value!r}") from exc
    if not resolved.is_file():
        raise PacketError(f"body_file is not a file: {value!r}")
    return resolved


def load_packet(packet_path: str | Path, expected_repo: str) -> Packet:
    if not REPOSITORY_RE.fullmatch(expected_repo):
        raise PacketError("--repo must be an exact owner/repository name")
    try:
        root = Path(packet_path).resolve()
    except OSError as exc:
        raise PacketError("packet path could not be read") from exc
    manifest_path = root / "manifest.json"
    if not root.is_dir() or not manifest_path.is_file():
        raise PacketError("packet must be a directory containing manifest.json")
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PacketError("invalid manifest.json") from exc
    if not isinstance(data, dict) or data.get("repository") != expected_repo:
        raise PacketError("manifest repository must exactly match --repo")
    entries = data.get("issues")
    if not isinstance(entries, list) or not entries:
        raise PacketError("manifest issues must be a non-empty list")
    issues: list[Issue] = []
    ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise PacketError("each manifest issue must be an object")
        issue_id, title = entry.get("id"), entry.get("title")
        if not isinstance(issue_id, str) or not ID_RE.fullmatch(issue_id):
            raise PacketError("issue id must be lowercase-kebab")
        if issue_id in ids:
            raise PacketError(f"duplicate issue id: {issue_id}")
        if not isinstance(title, str) or not title.strip():
            raise PacketError(f"issue {issue_id} has an empty title")
        path = _body_path(root, entry.get("body_file"))
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise PacketError(f"issue {issue_id} body could not be read") from exc
        if not body.strip():
            raise PacketError(f"issue {issue_id} has an empty body")
        if "local-ops-plan:" in body:
            raise PacketError(f"issue {issue_id} body already contains a local-ops-plan marker")
        issues.append(Issue(issue_id, title, path, body))
        ids.add(issue_id)
    return Packet(expected_repo, tuple(issues))


def _run(argv: Sequence[str], operation: str) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(list(argv), capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"GitHub {operation} had an unknown outcome; stopping without retry") from exc
    if (
        not isinstance(result, subprocess.CompletedProcess)
        or type(result.returncode) is not int
        or not isinstance(result.stdout, str)
        or not isinstance(result.stderr, str)
    ):
        raise RuntimeError(f"GitHub {operation} returned an invalid result")
    return result


def _json_gh(args: Sequence[str], operation: str) -> Any:
    result = _run(["gh", *args], operation)
    if result.returncode:
        raise RuntimeError(f"GitHub {operation} failed")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub API returned invalid JSON") from exc


def _existing_markers(repo: str) -> dict[str, str]:
    repository = _json_gh(["api", "--hostname", "github.com", f"repos/{repo}"], "repository check")
    if not isinstance(repository, dict) or not isinstance(repository.get("full_name"), str) or repository["full_name"].casefold() != repo.casefold():
        raise PacketError("refusing to publish when repository identity does not match --repo")
    if repository.get("private") is not True:
        raise PacketError("refusing to publish to a non-private repository")
    if repository.get("has_issues") is not True:
        raise PacketError("refusing to publish where issues are disabled")
    pages = _json_gh(
        ["api", "--hostname", "github.com", "--paginate", "--slurp", f"repos/{repo}/issues?state=all&per_page=100"],
        "existing-issues check",
    )
    rows = [row for page in pages for row in page] if isinstance(pages, list) and all(isinstance(page, list) for page in pages) else pages
    if not isinstance(rows, list):
        raise RuntimeError("GitHub issues response was not a list")
    found: dict[str, list[str]] = {}
    for row in rows:
        if not isinstance(row, dict) or "pull_request" in row:
            continue
        body = row.get("body")
        if not isinstance(body, str):
            continue
        issue_ids = EXISTING_MARKER_RE.findall(body)
        if not issue_ids:
            continue
        url = row.get("html_url")
        if not isinstance(url, str) or not _issue_url_for_repo(url, repo):
            raise RuntimeError("GitHub existing-issues check returned an issue without a URL")
        for issue_id in issue_ids:
            found.setdefault(issue_id, []).append(url)
    duplicates = sorted(issue_id for issue_id, urls in found.items() if len(urls) > 1)
    if duplicates:
        raise PacketError("duplicate existing issue markers: " + ", ".join(duplicates))
    return {issue_id: urls[0] for issue_id, urls in found.items()}


def preview(packet: Packet) -> None:
    print(f"repository: {packet.repository}")
    for issue in packet.issues:
        print(f"{issue.issue_id}\t{issue.title}\t{issue.body_path}")


def apply(packet: Packet) -> None:
    existing = _existing_markers(packet.repository)
    for issue in packet.issues:
        if issue.issue_id in existing:
            print(f"skipped {issue.issue_id} {existing[issue.issue_id]}", flush=True)
            continue
        content = issue.body.rstrip() + "\n\n" + marker(issue.issue_id) + "\n"
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".md", delete=False) as handle:
            handle.write(content)
            body_file = handle.name
        try:
            result = _run(
                ["gh", "issue", "create", "--repo", f"github.com/{packet.repository}", "--title", issue.title, "--body-file", body_file],
                "issue creation",
            )
        finally:
            Path(body_file).unlink(missing_ok=True)
        if result.returncode:
            raise RuntimeError("GitHub issue creation failed; stopping without retry")
        url = result.stdout.strip()
        if not url:
            raise RuntimeError("issue creation returned no URL; stopping without retry")
        if not _issue_url_for_repo(url, packet.repository):
            raise RuntimeError("issue creation returned a URL outside the requested repository; stopping without retry")
        print(f"created {issue.issue_id} {url}", flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packet")
    parser.add_argument("--repo", required=True, help="expected owner/repository target")
    parser.add_argument("--apply", action="store_true", help="perform GitHub checks and issue creation")
    args = parser.parse_args(argv)
    try:
        packet = load_packet(args.packet, args.repo)
        if args.apply:
            apply(packet)
        else:
            preview(packet)
    except (PacketError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
