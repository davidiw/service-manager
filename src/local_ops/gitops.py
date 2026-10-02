"""The only module allowed to shell out to `git` with a blocking `subprocess.run`.

Both read (`_git_revision`, used by `catalog.load_catalog`/`catalog.committed_change`) and write
(`commit_catalog_path`, used by catalog proposal acceptance D24 and the D29 provider-connection overlay)
go through this one module so `tests/test_async_bounds.py` can allowlist it by name while still
verifying every async caller offloads these calls with `asyncio.to_thread` (never blocks the event loop).
Fixed argv, no shell, everywhere here.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def git_revision_excluding_config(root: Path) -> str | None:
    """The hash of the most recent commit that touched catalog paths, excluding `config/` (the D29
    provider-connection overlay lives at `config/overlay.yaml`, server-written and reviewed, not approved
    catalog data; a commit that only changes it must never move the catalog revision)."""
    try:
        res = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%H", "--", ".", ":(exclude)config/*"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    head = res.stdout.strip()
    return head or None


class CatalogCommitError(RuntimeError):
    """Raised when a reviewed acceptance (catalog proposal D24, config overlay proposal D29) cannot
    commit its one path into the catalog's Git repository."""


def commit_catalog_path(root: Path, rel_path: str, message: str, author: str = "local-ops <local-ops@localhost>") -> str:
    """Commit exactly one path inside the catalog's own Git repository. Fixed argv, no shell, no
    auto-init: the catalog directory must already be a Git repository. Refuses if the repository already
    has other staged changes, so acceptance never commits someone else's in-progress edit and never
    touches a path it does not own. Shared by catalog proposal acceptance (D24) and the D29
    provider-connection overlay."""

    def _git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=10, check=False)

    check = _git("rev-parse", "--is-inside-work-tree")
    if check.returncode != 0 or check.stdout.strip() != "true":
        raise CatalogCommitError(f"{root} is not a Git repository; the server never initializes one")
    staged = _git("diff", "--cached", "--name-only")
    if staged.returncode != 0:
        raise CatalogCommitError("git diff --cached failed")
    pending = [ln for ln in staged.stdout.splitlines() if ln.strip()]
    if pending:
        raise CatalogCommitError(f"the catalog repository already has staged changes ({pending}); refusing to commit alongside them")
    add = _git("add", "--", rel_path)
    if add.returncode != 0:
        raise CatalogCommitError(f"git add {rel_path} failed: {add.stderr.strip()}")
    commit = _git("-c", "user.name=local-ops", "-c", "user.email=local-ops@localhost", "commit", f"--author={author}", "-m", message, "--", rel_path)
    if commit.returncode != 0:
        _git("reset", "--", rel_path)
        raise CatalogCommitError(f"git commit failed: {commit.stderr.strip()}")
    head = _git("rev-parse", "HEAD")
    if head.returncode != 0:
        raise CatalogCommitError("git rev-parse HEAD failed after commit")
    return head.stdout.strip()
