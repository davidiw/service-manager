#!/usr/bin/env python3
"""Regenerate .claude/agents/*.md from the canonical Codex roles in ~/.codex/agents/*.toml.

The Codex roles are the source of truth; the Claude files are thin mirrors (same mandate, Claude model and
tool mapping). Run after changing a Codex role: python3 scripts/sync-agents.py"""

from __future__ import annotations

import pathlib
import sys
import tomllib

SRC = pathlib.Path.home() / ".codex" / "agents"
DST = pathlib.Path(__file__).resolve().parents[1] / ".claude" / "agents"
MODEL = {"explorer": "haiku", "operator": "haiku", "worker": "sonnet", "reviewer": "opus"}
READ_ONLY_TOOLS = "Read, Grep, Glob, Bash"
WRITE_TOOLS = "Read, Grep, Glob, Bash, Edit, Write"


def render(a: dict) -> str:  # type: ignore[type-arg]
    n = a["name"]
    ro = a.get("sandbox_mode") == "read-only"
    guard = ("Codex runs this role in a read-only sandbox. Claude cannot enforce that here: do not edit files, do not run mutating commands, and never touch a Kubernetes context."
             if ro else "Codex runs this role with workspace-write. Stay inside the files and commands in your assignment.")
    return f"""---
name: {n}
description: {a['description']} Claude mirror of the Codex `{n}` role (~/.codex/agents/{n}.toml).
tools: {READ_ONLY_TOOLS if ro else WRITE_TOOLS}
model: {MODEL.get(n, 'inherit')}
---
<!-- Generated from ~/.codex/agents/{n}.toml by scripts/sync-agents.py. Edit the Codex role, then re-run. -->
Read `AGENTS.md` first; it is the repository authority. Engineering methodology comes from the Engineering
Harness skills (`engineering-harness:*` when the plugin is loaded, otherwise
`~/src/skills/engineering-harness/plugins/engineering-harness/skills/`); this role owns context and
permissions only, never policy.
{guard}

{a['developer_instructions'].strip()}
"""


def main() -> int:
    roles = sorted(SRC.glob("*.toml"))
    if not roles:
        print(f"no Codex roles in {SRC}", file=sys.stderr)
        return 1
    DST.mkdir(parents=True, exist_ok=True)
    for f in roles:
        a = tomllib.loads(f.read_text())
        (DST / f"{a['name']}.md").write_text(render(a))
        print(f"{f.name} -> .claude/agents/{a['name']}.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
