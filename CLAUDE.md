# Claude Code entry point

`AGENTS.md` is the repository authority for every agent and is imported below so Claude always loads it,
as Codex does. Do not duplicate policy in this file.

- Start sessions with `scripts/claude`, which loads the Engineering Harness skills from the davidiw/skills
  checkout and exports the MCP keys. Plain `claude` works but has no harness skills.
- Subagents in `.claude/agents/` mirror the Codex roles in `~/.codex/agents/` (`scripts/sync-agents.py`).

@AGENTS.md
