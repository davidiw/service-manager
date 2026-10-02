# Runbooks

> **Documentation only — this server never executes Markdown.**

These files are **generic examples** of how an operator might approach common situations. They are
not executable authority, they are not validated against any production system, and they
are not read by the Local Operations MCP server as instructions. The server's only sources of
authority are:

1. the approved catalog (`catalog/<name>/services/*.md` front matter) with execution enabled per
   binding and per catalog, and
2. the server configuration and the approval given at request time.

Commands shown in these runbooks are illustrations of *shape*. Before any of them is run by a
human, the target (account, cluster identity, namespace, controller) must be confirmed from
runtime discovery, not copied from a document.

## Contents

| File | What it covers |
|---|---|
| `generic-kubernetes-workload-restart.md` | How a rollout restart of a Deployment/StatefulSet is normally approached, what to check first, and how it maps to this server's `restart` operation. |
| `image-update-with-rollback.md` | Updating a container image by digest with an explicit rollback path, mapped to the `update` / `rollback` operations. |
| `intrusion-first-response.md` | First hour of a suspected intrusion: preserve evidence, contain, and what to query in this server before restarting anything. |
