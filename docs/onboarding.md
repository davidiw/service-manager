# Onboarding: using Local Operations MCP

This guide takes a new engineer from nothing to asking an assistant real questions about the estate through
local-ops. `README.md` is the reference; this is the path through it.

## What local-ops is

A server on your machine that holds read-only (and, separately, write) credentials for AWS accounts,
Kubernetes clusters and 1Password, and exposes them to an assistant (Claude Code, Codex) over MCP. The
assistant never sees credentials. Every provider call is a **request** that you can review before it runs
and whose result you can review before the assistant sees it. Findings the assistant wants to keep become
**catalog proposals** that you accept and commit.

```
assistant ──MCP──> local-ops server ──read-only role──> AWS / Kubernetes / 1Password
                        │
                 review UI :8765  (you approve requests, release results, accept proposals)
```

## 1. Prerequisites

| Need | Why | How to check |
|---|---|---|
| `uv`, Python 3.12+ | runs the server | `uv --version` |
| AWS Identity Center user with the read-only permission set on each account | the server's AWS identity | portal shows the read-only role on every account |
| AWS CLI v2 | SSO login | `aws --version` |
| `kubectl` | cluster access through EKS access entries | `kubectl version --client` |
| 1Password CLI `op` (optional) | 1Password metadata inventory | `op --version` |
| `gh` (optional) | GitHub context for assistants | `gh auth status` |

Never use an administrator permission set for local-ops. The server checks the role name on every AWS call
(`expected_role`) and refuses anything else.

## 2. Install and initialise

```bash
git clone <this repository> && cd service-management
uv sync --locked
uv run local-ops init --config-dir ./local-config --state-dir ./local-state
```

`init` asks for a reviewer password and writes `local-config/keys.env` (mode 0600) with the assistant keys.
`local-config/` and `local-state/` are gitignored: keep them that way.

## 3. Configure providers

Edit `local-config/server.yaml`. Each provider is a credential **reference** plus a scope.

**AWS account** — one SSO profile per account in `~/.aws/config`, using the read-only permission set:

```ini
[sso-session <session>]
sso_start_url = https://<org>.awsapps.com/start
sso_region = us-west-2

[profile <alias>-ro]
sso_session = <session>
sso_account_id = <account id>
sso_role_name = <read-only permission set>
region = us-west-2
```

```yaml
credentials:
  - {id: aws-<alias>-ro, kind: aws_sso, profile: <alias>-ro, purpose: read}
providers:
  - id: aws-<alias>
    kind: aws
    credential: aws-<alias>-ro
    account_alias: <alias>
    expected_account_id: "<account id>"
    expected_role: "AWSReservedSSO_<read-only permission set>_*"
    regions: [us-west-2, us-east-1]
    organizations_enumeration: false
```

Enable `organizations_enumeration: true` only on the management account provider.

**Kubernetes cluster** — every EKS cluster you want visible needs (a) an EKS access entry for the read-only
role with a view policy (cluster admins grant this), and (b) a context in a dedicated kubeconfig:

```bash
aws eks update-kubeconfig --profile <alias>-ro --region <region> --name <cluster> \
  --alias <alias>-<cluster> --kubeconfig ~/.kube/local-ops-<alias>
```

```yaml
credentials:
  - {id: kube-<alias>-<cluster>-ro, kind: kubeconfig_context, kubeconfig: ~/.kube/local-ops-<alias>, context: <alias>-<cluster>, purpose: read}
providers:
  - id: kube-<alias>-<cluster>
    kind: kubernetes
    credential: kube-<alias>-<cluster>-ro
    context: <alias>-<cluster>
    cluster_identity: {kube_system_uid: <uid>, eks_arn: "arn:aws:eks:<region>:<account id>:cluster/<cluster>"}
    namespaces: []          # empty = all namespaces
```

`cluster_identity` pins the provider to one cluster: `kube_system_uid` is the UID of the `kube-system`
namespace (`kubectl --context <alias>-<cluster> get ns kube-system -o jsonpath='{.metadata.uid}'`).
A cluster that appears in the AWS census but has no provider here shows up as "workloads unknown".

**1Password** (optional) — a credential `{id: op-user, kind: onepassword_cli, account: <account shorthand>,
purpose: read}` and a provider `{id: onepassword-main, kind: onepassword, credential: op-user, vaults: []}`
(empty = every vault you can see); see README "Human-operated 1Password CLI inventory". The server only
lists vault and item metadata.

Check everything: `uv run local-ops doctor --config ./local-config/server.yaml --catalog <catalog> --live`.

## 4. Start the server

```bash
aws sso login --sso-session <session>          # AWS credentials expire; log in first
op signin                                       # optional, in the same shell
uv run local-ops serve --config ./local-config/server.yaml --catalog <catalog dir>
```

The server inherits your SSO and `op` sessions at start. After re-authenticating, restart it.
Open http://127.0.0.1:8765/review and log in as `reviewer`.

## 5. Connect an assistant

```bash
set -a; . ./local-config/keys.env; set +a
scripts/claude            # Claude Code with this repo's skills; .mcp.json wires local-ops-read
```

Codex reads `.codex/config.toml`. The write surface (`local-ops-write`) is never wired by default.

## 6. Daily use

1. **Ask a question.** "Is the mainnet indexer healthy?", "Who can access the tools account?"
2. **Requests appear in the review queue** (banner and nav counts on every page). Inventory scans and
   control-only reads may run without review; content (logs, CloudTrail, metrics) follows your Settings.
3. **Approve** a request to let it run; **release** its result to let the assistant read it, or withhold it.
4. **Proposals** (Proposals page) are stacked per service. Accept or reject inline. Accepting writes a patch
   under `local-state/proposals/`; apply and commit it in the catalog repository:
   ```bash
   cd <catalog dir> && git apply <path>/local-state/proposals/<id>.patch && git commit -am "<what changed>"
   ```
   The server reloads the catalog within seconds of the commit.

Review modes (Settings, per client and data class): `review_both`, `review_requests`, `review_responses`,
`yolo`. A common setup is inventory `yolo`, content `review_responses`, mutation `review_both`. YOLO skips
human review only; authorization, bounds and credential protection still apply.

## 7. What the assistant can and cannot see

- Can: released observations, released evidence, the approved catalog, its own proposals.
- Cannot: credentials, secret values, 1Password item fields, unreleased results, anything outside configured
  providers and regions.
- "Nothing observed" is not "nothing exists": check the coverage block of every answer.

## 8. Safety rules

- Read-only identities only for the read surface; production signing identities never go into local-ops.
- Do not commit `local-config/`, `local-state/` or estate reports to a public repository.
- Mutations (deployments, restarts) go through the write surface, a reviewed plan and the stop switch, and
  are tested only against the disposable kind cluster (`scripts/demo-cluster.sh`).

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `auth_required` from AWS | `aws sso login --sso-session <session>`, restart the server |
| 1Password `auth_required` | `op signin` in the shell that starts the server, restart |
| Cluster shows "workloads unknown" | add an EKS access entry for the read-only role and a kubeconfig context + provider |
| `clock skew` errors | enable time sync (`timedatectl set-ntp true`) |
| Catalog proposal refused as stale/conflict | the catalog changed; the assistant re-reads and proposes again |
| Result looks truncated | results over 4 MB are bounded at release; scan one account at a time |
