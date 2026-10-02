# Image update with explicit rollback

> **Documentation only — this server never executes Markdown.**
> Generic example. Grants no authority. The server's `update` and `rollback` operations run only
> for an execution-enabled, approved binding whose allowed image repositories are declared in
> the catalog.

## Principles

- **Deploy by digest, not by tag.** A mutable tag can point at a different image tomorrow; a
  digest (`repo@sha256:...`) is immutable and is what a receipt should record.
- **Only images from the allowed repositories.** The catalog's `allowed_image_repositories` is the
  allowlist; anything else is refused regardless of who asks.
- **Rollback is explicit.** The default `rollback_policy` is `explicit_only`: a failed update is
  reported, not silently reverted, because an automatic revert can hide the evidence of what went
  wrong and can itself be the wrong move for a stateful node.
- **Track desired vs. running.** The desired image reference (what the spec says) and the running
  container image ID (what the kubelet actually pulled) are different facts; record both.

## Before you update

1. Confirm the target by identity (cluster ARN, namespace, kind, name, UID).
2. Confirm the new image's digest and that its repository is on the allowlist.
3. Know the current digest so you can roll back to *it*, not to "the previous tag".
4. Check dependents and, for chain nodes, version compatibility with peers and any
   hard-fork/upgrade window.
5. Confirm there is no active incident; see `intrusion-first-response.md`.

## The shape of the procedure (illustrative)

```text
# Documentation only — this server never executes Markdown.
# 1. record current state
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> get <KIND>/<NAME> \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="<CONTAINER>")].image}'
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> get pods -l <SELECTOR> \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[*].imageID}{"\n"}{end}'

# 2. set the new image BY DIGEST
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> set image <KIND>/<NAME> \
  <CONTAINER>=<REGISTRY>/<REPO>@sha256:<DIGEST>

# 3. wait for convergence with a bounded timeout
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> rollout status <KIND>/<NAME> --timeout=180s

# 4. verify (ready replicas, health endpoint, version endpoint matches the artifact label)

# 5. rollback ONLY if explicitly decided
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> set image <KIND>/<NAME> \
  <CONTAINER>=<REGISTRY>/<REPO>@sha256:<PREVIOUS-DIGEST>
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> rollout status <KIND>/<NAME> --timeout=180s
```

`kubectl rollout undo` is an alternative for Deployments but it rolls to "the previous revision
in the controller's history", which is not necessarily the digest you recorded in step 1. Prefer
setting the known-good digest explicitly.

## Verifying

- `ready_replicas` converged.
- The service's declared `http_status` / `http_json` checks green.
- An `http_json` check with `equals_artifact_version` (where the service exposes a version field) reports the artifact's version label, which
  proves the new code is actually serving, not merely scheduled.
- Running container image IDs match the intended digest on every pod.

## How this maps to the server

`kubernetes_native` with `kind: image_update` requires `container`, `allowed_image_repositories`
and (by default) `require_digest: true`. `kind: rollback` takes an explicit target digest. Helm
bindings use `helm_upgrade` / `helm_rollback` on a named release instead. The server never reads
this file.
