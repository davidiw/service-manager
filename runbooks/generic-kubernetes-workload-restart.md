# Generic Kubernetes workload restart

> **Documentation only — this server never executes Markdown.**
> This is a generic example. It does not describe any specific production system and grants no
> authority. The server's `restart` operation runs only for a catalog binding that is execution
> enabled, fully identified (cluster identity, namespace, kind, name) and approved.

## When a restart is the right tool

A rollout restart replaces every pod of a controller with a fresh one running the *same* desired
spec. It helps with: a wedged process, a leaked connection pool, picking up a rotated Secret or
ConfigMap that the process reads only at start. It does **not** help with: a bad image (use an
update/rollback), insufficient resources (the new pods will hit the same limit), a broken
dependency (restarting the consumer does not fix the producer), or a stateful node that must
re-sync (a restart may cost hours of catch-up).

## Before you restart

1. **Confirm the target by identity, not by name.** Cluster ARN, namespace, controller kind and
   name, and the controller UID. A pod name is a lead, not an identity.
2. **Check what depends on it** (`depends_on` / `used_by` in the catalog). For a stateful chain
   node, check quorum/availability constraints: how many peers may be down at once.
3. **Check that it is not already rolling.** A restart during a rollout compounds the problem.
4. **Check for an active incident or intrusion.** If compromise is suspected, do *not* restart
   first: see `intrusion-first-response.md`. A restart destroys in-memory evidence.
5. **Snapshot current state** so you can tell what changed: desired image reference, running image
   digest, replica counts, recent events, last N log lines.

## The shape of the procedure (illustrative)

```text
# Documentation only — this server never executes Markdown.
# 1. identify
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> get <KIND>/<NAME> -o wide
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> describe <KIND>/<NAME>

# 2. snapshot evidence
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> get events --sort-by=.lastTimestamp | tail -50
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> logs <KIND>/<NAME> --tail=500 > before.log

# 3. restart (Deployment / StatefulSet / DaemonSet)
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> rollout restart <KIND>/<NAME>

# 4. wait for convergence with a bounded timeout
kubectl --context <CLUSTER-IDENTITY> -n <NAMESPACE> rollout status <KIND>/<NAME> --timeout=180s
```

For a **StatefulSet** the pods restart one at a time in reverse ordinal order and each must
become Ready before the next is replaced. For a chain node this means the restart time is the
sum of per-pod sync times; do not interpret a slow rollout as a failure without looking at the
pod's own readiness reason.

## Verifying

- All desired replicas Ready and the rollout converged (`ready_replicas`).
- The service-specific health signal is back: HTTP health 2xx, or for an RPC node the ledger
  version advancing and the chain id matching the expectation (an `http_json` check declared in the service file).
- Downstream consumers recover (lag draining, error rate falling).
- If a check fails: record the outcome as `failed` or `outcome_unknown`, do not retry blindly,
  and do not proceed to a destructive step from an old document.

## How this maps to the server

The server's `kubernetes_native` executor with `kind: rollout_restart` performs steps 3-4 and the
configured health checks, and writes a receipt. It refuses to run unless the binding is execution
enabled, the catalog allows execution, and the request was approved. It never reads this file.
