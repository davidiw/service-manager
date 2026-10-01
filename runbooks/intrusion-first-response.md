# Intrusion first response

> **Documentation only — this server never executes Markdown.**
> Generic example. Grants no authority. Nothing here authorises destructive action; the point of
> this document is to slow down the reflex to "just restart it".

## The first rule: preserve evidence, then contain, then restart (if at all)

A restart is often the *worst* first move in a suspected intrusion: it destroys process memory,
ephemeral filesystem contents, open connections and the running container's image ID, and it may
be exactly what the attacker's persistence is waiting for. Containment that preserves the
artefact (isolate, revoke, snapshot) comes first.

## 0. Declare and record

- Open an incident record with the time you started, who is involved, and what you observed.
- Decide who is the single decision-maker for destructive actions.
- From here on, every action and its timestamp goes in the record.

## 1. Preserve evidence (do this before anything else that changes state)

- **Do not restart, scale to zero, or delete** the suspicious workload.
- **Do not rotate the credential yet** if rotation would also delete the audit trail of its use;
  rotate once you have captured who used it, from where, and when.
- Snapshot what can be snapshotted: pod spec and status (`get -o yaml`), running container image
  IDs, recent events, logs (all containers, including previous instances), node identity, and the
  EBS/EFS volumes behind a stateful pod.
- Capture a consistent time window for every source you will query (start a little before the
  first anomaly).

## 2. Contain without destroying

Choose the least destructive effective step:

- Network isolation of the pod (a deny-all NetworkPolicy or a security group change) rather than
  deletion.
- Revoke the *path in*: disable the compromised identity's access keys / sessions, remove the
  role binding, suspend the GitHub user, revoke the 1Password session. Capture the identity's
  recent activity first (step 3).
- Cordon the node if the compromise may be node-level.
- For signing identities (validators, relayers, multisig): escalate to the key custodians; this
  server must never touch key material.

## 3. What to query in this server (read-only, diagnosis capability)

The Local Operations server joins the approved catalog with observed state and audit sources. In
a suspected intrusion, use it to answer *who, what, when, from where* before changing anything:

1. **Which service is this?** Look the resource up by identity (cluster ARN + namespace + kind +
   name/UID). If it is not in the catalog, that is itself a finding: an unapproved workload.
2. **What does it depend on and what depends on it?** The catalog's `depends_on` / `used_by`
   bound the blast radius.
3. **What changed recently?** Image reference and digest history, controller revisions,
   recent events, Helm release history, and the service's receipt history in this server
   (was there an approved operation at that time, or not?).
4. **Who acted?** Normalized audit events for the time window from each configured audit source:
   - AWS CloudTrail / EKS control-plane audit log (who called the API, from which principal and
     IP; remember event-history scope and retention limits),
   - GitHub audit log (workflow runs, pushes to deploy branches, membership and secret changes),
   - 1Password events (sign-ins, item reads, vault membership changes),
   - GuardDuty runtime findings for the cluster/node.
5. **Did a departed or unexpected identity act?** The departed-identity rule flags activity by
   identities marked departed/revoked in `identities.yaml`, and identities not in
   `expected_identities`. An empty identities file means this check is blind, which is a gap to
   record, not a clean result.
6. **What credentials does this service reference?** `credential_refs` tells you what to rotate
   later and where custody is supposed to be (and where it is `unknown`).
7. **What is the coverage?** The coverage object tells you which sources were actually queried
   and over what window. Absence of an event in a source that was not queried, or whose retention
   has elapsed, is not evidence of absence.

Record the query results (or their export) as evidence with timestamps.

## 4. Only then decide on restart / rebuild

- If you must restore service, prefer **replace** over **restart**: deploy a known-good digest to
  fresh pods on a fresh node while the suspicious pod stays isolated for forensics.
- Any such change goes through the normal approval path (exact request review, execution-enabled
  binding). An incident does not relax the catalog's execution rules.
- Do not run destructive recovery steps from old documents. Validate recovery procedures against the
  verified target and its current configuration first.

## 5. Afterwards

- Rotate every credential the workload could reach, in the order that preserves audit trails.
- Record which questions could not be answered (missing logs, retention gaps, unknown custody) as
  catalog unknowns and gaps so they are fixed before the next incident.
- Update `identities.yaml` with any revocations, dated.
