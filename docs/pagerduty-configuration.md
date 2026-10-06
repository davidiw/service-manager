# PagerDuty configuration contract

This document describes the bounded PagerDuty configuration contract. It is not a
claim that a PagerDuty account has been configured, tested, or changed. Documentary catalogs remain
`execution_allowed: false`; enabling a catalog, loading a write credential reference, installing or
restarting the runtime, and performing a live operation are separate actions that require user
authorization. This contract does not mutate PagerDuty accounts, users, or incidents outside a released,
reviewed operation.

## Scope and authority

The `configure` action uses the normal `action_prepare` / released immutable plan / `action_submit` flow.
It accepts typed configuration only: schedule creation, escalation-policy creation or update, service
routing update, deletion of a named legacy schedule, and reassignment of an active incident to an
escalation policy. Raw HTTP is not an input. A schedule configuration creates a schedule; it does not
replace an arbitrary existing multi-layer schedule. Escalation policies may be created or updated, and a
service may only have its escalation-policy routing updated.

The catalog binding must name an exact PagerDuty target: `resource_type` is `schedule`,
`escalation_policy`, `service`, or `incident`; `account_domain` is a lowercase
`subdomain.pagerduty.com` or `subdomain.eu.pagerduty.com`; `id` is a validated provider ID when the resource
already exists; and `name` is required. An omitted ID is valid only for creating a schedule or escalation
policy. The executable operation must use the `pagerduty_configuration` executor, `configure` kind, and the built-in
`pagerduty_configuration_matches` health check.

An incident target always carries its exact ID, title, and account domain in the catalog. Its `configure`
operation must also declare `pagerduty_actor_user_id`, a selected human PagerDuty user reference. The server
does not choose a default actor or impersonate another user. It resolves that actor's email privately under
the execution credential for PagerDuty's request header; the email is never stored or released.

The synthetic example below illustrates the catalog shape. It uses no live identity or credential value.

```yaml
# catalog.yaml -- an executable catalog requires an independently authorized decision.
name: example-pagerduty
execution_allowed: true
```

```yaml
---
schema_version: 1
id: example-oncall
name: Example on-call configuration
purpose: Synthetic PagerDuty configuration example.
owner: Example operator
bindings:
  - id: pagerduty-engineering
    environment: example
    provider_id: pagerduty-example
    execution_enabled: true
    source_state: verified
    pagerduty_target:
      resource_type: schedule
      account_domain: example.pagerduty.com
      name: Example Engineering Rotation
operations:
  configure:
    executor: pagerduty_configuration
    kind: configure
    binding_id: pagerduty-engineering
    health_checks: [pagerduty_configuration_matches]
---
```

Credentials are references only. The provider uses its read credential for released configuration evidence;
`provider.execution_credential` is required for every prepare, execution, and reconciliation
configuration read. There is no fallback to the read key. The actual write credential is independently
checked against the target account using the resource URL hostname (or the users listing for a create).
Every existing target must match exact ID, name, and account domain. Responses are projected and stripped of
integration keys.

## Preparing typed configuration

Schedule input has an aware `rotation_start`, an IANA `time_zone`, 1–50 unique ordered `user_ids`, optional
description, and a rotation length from 3,600 to 2,592,000 seconds. For a three-day rotation use exactly
`259200` seconds. That is elapsed time, so local handoff clock time can shift at daylight-saving transitions;
the aware start and named timezone make the selected schedule explicit.

```yaml
action: configure
desired_configuration:
  kind: schedule
  name: Example Engineering Rotation
  time_zone: America/Los_Angeles
  rotation_start: 2026-11-02T17:00:00-08:00
  rotation_turn_length_seconds: 259200
  user_ids: [PUSER01, PUSER02, PUSER03]
  description: Synthetic three-day engineering rotation
```

An escalation policy uses `num_loops` from 0 through 9. Each rule has a 1–60 minute delay and typed user or
schedule references. Service routing supplies the exact escalation-policy ID. Legacy schedule deletion needs
the target ID plus `kind: schedule_delete` and a matching `confirm_name`; it is not a general delete surface.

```yaml
# Escalation-policy create or update
action: configure
desired_configuration:
  kind: escalation_policy
  name: Example Engineering Escalation
  num_loops: 1
  rules:
    - delay_minutes: 5
      targets:
        - {id: PSCHEDULE01, type: schedule_reference}
        - {id: PUSER01, type: user_reference}

# Routing update for an existing service target
action: configure
desired_configuration:
  kind: service_routing
  escalation_policy_id: PEPOLICY01

# Deletion is restricted to an exact legacy schedule target
action: configure
desired_configuration:
  kind: schedule_delete
  confirm_name: Example Retired Rotation

# Reassigns the catalog-bound active incident; caller input contains only the new policy ID.
# The operation declaration carries the mandatory synthetic actor reference:
# pagerduty_actor_user_id: PACTOR01
action: configure
desired_configuration:
  kind: incident_reassignment
  escalation_policy_id: PEPOLICY01
```

Before prepare and again before dispatch, the executor validates every referenced user, schedule, and
escalation-policy ID in the same account. It uses complete lists for name absence and schedule-reference
checks. Schedule rendering is a bounded read: a `pagerduty_configuration` evidence query for a schedule
requires an exact `scope.resource_id` and a time range no longer than 31 days. Configuration evidence is
stored through the normal release gate. The check verifies configuration only; it never proves page or
incident delivery.

## Write, reconciliation, and limits

All configuration actions for one PagerDuty API base URL/account use the account-wide lock
`pagerduty:<api_base_url>:<account_domain>`, so provider aliases for the same estate serialize together.
The immutable plan contains projected relevant configuration,
the before state, method, resource type, resource ID, and payload. An intent is persisted before a write.
After an accepted write, the executor immediately rereads and verifies the requested configuration subset.

An uncertain write is never retried automatically, especially a `POST` where PagerDuty may have accepted a
create before the connection failed. An accepted create records the returned ID. If that ID was not confirmed,
reconciliation reports `outcome_unknown`: a same-name resource does not establish ownership and is never
used to infer success. Failure reconciliation reads only and never resends a mutation. PagerDuty provides no
documented conditional write for these endpoints, so an external change can race the pre-dispatch reread;
the immediate reread exposes residual drift but does not provide remote compare-and-swap or atomic fencing.

A typed 4xx refusal is a confirmed refusal and is not retried. That differs from an uncertain transport
failure or a create whose accepted resource ID was not returned, which follows the read-only reconciliation
path above. A legacy-schedule delete can remain blocked by open incidents that retain a snapshot of its old
escalation policy even after current references have migrated. A released incident-reassignment plan can
refresh that snapshot, which can notify the newly on-call responder, and can remove this deletion dependency.
It never acts automatically.

Incident reassignment is restricted to the catalog-bound active incident and supplies only
`kind: incident_reassignment` plus the new escalation-policy ID. It cannot acknowledge, resolve, snooze,
create, or delete an incident. If an uncertain reassignment targets the same escalation policy the incident
already had, seeing that policy again cannot prove the refresh occurred; reconciliation remains
`outcome_unknown` and never resends the request. See PagerDuty's
[escalation policy documentation](https://support.pagerduty.com/main/docs/escalation-policies).

Writes are limited to `POST` for schedules and escalation policies, `PUT` for escalation policies and
services, and `DELETE` for schedules. Requests use only the configured allowlisted US or EU PagerDuty API
host, reject redirects, and treat a GET 404 as explicit absence; other errors are safe failures without a
response body.

## Default Mobilization

Default Mobilization is a PagerDuty system service. This contract cannot delete, archive, or guarantee hiding
it. PagerDuty documents an account setting that disables automatic use of Default Mobilization. When it is
off, declaring an incident requires an Impacted Service. The administrator path is **Account Settings →
Incident Settings → Allow default mobilization**. This setting does not guarantee that Default Mobilization
will be hidden. See PagerDuty's
[Default Mobilization service documentation](https://support.pagerduty.com/main/docs/default-mobilization-service).
This limitation does not authorize a workaround or removal call.

Names and IDs in this document are synthetic placeholders. They are not source-specific mappings for any
team, migration, or existing schedule.
