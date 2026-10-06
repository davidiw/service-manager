# Developing a separate operations catalog

Keep service records and operational decisions in the catalog repository. Service Manager owns the
application-neutral parser, execution contracts and review machinery. A new service using an existing
deployment mechanism should require catalog data rather than service-specific Python.

The commands below read catalog files locally. They neither connect to providers nor grant execution
authority. Schema validity, approved configuration, current runtime evidence and permission to execute
are separate questions.

## Validation and editor schemas

Run from the Service Manager checkout with its locked environment:

```bash
uv sync --locked
uv run local-ops catalog validate /path/to/catalog --strict --documentary --format json
uv run local-ops catalog schema --kind service > /tmp/service.schema.json
uv run local-ops catalog schema --kind catalog > /tmp/catalog.schema.json
uv run local-ops catalog schema --kind identity > /tmp/identity.schema.json
uv run local-ops catalog report /path/to/catalog > /tmp/catalog-report.json
```

`validate` retains the existing human-readable output unless `--format json` is supplied. It exits 1
on validation errors; `--strict` additionally rejects missing metadata, an empty catalog and loader
warnings. `--documentary` requires `execution_allowed: false`. Invalid command options exit 2. Catalog
gaps such as an unknown owner remain visible in the report; they are not all schema errors.

`schema` generates JSON Schema from the same Pydantic models used by the loader. Apply the service
schema to a service file's YAML front matter, the catalog schema to `catalog.yaml`, and the identity
schema to each entry in `identities.yaml`. Cross-file checks and model validators still require the
CLI; JSON Schema alone does not replace it. Do not maintain a second handwritten schema.

`report` emits catalog declarations, provenance, declared operations/checks, unknowns and the canonical
`Catalog.gaps()` results. It does not establish approval, live health, credential availability or
executor availability. In particular, declaring a GitHub workflow does not wire a dispatcher.

Pin a separate catalog CI job to a reviewed Service Manager commit. Give checkout only the repository
read access it needs; never supply production provider credentials to catalog validation. Do not run
catalog-supplied scripts as part of validation.

## Publishing a reviewed issue packet

`scripts/publish-catalog-issues.py` consumes a directory containing `manifest.json` and Markdown issue
bodies. The target must match `--repo` exactly. Example manifest:

```json
{
  "repository": "example/operations-catalog",
  "issues": [
    {
      "id": "deployment-proof",
      "title": "Prove the reviewed deployment and rollback path",
      "body_file": "deployment-proof.md"
    }
  ]
}
```

The issue body should state the outcome, dated evidence, dependencies, acceptance criteria, proposed
reviewers and rollback/recovery requirements. Suggested reviewers are not assignments. The packet
must contain only material reviewed for sharing in the target repository, with credential references
rather than values. Keep source workbooks and raw operational evidence out of the packet.

```bash
# Offline preview; makes no GitHub requests.
python3 scripts/publish-catalog-issues.py /path/to/packet --repo example/operations-catalog

# After issue creation in this target has been authorized:
python3 scripts/publish-catalog-issues.py /path/to/packet --repo example/operations-catalog --apply
```

Publication uses the operator's existing `gh` authentication for GitHub.com. It verifies the canonical
repository name, requires a private repository with issues enabled, checks stable packet markers, and creates
missing issues sequentially. Existing open or closed issues are skipped so team edits survive reruns.
Returned issue URLs must match the same GitHub.com repository. The script does not assign people,
create labels or milestones, or overwrite issue bodies.

Run one publisher at a time for a given packet/repository. If a create times out, stop and inspect the
target before retrying; GitHub issue creation has no atomic idempotency key. Printed URLs retain the
completed portion. A rerun checks existing markers before creating anything further.

## Deployment rehearsal and its limits

The existing `scripts/demo-e2e.sh` is the generic end-to-end rehearsal. It may create a disposable kind
cluster and mutate its demo workloads, so running it requires authorization for that cluster action.
The recorded identity guard must succeed. It exercises digest resolution, reviewed updates, health
checks, failed health, explicit rollback and stale-plan/idempotency behavior through the existing
core. Production credentials and signing identities do not belong in this rehearsal.

Keep its results separate from a real service proof. A live proof additionally needs the exact target,
canonical source/build/config/state path, immutable prior/candidate artifacts, service-specific health
criteria, downgrade compatibility and separately authorized execution and rollback. The current GitHub
Actions executor is an unwired interface; its presence is not evidence of a complete workflow deployment.
