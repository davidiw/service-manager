"""D30: computed provenance gaps (artifact_drift, mutable_artifact) from a matched observation row
joined against the catalog's declared `SourceRepository.artifact`/`tag`/`digest`. No stored state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from local_ops.catalog import Catalog, CatalogMeta, ServiceDoc, ServiceSpec, SourceRepository
from local_ops.discovery import observed_gaps


def _catalog(source_repositories: list[SourceRepository]) -> Catalog:
    spec = ServiceSpec(id="demo-app", name="Demo", source_repositories=source_repositories)
    doc = ServiceDoc(spec=spec, body="", path="demo-app.md", file_hash="h")
    meta = CatalogMeta(name="t")
    return Catalog(root=Path("/tmp/cat"), meta=meta, services={"demo-app": doc}, identities=[], revision="rev1", issues=[])


def _row(*, running: list[dict[str, Any]], match_service_id: str | None = "demo-app", resource_key: str = "k8s:c:demo:Deployment:u1") -> dict[str, Any]:
    return {
        "resource_type": "k8s/Deployment", "resource_key": resource_key, "provider_id": "kube-demo",
        "identity": {"namespace": "demo", "name": "app"}, "match_service_id": match_service_id, "match_binding_id": "b1" if match_service_id else None,
        "match_confidence": "verified", "attributes": {"running": running, "desired_images": [], "ownership": {"mechanism": "native"}, "also_matches": []},
    }


def test_no_declared_artifact_means_no_drift_gaps() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app")])  # no artifact declared
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": "repo/app@sha256:" + "a" * 64}])
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] in ("artifact_drift", "mutable_artifact") for g in gaps)


def test_digest_drift_is_reported() -> None:
    declared_digest = "sha256:" + "a" * 64
    running_digest = "sha256:" + "b" * 64
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", digest=declared_digest)])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": f"repo/app@{running_digest}"}])
    gaps = observed_gaps([row], cat)
    drift = [g for g in gaps if g["kind"] == "artifact_drift"]
    assert len(drift) == 1
    assert declared_digest in drift[0]["detail"] and running_digest in drift[0]["detail"]
    assert drift[0]["service_id"] == "demo-app" and drift[0]["basis"] == "observation"


def test_matching_digest_has_no_drift() -> None:
    digest = "sha256:" + "a" * 64
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", digest=digest)])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": f"repo/app@{digest}"}])
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] == "artifact_drift" for g in gaps)
    # The running image is pinned to a digest and is not one of the mutable tags: no mutable_artifact gap.
    assert not any(g["kind"] == "mutable_artifact" for g in gaps)


def test_tag_drift_is_reported_when_no_digest_declared() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", tag="v2")])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": ""}])
    gaps = observed_gaps([row], cat)
    drift = [g for g in gaps if g["kind"] == "artifact_drift"]
    assert len(drift) == 1 and "v2" in drift[0]["detail"] and "v1" in drift[0]["detail"]


def test_mutable_running_tag_is_reported_even_without_drift() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", tag="latest")])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:latest", "image_id": ""}])
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] == "artifact_drift" for g in gaps)
    mutable = [g for g in gaps if g["kind"] == "mutable_artifact"]
    assert len(mutable) == 1 and mutable[0]["service_id"] == "demo-app"


def test_running_without_any_digest_is_mutable_even_with_a_pinned_declared_tag() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", tag="v1")])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": ""}])
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] == "artifact_drift" for g in gaps)
    assert any(g["kind"] == "mutable_artifact" for g in gaps)


def test_different_repository_is_not_compared() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/other", digest="sha256:" + "a" * 64)])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": "repo/app@sha256:" + "b" * 64}])
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] in ("artifact_drift", "mutable_artifact") for g in gaps)


def test_unmatched_workload_is_not_considered_for_artifact_gaps() -> None:
    cat = _catalog([SourceRepository(url="https://github.com/example/app", artifact="repo/app", digest="sha256:" + "a" * 64)])
    row = _row(running=[{"pod": "app-0", "container": "app", "image": "repo/app:v1", "image_id": "repo/app@sha256:" + "b" * 64}], match_service_id=None)
    gaps = observed_gaps([row], cat)
    assert not any(g["kind"] in ("artifact_drift", "mutable_artifact") for g in gaps)
