"""Storage integrity and correlation boundaries, without a VM or service."""

from dataclasses import FrozenInstanceError
import hashlib

import pytest
from pydantic import ValidationError

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, load_record, parse_json
from agent_pipeline.evidence import (
    ArtifactInput, CollectionMetadata, EvidenceArtifact, EvidenceLimits,
    EvidenceManifest, EvidenceSealingError, EvidenceStore,
    EvidenceVerificationError, ExecutionCorrelation, SealingMetadata,
)


@pytest.fixture
def correlation():
    return ExecutionCorrelation(job_id="job-1", task_id="task-1",
                                execution_harness_id="a" * 64,
                                vm_instance_id="vm-1", lane=1, generation_id=7)


@pytest.fixture
def metadata():
    return {
        "collection": CollectionMetadata(collector_id="runner-1", started_at_ns=10,
                                         completed_at_ns=20),
        "sealing": SealingMetadata(sealer_id="runner-1", sealed_at_ns=30),
    }


@pytest.fixture
def artifacts():
    return (
        ArtifactInput(identity="coverage", type="remote_kcov", data=b"\x00\xffcoverage"),
        ArtifactInput(identity="status", type="application/json", data=b'{"ok":true}'),
    )


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(ArtifactStore(tmp_path / "artifacts"))


@pytest.fixture
def sealed(store, artifacts, correlation, metadata):
    return store.seal(artifacts, correlation=correlation, **metadata)


def change_manifest(store, sealed, change):
    payload = parse_json(store.artifacts.get(sealed))
    change(payload)
    return store.artifacts.put(canonical_json(payload))


def test_seal_canonical_roundtrip_and_snapshot(store, sealed, correlation, artifacts):
    bundle = store.verify(sealed, expected_correlation=correlation,
                          expected_types={"coverage": "remote_kcov"})
    assert bundle.manifest_sha256 == sealed
    assert bundle.manifest.correlation == correlation
    assert canonical_json(bundle.manifest) == store.artifacts.get(sealed)
    assert load_record(store.artifacts, sealed, EvidenceManifest) == bundle.manifest
    assert bundle.get("coverage", expected_type="remote_kcov") == artifacts[0].data
    assert bundle.get("status", expected_type="application/json") == artifacts[1].data
    assert len(bundle.artifacts) == 2
    # Consumers keep verified immutable bytes even if storage later changes.
    store.artifacts._path(bundle.manifest.artifacts[0].sha256).write_bytes(b"changed")
    assert bundle.get("coverage", expected_type="remote_kcov") == artifacts[0].data
    with pytest.raises(EvidenceVerificationError):
        store.verify(sealed, expected_correlation=correlation)


def test_deterministic_seal_order(store, artifacts, correlation, metadata):
    first = store.seal(artifacts, correlation=correlation, **metadata)
    second = store.seal(tuple(reversed(artifacts)), correlation=correlation, **metadata)
    assert first == second


def test_all_models_and_verified_snapshot_are_immutable(store, sealed, correlation):
    bundle = store.verify(sealed, expected_correlation=correlation)
    for model, field, value in (
        (bundle.manifest, "schema_version", 2),
        (bundle.manifest.artifacts[0], "size", 999),
        (bundle.manifest.correlation, "task_id", "other"),
        (bundle.manifest.collection, "completed_at_ns", 999),
        (bundle.manifest.sealing, "sealed_at_ns", 999),
    ):
        with pytest.raises(ValidationError):
            setattr(model, field, value)
    with pytest.raises(FrozenInstanceError):
        bundle.manifest_sha256 = "b" * 64
    with pytest.raises(FrozenInstanceError):
        bundle.artifacts[0].data = b"changed"


@pytest.mark.parametrize("field,value", [
    ("job_id", "other-job"), ("task_id", "other-task"),
    ("execution_harness_id", "b" * 64), ("vm_instance_id", "other-vm"),
    ("lane", 2), ("generation_id", 8),
])
def test_every_host_correlation_field_must_match(store, sealed, correlation, field, value):
    expected = ExecutionCorrelation.model_validate(
        {**correlation.model_dump(), field: value})
    with pytest.raises(EvidenceVerificationError, match="trusted expected correlation"):
        store.verify(sealed, expected_correlation=expected)


def test_correlation_is_required_even_when_manifest_hash_matches(store, sealed):
    assert hashlib.sha256(store.artifacts.get(sealed)).hexdigest() == sealed
    with pytest.raises(TypeError):
        store.verify(sealed)
    with pytest.raises(EvidenceVerificationError):
        store.verify(sealed, expected_correlation=None)


@pytest.mark.parametrize("field,value", [
    ("lane", "1"), ("lane", True), ("lane", 1.0),
    ("generation_id", "7"), ("generation_id", False),
    ("job_id", 1), ("vm_instance_id", ""),
    ("execution_harness_id", "A" * 64), ("extra_guest_claim", "ignored?"),
])
def test_correlation_models_are_strict(correlation, field, value):
    with pytest.raises(ValidationError):
        ExecutionCorrelation.model_validate({**correlation.model_dump(), field: value})


@pytest.mark.parametrize("field,value", [
    ("job_id", "other-job"), ("task_id", "other-task"),
    ("execution_harness_id", "b" * 64), ("vm_instance_id", "other-vm"),
    ("lane", 2), ("generation_id", 8),
])
def test_reported_correlation_conflict_not_rewritten(
        store, artifacts, metadata, correlation, field, value):
    reported = ExecutionCorrelation.model_validate(
        {**correlation.model_dump(), field: value})
    conflicting = ArtifactInput(identity="coverage", type="remote_kcov", data=b"bytes",
                                reported_correlation=reported)
    with pytest.raises(EvidenceSealingError, match="reported correlation conflicts"):
        store.seal((conflicting,), correlation=correlation, **metadata)
    assert list(store.artifacts.root.iterdir()) == []
    sealed = store.seal(artifacts, correlation=correlation, **metadata)
    ref = change_manifest(store, sealed, lambda value: value["artifacts"][0].update(
        reported_correlation=reported.model_dump(mode="json")))
    with pytest.raises(EvidenceVerificationError, match="reported correlation conflicts"):
        store.verify(ref, expected_correlation=correlation)


def test_matching_reported_correlation_is_retained(store, correlation, metadata):
    item = ArtifactInput(identity="coverage", type="remote_kcov", data=b"bytes",
                         reported_correlation=correlation)
    ref = store.seal((item,), correlation=correlation, **metadata)
    bundle = store.verify(ref, expected_correlation=correlation)
    assert bundle.manifest.artifacts[0].reported_correlation == correlation


def test_duplicate_identity_rejected_at_seal_and_verify(
        store, artifacts, sealed, correlation, metadata):
    with pytest.raises(EvidenceSealingError, match="duplicate artifact identity"):
        store.seal((artifacts[0], artifacts[0]), correlation=correlation, **metadata)
    ref = change_manifest(store, sealed, lambda value: value["artifacts"].append(
        value["artifacts"][0]))
    with pytest.raises(EvidenceVerificationError, match="duplicate artifact identity"):
        store.verify(ref, expected_correlation=correlation)


def test_distinct_identities_can_share_bytes(store, correlation, metadata):
    items = tuple(ArtifactInput(identity=name, type="log", data=b"same")
                  for name in ("first", "second"))
    ref = store.seal(items, correlation=correlation, **metadata)
    bundle = store.verify(ref, expected_correlation=correlation)
    assert bundle.manifest.artifacts[0].sha256 == bundle.manifest.artifacts[1].sha256


@pytest.mark.parametrize("mutation", [
    lambda v: v["artifacts"][0].update(size=1),
    lambda v: v["artifacts"][0].update(size=999),
    lambda v: v["artifacts"][0].update(sha256="f" * 64),
    lambda v: v["artifacts"][0].update(sha256="../../outside"),
    lambda v: v["artifacts"][0].update(size="10"),
    lambda v: v["artifacts"][0].update(size=True),
    lambda v: v["artifacts"][0].update(size=-1),
    lambda v: v["artifacts"][0].update(type=123),
    lambda v: v["artifacts"][0].update(type=""),
    lambda v: v["artifacts"][0].update(identity=""),
    lambda v: v["artifacts"][0].update(extra="ignored?"),
    lambda v: v.update(extra="ignored?"),
    lambda v: v.update(schema_version=True),
    lambda v: v.update(schema_version=1.0),
    lambda v: v.update(schema_version="1"),
    lambda v: v.update(schema_version=2),
    lambda v: v.update(artifacts=[]),
    lambda v: v["collection"].update(completed_at_ns=1),
    lambda v: v["collection"].update(started_at_ns=True),
    lambda v: v["sealing"].update(sealed_at_ns=1),
    lambda v: v["correlation"].update(lane="1"),
    lambda v: v["correlation"].pop("task_id"),
])
def test_malformed_or_inconsistent_manifest_rejected(
        store, sealed, correlation, mutation):
    ref = change_manifest(store, sealed, mutation)
    with pytest.raises(EvidenceVerificationError):
        store.verify(ref, expected_correlation=correlation)


def test_missing_referenced_bytes_cannot_pass(store, sealed, correlation, tmp_path):
    other = EvidenceStore(ArtifactStore(tmp_path / "manifest-only"))
    ref = other.artifacts.put(store.artifacts.get(sealed))
    assert ref == sealed
    with pytest.raises(EvidenceVerificationError):
        other.verify(ref, expected_correlation=correlation)


@pytest.mark.parametrize("replacement", [b"", b"truncated", b"\x00\xffcoveragh"])
def test_referenced_hash_or_truncation_rejected(store, sealed, correlation, replacement):
    manifest = load_record(store.artifacts, sealed, EvidenceManifest)
    store.artifacts._path(manifest.artifacts[0].sha256).write_bytes(replacement)
    with pytest.raises(EvidenceVerificationError):
        store.verify(sealed, expected_correlation=correlation)


def test_missing_or_changed_manifest_rejected(store, sealed, correlation):
    with pytest.raises(EvidenceVerificationError):
        store.verify("f" * 64, expected_correlation=correlation)
    with pytest.raises(EvidenceVerificationError):
        store.verify("../outside", expected_correlation=correlation)
    store.artifacts._path(sealed).write_bytes(b"{}")
    with pytest.raises(EvidenceVerificationError):
        store.verify(sealed, expected_correlation=correlation)


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b"null", b"\xff", b'{"schema_version":1,"schema_version":1}',
    b'{"nested":{"a":1,"a":2}}', b'{"x":NaN}', b'{"x":Infinity}',
    b'{"x":1e999}', b"[" * 2000 + b"]" * 2000,
])
def test_bad_json_fails_with_public_verification_error(store, correlation, raw):
    ref = store.artifacts.put(raw)
    with pytest.raises(EvidenceVerificationError):
        store.verify(ref, expected_correlation=correlation)


def test_noncanonical_manifest_rejected(store, sealed, correlation):
    raw = store.artifacts.get(sealed)
    ref = store.artifacts.put(raw + b"\n")
    with pytest.raises(EvidenceVerificationError, match="canonical"):
        store.verify(ref, expected_correlation=correlation)


def test_missing_default_fields_are_not_canonical(store, sealed, correlation):
    ref = change_manifest(store, sealed, lambda value: value.pop("schema_version"))
    with pytest.raises(EvidenceVerificationError, match="canonical"):
        store.verify(ref, expected_correlation=correlation)


def test_expected_type_and_required_artifact_checks(store, sealed, correlation):
    with pytest.raises(EvidenceVerificationError, match="type mismatch"):
        store.verify(sealed, expected_correlation=correlation,
                     expected_types={"coverage": "local_kcov"})
    with pytest.raises(EvidenceVerificationError, match="missing required artifact"):
        store.verify(sealed, expected_correlation=correlation,
                     expected_types={"journal": "journal"})
    bundle = store.verify(sealed, expected_correlation=correlation)
    with pytest.raises(EvidenceVerificationError, match="type mismatch"):
        bundle.get("coverage", expected_type="local_kcov")
    with pytest.raises(EvidenceVerificationError, match="missing required artifact"):
        bundle.get("missing", expected_type="remote_kcov")


def test_forged_type_rejected_against_trusted_expectation(store, sealed, correlation):
    ref = change_manifest(store, sealed, lambda value: value["artifacts"][0].update(
        type="local_kcov"))
    with pytest.raises(EvidenceVerificationError, match="type mismatch"):
        store.verify(ref, expected_correlation=correlation,
                     expected_types={"coverage": "remote_kcov"})


@pytest.mark.parametrize("limits", [
    EvidenceLimits(max_manifest_bytes=1), EvidenceLimits(max_artifacts=1),
    EvidenceLimits(max_artifact_bytes=1), EvidenceLimits(max_bundle_bytes=1),
])
def test_limits_apply_to_seal_and_verify(
        store, sealed, artifacts, correlation, metadata, limits):
    limited = EvidenceStore(store.artifacts, limits=limits)
    with pytest.raises(EvidenceSealingError, match="limit"):
        limited.seal(artifacts, correlation=correlation, **metadata)
    with pytest.raises(EvidenceVerificationError, match="limit"):
        limited.verify(sealed, expected_correlation=correlation)


def test_exact_limits_pass(store, sealed, artifacts, correlation, metadata):
    limits = EvidenceLimits(max_manifest_bytes=len(store.artifacts.get(sealed)),
                            max_artifacts=len(artifacts),
                            max_artifact_bytes=max(len(a.data) for a in artifacts),
                            max_bundle_bytes=sum(len(a.data) for a in artifacts))
    exact = EvidenceStore(store.artifacts, limits=limits)
    assert exact.seal(artifacts, correlation=correlation, **metadata) == sealed
    assert exact.verify(sealed, expected_correlation=correlation).manifest_sha256 == sealed


def test_manifest_read_is_bounded_before_parsing(store, correlation, monkeypatch):
    limits = EvidenceLimits(max_manifest_bytes=8)
    limited = EvidenceStore(store.artifacts, limits=limits)
    ref = store.artifacts.put(b" " * 9)

    def no_parse(data):
        pytest.fail("oversized manifest must be rejected before parsing")

    monkeypatch.setattr("agent_pipeline.evidence.parse_json", no_parse)
    with pytest.raises(EvidenceVerificationError, match="byte limit"):
        limited.verify(ref, expected_correlation=correlation)


def test_artifact_count_and_total_limits_checked_before_artifact_reads(
        store, sealed, correlation, monkeypatch):
    original_get = store.artifacts.get
    reads = []

    def get(ref, **kwargs):
        reads.append(ref)
        return original_get(ref, **kwargs)

    monkeypatch.setattr(store.artifacts, "get", get)
    for limits in (EvidenceLimits(max_bundle_bytes=1), EvidenceLimits(max_artifacts=1)):
        reads.clear()
        with pytest.raises(EvidenceVerificationError):
            EvidenceStore(store.artifacts, limits=limits).verify(
                sealed, expected_correlation=correlation)
        assert reads == [sealed]


def test_seal_validates_before_storing_any_bytes(store, artifacts, correlation, metadata):
    limited = EvidenceStore(store.artifacts, limits=EvidenceLimits(max_manifest_bytes=1))
    with pytest.raises(EvidenceSealingError):
        limited.seal(artifacts, correlation=correlation, **metadata)
    assert list(store.artifacts.root.iterdir()) == []


def test_corrupt_existing_bytes_prevent_seal(store, artifacts, correlation, metadata):
    ref = store.artifacts.put(artifacts[0].data)
    store.artifacts._path(ref).write_bytes(b"corrupt")
    with pytest.raises(EvidenceSealingError):
        store.seal(artifacts, correlation=correlation, **metadata)


def test_invalid_constructed_models_are_revalidated(store, correlation, metadata):
    forged = ArtifactInput.model_construct(identity="bad", type="log", data="not bytes")
    with pytest.raises(EvidenceSealingError):
        store.seal((forged,), correlation=correlation, **metadata)


def test_empty_bundle_rejected_but_empty_artifact_allowed(store, correlation, metadata):
    with pytest.raises(EvidenceSealingError):
        store.seal((), correlation=correlation, **metadata)
    ref = store.seal((ArtifactInput(identity="coverage", type="remote_kcov", data=b""),),
                     correlation=correlation, **metadata)
    assert store.verify(ref, expected_correlation=correlation).get(
        "coverage", expected_type="remote_kcov") == b""


def test_payload_semantics_are_explicitly_outside_storage_validation(
        store, correlation, metadata):
    # No claim that this is valid JSON or that Q1 is reached: the Judge parses it.
    ref = store.seal((ArtifactInput(identity="status", type="application/json",
                                    data=b"opaque, not JSON"),),
                     correlation=correlation, **metadata)
    assert store.verify(ref, expected_correlation=correlation).get(
        "status", expected_type="application/json") == b"opaque, not JSON"


def test_manifest_hash_alone_is_not_host_authentication(store, correlation, metadata):
    # Anyone who can write the store can reproduce host-looking metadata. This
    # component requires a trusted caller/storage boundary, not a signature.
    raw = b"untrusted bytes"
    ref = store.artifacts.put(raw)
    forged = EvidenceManifest(
        correlation=correlation, artifacts=(EvidenceArtifact(
            identity="coverage", type="remote_kcov", sha256=ref, size=len(raw)),),
        **metadata,
    )
    manifest_ref = store.artifacts.put(canonical_json(forged))
    bundle = store.verify(manifest_ref, expected_correlation=correlation)
    assert bundle.get("coverage", expected_type="remote_kcov") == raw
