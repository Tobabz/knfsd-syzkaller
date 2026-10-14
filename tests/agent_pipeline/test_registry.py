import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import HarnessBinding, Sanitizer
from agent_pipeline.data import put_record
from agent_pipeline.hcap import AuthorityRef, HcapCatalog
from agent_pipeline.registry import (ArtifactHarnessRegistry, HarnessCatalog,
                                     HarnessRegistration)


def registration(store, *, commit="a" * 40, sanitizer=Sanitizer.KASAN):
    # A synthetic host approval, not evidence of a validated real kernel.
    hcap_ref = put_record(store, HcapCatalog(capabilities=(), missing_capability_ids=()))
    evidence_ref = store.put(b"synthetic-host-approval-evidence")
    return HarnessRegistration(
        binding=HarnessBinding(kernel_commit=commit, sanitizer=sanitizer,
                               execution_harness_id="b" * 64,
                               hcap_revision=hcap_ref),
        evidence_refs=(evidence_ref,))


def test_registry_selects_exact_commit_and_sanitizer(tmp_path):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    b = registration(store, sanitizer=Sanitizer.KCSAN)
    ref = put_record(store, HarnessCatalog(registrations=(a, b)))
    registry = ArtifactHarnessRegistry(store, ref)
    assert registry.lookup("a" * 40, Sanitizer.KASAN) == a.binding
    assert registry.lookup("a" * 40, Sanitizer.KCSAN) == b.binding
    assert registry.lookup("c" * 40, Sanitizer.KASAN) is None
    assert registry.lookup("main", Sanitizer.KASAN) is None


def test_duplicate_binding_is_not_a_last_writer_wins_registry(tmp_path):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    with pytest.raises(ValueError):
        HarnessCatalog(registrations=(a, a))


@pytest.mark.parametrize("which", ["catalog", "hcap", "evidence"])
def test_missing_artifact_has_no_binding(tmp_path, which):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    ref = put_record(store, HarnessCatalog(registrations=(a,)))
    target = {"catalog": ref, "hcap": a.binding.hcap_revision,
              "evidence": a.evidence_refs[0]}[which]
    (store.root / target[:2] / target).unlink()
    assert ArtifactHarnessRegistry(store, ref).lookup(
        "a" * 40, Sanitizer.KASAN) is None


@pytest.mark.parametrize("which", ["catalog", "hcap", "evidence"])
def test_corrupt_artifact_has_no_binding(tmp_path, which):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    ref = put_record(store, HarnessCatalog(registrations=(a,)))
    target = {"catalog": ref, "hcap": a.binding.hcap_revision,
              "evidence": a.evidence_refs[0]}[which]
    (store.root / target[:2] / target).write_bytes(b"corrupt")
    assert ArtifactHarnessRegistry(store, ref).lookup(
        "a" * 40, Sanitizer.KASAN) is None


def test_catalog_change_is_explicit(tmp_path):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    old_ref = put_record(store, HarnessCatalog(registrations=(a,)))
    new_ref = put_record(store, HarnessCatalog(registrations=()))
    old = ArtifactHarnessRegistry(store, old_ref)
    new = ArtifactHarnessRegistry(store, new_ref)
    assert old.lookup("a" * 40, Sanitizer.KASAN) == a.binding
    assert new.lookup("a" * 40, Sanitizer.KASAN) is None


def test_unapproved_or_path_like_catalog_is_refused(tmp_path):
    store = ArtifactStore(tmp_path)
    assert ArtifactHarnessRegistry(store, "0" * 64).lookup(
        "a" * 40, Sanitizer.KASAN) is None
    assert ArtifactHarnessRegistry(store, "../outside").lookup(
        "a" * 40, Sanitizer.KASAN) is None


@pytest.mark.parametrize("payload", [b"opaque approval, not HCAP", b'{"unknown":true}'])
def test_hcap_digest_integrity_does_not_replace_schema_validation(tmp_path, payload):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    a = a.model_copy(update={"binding": a.binding.model_copy(update={
        "hcap_revision": store.put(payload)})})
    ref = put_record(store, HarnessCatalog(registrations=(a,)))
    assert ArtifactHarnessRegistry(store, ref).lookup(
        "a" * 40, Sanitizer.KASAN) is None


def test_hcap_with_missing_authority_has_no_binding(tmp_path):
    store = ArtifactStore(tmp_path)
    a = registration(store)
    hcap_ref = put_record(store, HcapCatalog(capabilities=(), missing_capability_ids=(),
        authority_refs=(AuthorityRef(kind="CallAdmissionProfile",
                                     artifact_ref="0" * 64),)))
    a = a.model_copy(update={"binding": a.binding.model_copy(update={
        "hcap_revision": hcap_ref})})
    ref = put_record(store, HarnessCatalog(registrations=(a,)))
    assert ArtifactHarnessRegistry(store, ref).lookup(
        "a" * 40, Sanitizer.KASAN) is None
