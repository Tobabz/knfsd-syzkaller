"""Artifact-backed Q2 tests with synthetic reports and trusted host receipts."""

from __future__ import annotations

from hashlib import sha256
from types import SimpleNamespace

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.evidence import (ArtifactInput, CollectionMetadata,
                                     EvidenceStore, ExecutionCorrelation,
                                     SealingMetadata)
from agent_pipeline.q2 import (CandidateAssociation, Q2CollectionWindow,
                               Q2JudgeProfile, Q2Status, default_q2_profile)
from agent_pipeline.sealed_q2 import (
    CONSOLE_LOG_TYPE,
    MANAGER_REPORT_TYPE,
    Q2_EVIDENCE_ID,
    Q2_EVIDENCE_TYPE,
    ArtifactQ2Judge,
    Q2EvidenceUnavailable,
    SealedArtifactRef,
    SealedQ2Evidence,
    TrustedQ2Execution,
    UnknownQ2Execution,
)


def digest_bytes(data: bytes) -> str:
    return sha256(data).hexdigest()


def setup(tmp_path, *, reports=(), completeness="complete",
          vm_termination="runner_stopped", window=None,
          console=b"complete console\n", observation_update=None,
          receipt_update=None, manifest_correlation=None):
    store = ArtifactStore(tmp_path / "artifacts")
    evidence = EvidenceStore(store)
    harness_id = digest_bytes(b"execution-harness")
    correlation = ExecutionCorrelation(
        job_id="job-1",
        task_id="task-1",
        execution_harness_id=harness_id,
        vm_instance_id="vm-1",
        lane=2,
        generation_id=7,
    )
    window = window or Q2CollectionWindow(start_marker="start", end_marker="end")
    console_identity = None if completeness == "missing" else "console"
    console_ref = None if console_identity is None else digest_bytes(console)
    report_items = tuple((f"report-{index}", value)
                         for index, value in enumerate(reports))
    report_refs = tuple(SealedArtifactRef(identity=identity,
                                          sha256=digest_bytes(data))
                        for identity, data in report_items)
    observation = SealedQ2Evidence(
        execution_harness_id=harness_id,
        correlation=correlation,
        console_log_identity=console_identity,
        console_log_ref=console_ref,
        console_log_completeness=completeness,
        manager_crash_reports=report_refs,
        vm_termination=vm_termination,
        collection_window=window,
        candidate_association=CandidateAssociation(
            candidate_id="candidate-1", symbol="nfsd4_open", symbol_present=False),
    )
    if observation_update:
        observation = observation.model_copy(update=observation_update)
    artifacts = [ArtifactInput(
        identity=Q2_EVIDENCE_ID,
        type=Q2_EVIDENCE_TYPE,
        data=canonical_json(observation),
        reported_correlation=manifest_correlation or correlation,
    )]
    if console_identity is not None:
        artifacts.append(ArtifactInput(identity=console_identity,
                                       type=CONSOLE_LOG_TYPE, data=console))
    artifacts.extend(ArtifactInput(identity=identity, type=MANAGER_REPORT_TYPE,
                                   data=data)
                     for identity, data in report_items)
    bundle_ref = evidence.seal(
        artifacts,
        correlation=manifest_correlation or correlation,
        collection=CollectionMetadata(collector_id="host-collector",
                                      started_at_ns=10, completed_at_ns=20),
        sealing=SealingMetadata(sealer_id="host-sealer", sealed_at_ns=21),
    )
    receipt = TrustedQ2Execution(
        bundle_ref=bundle_ref,
        execution_harness_id=harness_id,
        correlation=correlation,
        console_log_identity=console_identity,
        console_log_completeness=completeness,
        manager_crash_report_identities=tuple(item[0] for item in report_items),
        vm_termination=vm_termination,
        collection_window=window,
    )
    if receipt_update:
        receipt = receipt.model_copy(update=receipt_update)
    profile = default_q2_profile()
    profile_ref = put_record(store, profile)
    judge = ArtifactQ2Judge(store, receipts={bundle_ref: receipt}, evidence=evidence)
    return SimpleNamespace(**locals())


def reseal(f, artifacts, *, correlation=None, receipt_update=None):
    bundle_ref = f.evidence.seal(
        artifacts,
        correlation=correlation or f.correlation,
        collection=CollectionMetadata(collector_id="host-collector",
                                      started_at_ns=10, completed_at_ns=20),
        sealing=SealingMetadata(sealer_id="host-sealer", sealed_at_ns=21),
    )
    updates = {"bundle_ref": bundle_ref}
    if receipt_update:
        updates.update(receipt_update)
    receipt = f.receipt.model_copy(update=updates)
    f.bundle_ref = bundle_ref
    f.receipt = receipt
    f.judge = ArtifactQ2Judge(f.store, receipts={bundle_ref: receipt}, evidence=f.evidence)


def test_sealed_valid_report_is_observed_without_candidate_symbol(tmp_path):
    f = setup(tmp_path, reports=(
        b"BUG: KASAN: slab-use-after-free in unrelated_worker\n"
        b"Write of size 8 at addr ffff0000\n",
    ))
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.OBSERVED
    assert result.signals[0].signal_class == "KASAN"
    assert result.candidate_association.symbol_present is False
    assert result == f.judge.judge(f.bundle_ref, f.profile_ref)
    assert f.judge.matches_execution(f.bundle_ref, job_id="job-1", task_id="task-1")


def test_sealed_complete_no_report_is_not_observed(tmp_path):
    f = setup(tmp_path)
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.NOT_OBSERVED
    assert result.signals == ()


@pytest.mark.parametrize(("completeness", "window", "reason"), [
    ("truncated", Q2CollectionWindow(start_marker="start", end_marker="end"),
     "console_log_truncated"),
    ("missing", Q2CollectionWindow(start_marker="start", end_marker="end"),
     "console_log_missing"),
    ("complete", Q2CollectionWindow(start_marker="start"),
     "collection_window_open"),
])
def test_host_recorded_incomplete_collection_is_inconclusive(
        tmp_path, completeness, window, reason):
    f = setup(tmp_path, completeness=completeness, window=window)
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == reason


@pytest.mark.parametrize("authority_update", [
    {"console_log_completeness": "truncated"},
    {"collection_window": Q2CollectionWindow(start_marker="start")},
    {"execution_harness_id": "f" * 64},
])
def test_sealed_claims_cannot_override_host_identity_or_completeness(
        tmp_path, authority_update):
    # The sealed observation still claims the default complete/closed identity.
    f = setup(tmp_path, receipt_update=authority_update)
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


def test_manifest_correlation_conflict_is_invalid_evidence(tmp_path):
    f = setup(tmp_path)
    other = f.correlation.model_copy(update={"task_id": "other-task"})
    receipt = f.receipt.model_copy(update={"correlation": other})
    judge = ArtifactQ2Judge(f.store, receipts={f.bundle_ref: receipt})
    result = judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


@pytest.mark.parametrize("target", ["manifest", "console", "report"])
def test_hash_corruption_is_invalid_evidence(tmp_path, target):
    f = setup(tmp_path, reports=(b"WARNING: recoverable report\n",))
    if target == "manifest":
        ref = f.bundle_ref
    elif target == "console":
        ref = f.console_ref
    else:
        ref = f.report_refs[0].sha256
    f.store._path(ref).write_bytes(b"corrupt")
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


@pytest.mark.parametrize("malformed", [
    b"{",
    b"[]",
    b'{"schema_version":"sealed-q2-evidence-v1"}',
    b'{"schema_version":"sealed-q2-evidence-v1","schema_version":"x"}',
])
def test_malformed_q2_index_is_invalid_evidence(tmp_path, malformed):
    f = setup(tmp_path)
    artifacts = [
        ArtifactInput(identity=Q2_EVIDENCE_ID, type=Q2_EVIDENCE_TYPE,
                      data=malformed, reported_correlation=f.correlation),
        ArtifactInput(identity="console", type=CONSOLE_LOG_TYPE, data=f.console),
    ]
    reseal(f, artifacts)
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


def test_non_utf8_manager_report_is_invalid_evidence(tmp_path):
    f = setup(tmp_path, reports=(b"\xff\xfe\x00",))
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


def test_unlisted_or_omitted_report_cannot_change_the_oracle(tmp_path):
    f = setup(tmp_path, reports=(b"WARNING: report\n",))
    receipt = f.receipt.model_copy(update={"manager_crash_report_identities": ()})
    judge = ArtifactQ2Judge(f.store, receipts={f.bundle_ref: receipt})
    result = judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


def test_report_reference_must_match_sealed_bytes(tmp_path):
    f = setup(tmp_path, reports=(b"WARNING: report\n",),
              observation_update={"manager_crash_reports": (
                  SealedArtifactRef(identity="report-0", sha256="0" * 64),)})
    result = f.judge.judge(f.bundle_ref, f.profile_ref)
    assert result.status is Q2Status.INCONCLUSIVE
    assert result.reason == "invalid_evidence"


def test_missing_receipt_or_transient_io_produces_no_verdict(tmp_path, monkeypatch):
    f = setup(tmp_path)
    empty = ArtifactQ2Judge(f.store, receipts={})
    with pytest.raises(UnknownQ2Execution):
        empty.judge(f.bundle_ref, f.profile_ref)

    def unavailable(*args, **kwargs):
        raise OSError("temporary storage outage")

    monkeypatch.setattr(f.judge.evidence, "verify", unavailable)
    with pytest.raises(Q2EvidenceUnavailable, match="unavailable"):
        f.judge.judge(f.bundle_ref, f.profile_ref)


def test_missing_referenced_artifact_is_retryable(tmp_path):
    f = setup(tmp_path, reports=(b"WARNING: report\n",))
    f.store._path(f.report_refs[0].sha256).unlink()
    with pytest.raises(Q2EvidenceUnavailable):
        f.judge.judge(f.bundle_ref, f.profile_ref)


def test_profile_change_rejudges_same_bundle_without_mutation(tmp_path):
    f = setup(tmp_path, reports=(b"WARNING: recoverable report\n",))
    old = f.judge.assess(f.bundle_ref, f.profile_ref)
    old_manifest = f.store.get(f.bundle_ref)

    profile_data = f.profile.model_dump()
    profile_data.update(
        revision="2",
        parse_rules=tuple(
            {**rule, "pattern": "NEVER-MATCH-CHANGED-PROFILE"}
            if rule["rule_id"] == "warning" else rule
            for rule in profile_data["parse_rules"]
        ),
    )
    new_profile = Q2JudgeProfile.model_validate(profile_data)
    new_profile_ref = put_record(f.store, new_profile)
    new = f.judge.assess(f.bundle_ref, new_profile_ref)

    assert old.status is Q2Status.OBSERVED
    assert new.status is Q2Status.INCONCLUSIVE
    assert old.evidence_manifest_sha256 == new.evidence_manifest_sha256 == f.bundle_ref
    assert old.judge_profile_id != new.judge_profile_id
    assert old.verdict_id != new.verdict_id
    assert f.judge.assess(f.bundle_ref, f.profile_ref) == old
    assert f.store.get(f.bundle_ref) == old_manifest


def test_receipt_registry_is_an_immutable_snapshot(tmp_path):
    f = setup(tmp_path)
    receipts = {f.bundle_ref: f.receipt}
    judge = ArtifactQ2Judge(f.store, receipts=receipts)
    receipts.clear()
    assert judge.judge(f.bundle_ref, f.profile_ref).status is Q2Status.NOT_OBSERVED
