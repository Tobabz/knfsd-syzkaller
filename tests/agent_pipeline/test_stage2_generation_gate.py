"""The candidate-independent generation gate of the Stage 2 judge."""

from types import SimpleNamespace

import pytest

from agent_pipeline.data import canonical_json
from agent_pipeline.journal_sink import (
    Closure, Correlation, GenerationCompletePayload, RecordContext,
)
from agent_pipeline.q1 import ExecutionCorrelation
from agent_pipeline.sealed_q1 import PublishedCoverage
from agent_pipeline.semantic_delta import (
    ApplicationDelta, CompoundReplyDelta, ExposureDelta, GenerationDelta,
    ProtocolOperationDelta,
)
from agent_pipeline.stage2.evidence import (
    GENERATION_COVERAGE_PREFIX, GENERATION_COVERAGE_TYPE,
    GENERATION_EXECUTION_PREFIX, GENERATION_EXECUTION_TYPE,
    GenerationExecution,
)
from agent_pipeline.stage2.judge import ArtifactStage2Judge

PROGRAM = "7" * 64
DIGEST = "5" * 64
PATH = "nfs4.request.EXCHANGE_ID.args.eia_clientowner.co_ownerid"


def _correlation():
    return ExecutionCorrelation(
        job_id="job", task_id="task", execution_harness_id="e" * 64,
        vm_instance_id="vm", lane=0, generation_id=7)


def _attestation(**changes):
    values = dict(
        correlation=_correlation(), execution_id=11,
        program_sha256=PROGRAM, program_digest=DIGEST,
        activation="Acked", activation_status=0,
        deactivation="Acked", deactivation_status=0,
        executed=True, lease_cleared=True)
    values.update(changes)
    return GenerationExecution(**values)


def _context(direction, message_type):
    return RecordContext(
        backend=0, client=0, connection_id=1, direction=direction,
        message_type=message_type, procedure=1, program=100003, version=4,
        xid=9)


def _generation(*, statuses=None, mutation=True, complete=True):
    corr = Correlation(kcov_generation=7, lane_id=0, program_digest=DIGEST,
                       rule_set_id="a" * 64)
    generation = GenerationDelta(7, 0, DIGEST, 1, draining_seq=8)
    if mutation:
        generation.exposures.append(ExposureDelta(
            batch_id=0, event_seq=2, message_type="call", signature=(),
            terminal="complete", terminal_seq=3,
            applications=(ApplicationDelta(
                rule_id="r000", semantic_path=PATH, kind="replace",
                part="value", original_value="00" * 16,
                mutated_value="61"),),
            record_context=_context("c2s", "call")))
    statuses = statuses or {42: 0, 43: 0, 53: 0, 58: 0}
    generation.protocol_replies.append(CompoundReplyDelta(
        event_seq=4, minor_version=1,
        record_context=_context("s2c", "reply"),
        operations=tuple(ProtocolOperationDelta(
            index=index, name=f"OP_{opcode}", opcode=opcode, status=status)
            for index, (opcode, status) in enumerate(statuses.items()))))
    if complete:
        generation.summary = GenerationCompletePayload(
            closure=Closure(drain_bound_ms=5000, reason="drained",
                            reply_unresolved_count=0),
            correlation=corr, evidence_path_failures=0,
            exposure_batch_count=1 if mutation else 0,
            outside_activation_window=0, records_seen=7,
            resolver_summary=[])
        generation.summary_seq = 9
    return generation


def _execution(candidate="VC-1"):
    return SimpleNamespace(
        candidate=SimpleNamespace(candidate_id=candidate),
        program_ref=PROGRAM)


def _session(**changes):
    values = dict(rejections=0, inconsistent=())
    values.update(changes)
    return SimpleNamespace(**values)


def _artifact(identity, type_, value):
    return SimpleNamespace(
        descriptor=SimpleNamespace(identity=identity, type=type_),
        data=canonical_json(value),
    )


def _generation_evidence(*, coverage=True, execution=True,
                         correlation=None, second=False, reused_id=False):
    corr = correlation or _correlation()
    artifacts = []
    if coverage:
        artifacts.append(_artifact(
            f"{GENERATION_COVERAGE_PREFIX}0.7",
            GENERATION_COVERAGE_TYPE,
            PublishedCoverage(correlation=corr, pcs=(1,)),
        ))
    if execution:
        artifacts.append(_artifact(
            f"{GENERATION_EXECUTION_PREFIX}0.7",
            GENERATION_EXECUTION_TYPE,
            _attestation(correlation=corr),
        ))
    if second:
        corr2 = corr.model_copy(update={"generation_id": 8})
        artifacts.extend((
            _artifact(
                f"{GENERATION_COVERAGE_PREFIX}0.8",
                GENERATION_COVERAGE_TYPE,
                PublishedCoverage(correlation=corr2, pcs=(1,)),
            ),
            _artifact(
                f"{GENERATION_EXECUTION_PREFIX}0.8",
                GENERATION_EXECUTION_TYPE,
                _attestation(
                    correlation=corr2, execution_id=11 if reused_id else 12),
            ),
        ))
    return SimpleNamespace(bundle=SimpleNamespace(artifacts=artifacts))


def test_exact_program_and_established_session_pass():
    generation = _generation()
    attestation = _attestation()
    assert ArtifactStage2Judge._execution_valid(attestation, generation)
    assert ArtifactStage2Judge._generation_sound(
        _execution(), _session(), generation, attestation)


@pytest.mark.parametrize("statuses", [
    {42: 0, 43: 1, 53: 0, 58: 0},
    {42: 0, 43: 0, 53: 0, 58: 10054},
])
def test_failed_session_operation_refuses_generation(statuses):
    assert not ArtifactStage2Judge._generation_sound(
        _execution(), _session(), _generation(statuses=statuses),
        _attestation())


def test_other_operation_failures_do_not_refuse_generation():
    """A mutated request may legitimately be refused by the server."""
    assert ArtifactStage2Judge._generation_sound(
        _execution(), _session(),
        _generation(statuses={42: 0, 43: 0, 53: 0, 58: 0, 25: 22}),
        _attestation())


def test_mutation_outcome_is_not_decided_by_the_gate():
    """Whether a rule applied is M1's verdict, for every candidate."""
    for candidate in ("VC-1", "VC-2"):
        assert ArtifactStage2Judge._valid_generation(
            _execution(candidate), _session(), _generation(mutation=False),
            _attestation())


def test_changed_program_or_dirty_session_refuses_generation():
    assert not ArtifactStage2Judge._generation_sound(
        _execution(), _session(), _generation(),
        _attestation(program_sha256="8" * 64))
    assert not ArtifactStage2Judge._generation_sound(
        _execution(), _session(rejections=1), _generation(), _attestation())


def test_digest_mismatch_or_incomplete_generation_refuses_execution():
    assert not ArtifactStage2Judge._execution_valid(
        _attestation(program_digest="6" * 64), _generation())
    generation = _generation(complete=False)
    assert ArtifactStage2Judge._execution_valid(_attestation(), generation)
    assert not ArtifactStage2Judge._generation_sound(
        _execution(), _session(), generation, _attestation())


@pytest.mark.parametrize(("coverage", "execution"), [
    (True, False),
    (False, True),
])
def test_generation_coverage_and_execution_must_be_one_to_one(
        coverage, execution):
    with pytest.raises(ValueError, match="generations differ"):
        ArtifactStage2Judge._generation_artifacts(
            ArtifactStage2Judge.__new__(ArtifactStage2Judge),
            SimpleNamespace(correlation=_correlation()),
            _generation_evidence(coverage=coverage, execution=execution),
        )


def test_generation_artifact_key_must_match_payload_correlation():
    wrong = _correlation().model_copy(update={"generation_id": 8})
    with pytest.raises(ValueError, match="correlation mismatch"):
        ArtifactStage2Judge._generation_artifacts(
            ArtifactStage2Judge.__new__(ArtifactStage2Judge),
            SimpleNamespace(correlation=_correlation()),
            _generation_evidence(correlation=wrong),
        )


def test_generation_execution_id_cannot_be_reused():
    with pytest.raises(ValueError, match="execution ID is reused"):
        ArtifactStage2Judge._generation_artifacts(
            ArtifactStage2Judge.__new__(ArtifactStage2Judge),
            SimpleNamespace(correlation=_correlation()),
            _generation_evidence(second=True, reused_id=True),
        )
