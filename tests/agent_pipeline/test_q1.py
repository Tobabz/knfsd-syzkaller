"""Decision-kernel tests only; these are not runtime/attribution validation."""

from __future__ import annotations

import json
from hashlib import sha256

import pytest
from pydantic import ValidationError

from agent_pipeline.contracts import GapClass, Q1Status
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.q1 import (
    CandidateTarget, ContextLossPolicy, CounterDelta, CounterLimit,
    ExecutionCorrelation, GenerationCounters, KernelIdentity, ObservationRequirement,
    Q1AdmissibilityProfile, Q1Decision, Q1Input, RemoteKcovObservation,
    RemoteKcovSupportBoundary, TargetPcMapping, evaluate,
)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def replace(record, **changes):
    """Revalidate updates; production callers must not trust model_copy updates."""
    return type(record).model_validate({**record.model_dump(), **changes})


@pytest.fixture
def sample() -> Q1Input:
    target = CandidateTarget(
        candidate_id="candidate-1", kernel_commit="a" * 40, kind="function",
        path="fs/nfsd/nfs4proc.c", symbol="nfsd4_open", start_line=100, end_line=180,
    )
    identity = KernelIdentity(
        execution_harness_id=digest("execution"), kernel_commit=target.kernel_commit,
        instrumentation_sha256=digest("patches"), vmlinux_sha256=digest("vmlinux"),
        kaslr_enabled=False, kaslr_offset=0,
    )
    correlation = ExecutionCorrelation(
        job_id="job-1", task_id="task-1", execution_harness_id=identity.execution_harness_id,
        vm_instance_id="vm-1", lane=0, generation_id=1,
    )
    profile = Q1AdmissibilityProfile(
        name="test-only", revision="1", allowed_trace_modes=("off",),
        contexts=(ContextLossPolicy(
            context="request", window="begin-through-late-sections",
            counters=(CounterLimit(counter="lane_owner_failed"),
                      CounterLimit(counter="new_root_rejected_closed"),
                      CounterLimit(counter="remote_grant_rejected_closed", max_delta=2)),
            normal_counters=("lane_owner_no_generation",),
        ),),
    )
    return Q1Input(
        candidate=target, plan_ref=digest("plan"), hcap_revision="hcap-1",
        requirement=ObservationRequirement(target=target, expected_context="request"),
        evidence_manifest_sha256=digest("manifest"), evidence_verified=True,
        expected_identity=identity, expected_correlation=correlation,
        profile=profile,
        boundary=RemoteKcovSupportBoundary(
            name="test-only", revision="1", kernel_commit=target.kernel_commit,
            instrumentation_sha256=identity.instrumentation_sha256,
            supported_contexts=("request", "async_copy", "callback_v41"),
        ),
        mapping=TargetPcMapping(
            mapping_method="externally-validated-fixture", verified=True,
            target=target, identity=identity, target_pcs=(0x1010, 0x1020),
        ),
        observation=RemoteKcovObservation(
            candidate_id=target.candidate_id, identity=identity, correlation=correlation,
            boot_ok=True, fixture_ok=True, lane_ok=True, runner_completed=True,
            collection_started=True, collection_completed=True, generation_attributed=True,
            channel="remote_kcov", lane_trace_mode="off",
            coverage_artifacts=(digest("coverage"),), published_pcs=(0x1010, 0x2000),
            generation=GenerationCounters(
                generation_begin=1, remote_start_ok=3, aggregate_published=1,
                generation_aborted=0, scratch_overflow=0, merge_truncation=0,
                outstanding_tokens=0, remote_refs=0,
            ),
            counter_deltas=tuple(CounterDelta(
                counter=counter.counter, window=profile.contexts[0].window, value=0,
            ) for counter in profile.contexts[0].counters),
        ),
    )


def observe(sample, **changes):
    return replace(sample, observation=replace(sample.observation, **changes))


def count(sample, **changes):
    return observe(sample, generation=replace(sample.observation.generation, **changes))


def miss(sample):
    return observe(sample, published_pcs=(0x2000,))


def expect_unknown(sample, reason, diagnostic=None):
    result = evaluate(sample)
    assert result.status is Q1Status.INCONCLUSIVE
    assert result.reason == reason
    assert result.matched_pcs == ()
    if diagnostic is not None:
        assert result.observations == (diagnostic,)
    if reason != "unsupported_attribution":
        assert result.gap_signal is None
    return result


def test_hit_is_pc_intersection_and_controller_result(sample):
    result = evaluate(sample)
    assert result.status is Q1Status.REACHED
    assert result.reason is None
    assert result.target_observed is True
    assert result.execution_valid is True
    assert result.matched_pcs == (0x1010,)
    assert result.gap_signal is None
    assert result.as_result().model_dump() == {
        key: result.model_dump()[key]
        for key in type(result.as_result()).model_fields
    }


@pytest.mark.parametrize("pcs", [(), (0x2000,), (0x1011, 0x1021)])
def test_only_admissible_miss_is_not_reached(sample, pcs):
    result = evaluate(observe(sample, published_pcs=pcs))
    assert result.status is Q1Status.NOT_REACHED
    assert result.target_observed is False
    assert result.execution_valid is True
    assert result.reason is None


@pytest.mark.parametrize("guest_claim", [True, False, None])
@pytest.mark.parametrize("hit", [True, False])
def test_guest_boolean_never_decides_reachability(sample, guest_claim, hit):
    data = sample if hit else miss(sample)
    result = evaluate(observe(data, guest_target_observed=guest_claim))
    assert result.status is (Q1Status.REACHED if hit else Q1Status.NOT_REACHED)


@pytest.mark.parametrize("change,reason", [
    ({"boot_ok": False}, "infra"),
    ({"fixture_ok": False}, "infra"),
    ({"lane_ok": False}, "infra"),
    ({"runner_completed": False}, "infra"),
    ({"runtime_errors": ("runner exited",)}, "infra"),
    ({"collection_started": False}, "evidence"),
    ({"collection_completed": False}, "evidence"),
    ({"generation_attributed": False}, "evidence"),
    ({"coverage_artifacts": ()}, "evidence"),
    ({"published_pcs": None}, "evidence"),
    ({"correlation": None}, "evidence"),
    ({"lane_trace_mode": None}, "evidence"),
    ({"lane_trace_mode": "other-mode"}, "evidence"),
    ({"internal_errors": ("sequence gap",)}, "evidence"),
    ({"candidate_id": "another-candidate"}, "evidence"),
])
def test_invalid_observation_blocks_hit_before_mapping(sample, change, reason):
    expect_unknown(observe(replace(sample, mapping=None), **change), reason)


def test_unverified_manifest_precedes_everything(sample):
    expect_unknown(replace(sample, evidence_verified=False, mapping=None), "evidence")


@pytest.mark.parametrize("channel", [
    "KCOV_NFSD_OBSERVE", "local_kcov", "tracepoint", "kprobe", "flow_trace",
    "dmesg", "functional_side_effect", "unrecognized",
])
def test_no_other_observation_channel_is_an_oracle(sample, channel):
    expect_unknown(observe(sample, channel=channel), "evidence")


@pytest.mark.parametrize("field,value", [
    ("job_id", "job-other"), ("task_id", "task-other"),
    ("vm_instance_id", "vm-other"), ("execution_harness_id", digest("other-execution")),
    ("lane", 1), ("generation_id", 2),
])
def test_guest_correlation_must_match_independent_host_expectation(sample, field, value):
    different = replace(sample.expected_correlation, **{field: value})
    expect_unknown(observe(sample, correlation=different), "evidence",
                   "generation_correlation_mismatch")


def test_matching_correlation_cannot_override_host_build(sample):
    different = replace(sample.expected_correlation, execution_harness_id=digest("other"))
    expect_unknown(observe(replace(sample, expected_correlation=different), correlation=different),
                   "evidence", "generation_correlation_mismatch")


@pytest.mark.parametrize("field,value", [
    ("execution_harness_id", digest("other-harness")), ("kernel_commit", "b" * 40),
    ("instrumentation_sha256", digest("other-patches")),
    ("vmlinux_sha256", digest("other-vmlinux")), ("kaslr_enabled", True),
])
@pytest.mark.parametrize("location", ["observation", "mapping"])
def test_build_mapping_and_observation_bind_all_identity_fields(sample, field, value, location):
    identity = replace(sample.expected_identity, **{field: value})
    if location == "observation":
        data = observe(sample, identity=identity)
    else:
        data = replace(sample, mapping=replace(sample.mapping, identity=identity))
    expect_unknown(data, "evidence")


def test_kaslr_mapping_must_match_verified_runtime_offset(sample):
    identity = replace(sample.expected_identity, kaslr_enabled=True, kaslr_offset=0x100000)
    data = replace(sample, expected_identity=identity,
                   observation=replace(sample.observation, identity=identity),
                   mapping=replace(sample.mapping, identity=identity))
    assert evaluate(data).status is Q1Status.REACHED
    different = replace(identity, kaslr_offset=0x200000)
    expect_unknown(replace(data, mapping=replace(data.mapping, identity=different)), "evidence")


@pytest.mark.parametrize("field,value", [
    ("kernel_commit", "b" * 40), ("instrumentation_sha256", digest("new-patches")),
])
def test_boundary_must_match_attribution_build_even_on_hit(sample, field, value):
    expect_unknown(replace(sample, boundary=replace(sample.boundary, **{field: value})),
                   "evidence", "support_boundary_build_mismatch")


@pytest.mark.parametrize("field", tuple(GenerationCounters.model_fields))
def test_missing_integrity_counter_blocks_even_valid_hit(sample, field):
    expect_unknown(count(sample, **{field: None}), "evidence", "missing_generation_counter")


@pytest.mark.parametrize("field,value", [
    ("generation_begin", 0), ("generation_begin", 2), ("remote_start_ok", 0),
    ("aggregate_published", 2), ("generation_aborted", 1), ("scratch_overflow", 1),
    ("merge_truncation", 1), ("outstanding_tokens", 1), ("remote_refs", 1),
])
@pytest.mark.parametrize("hit", [True, False])
def test_published_contradiction_forbids_both_definite_verdicts(sample, field, value, hit):
    expect_unknown(count(sample if hit else miss(sample), **{field: value}), "evidence")


@pytest.mark.parametrize("changes,missing", [
    ({"generation_begin": 2}, "remote_refs"),
    ({"aggregate_published": 2}, "remote_refs"),
    ({"generation_begin": 0}, "remote_refs"),
    ({"remote_start_ok": 0}, "remote_refs"),
    ({"generation_aborted": 1}, "remote_refs"),
    ({"scratch_overflow": 1}, "remote_refs"),
    ({"merge_truncation": 1}, "remote_refs"),
    ({"outstanding_tokens": 1}, "remote_refs"),
    ({"remote_refs": 1}, "merge_truncation"),
])
def test_known_published_contradiction_precedes_unrelated_missing_counter(
        sample, changes, missing):
    data = count(observe(sample, runner_completed=False), **changes, **{missing: None})
    diagnostic = ("multiple_generations_in_single_generation_evidence"
                  if "generation_begin" in changes and changes["generation_begin"] > 1
                  or "aggregate_published" in changes and changes["aggregate_published"] > 1
                  else "published_aggregate_contradicts_generation_counters")
    expect_unknown(data, "evidence", diagnostic)


@pytest.mark.parametrize("early_failure", [False, True])
def test_truly_undecidable_partial_counter_preserves_early_infra_precedence(
        sample, early_failure):
    data = count(observe(sample, runner_completed=not early_failure), remote_refs=None)
    if early_failure:
        expect_unknown(data, "infra", "execution_incomplete_or_failed")
    else:
        expect_unknown(data, "evidence", "missing_generation_counter")


@pytest.mark.parametrize("changes,missing,reason,diagnostic", [
    ({"scratch_overflow": 1}, "remote_refs", "loss",
     "aggregate_unpublished_after_coverage_loss"),
    ({"merge_truncation": 1}, "remote_refs", "loss",
     "aggregate_unpublished_after_coverage_loss"),
    ({"generation_aborted": 1}, "remote_refs", "infra",
     "aggregate_unpublished_after_generation_failure"),
    ({"remote_refs": 1}, "outstanding_tokens", "infra",
     "aggregate_unpublished_after_generation_failure"),
])
def test_known_unpublished_failure_precedes_unrelated_missing_counter(
        sample, changes, missing, reason, diagnostic):
    data = count(sample, aggregate_published=0, **changes, **{missing: None})
    expect_unknown(data, reason, diagnostic)


def test_unpublished_failure_waits_for_undecidable_higher_precedence_loss(sample):
    data = count(sample, aggregate_published=0, generation_aborted=1, scratch_overflow=None)
    expect_unknown(data, "evidence", "missing_generation_counter")


@pytest.mark.parametrize("changes,reason", [
    ({}, "evidence"), ({"scratch_overflow": 1}, "loss"),
    ({"merge_truncation": 1}, "loss"), ({"generation_aborted": 1}, "infra"),
    ({"outstanding_tokens": 1}, "infra"), ({"remote_refs": 1}, "infra"),
    ({"generation_begin": 0}, "infra"), ({"remote_start_ok": 0}, "infra"),
])
def test_unpublished_generation_diagnostics_precede_mapping(sample, changes, reason):
    data = count(replace(sample, mapping=None), aggregate_published=0, **changes)
    expect_unknown(data, reason)


def test_profile_may_require_more_remote_starts_but_cannot_disable_integrity(sample):
    profile = replace(sample.profile, minimum_remote_start_ok=4)
    expect_unknown(replace(sample, profile=profile), "evidence")
    with pytest.raises(ValidationError):
        replace(profile, minimum_remote_start_ok=0)


@pytest.mark.parametrize("unavailable", ["none", "unverified", "empty"])
@pytest.mark.parametrize("hit", [True, False])
def test_mapping_unavailable_precedes_context_and_loss(sample, unavailable, hit):
    mapping = {"none": None, "unverified": replace(sample.mapping, verified=False),
               "empty": replace(sample.mapping, target_pcs=())}[unavailable]
    data = sample if hit else miss(sample)
    data = replace(data, mapping=mapping,
                   requirement=replace(sample.requirement, expected_context="client_side"))
    result = expect_unknown(observe(data, counter_deltas=()), "mapping")
    assert result.execution_valid is True
    assert result.target_observed is None


@pytest.mark.parametrize("field,value", [
    ("candidate_id", "another-candidate"), ("kernel_commit", "b" * 40),
    ("path", "fs/nfs/client.c"), ("symbol", "other_function"),
    ("start_line", 101), ("end_line", 181),
])
def test_mapping_must_bind_complete_candidate(sample, field, value):
    target = replace(sample.candidate, **{field: value})
    expect_unknown(replace(sample, mapping=replace(sample.mapping, target=target)), "evidence")


def test_plan_target_and_candidate_commit_must_match(sample):
    target = replace(sample.candidate, start_line=101)
    expect_unknown(replace(sample, requirement=replace(sample.requirement, target=target)), "evidence")
    target = replace(sample.candidate, kernel_commit="b" * 40)
    expect_unknown(replace(sample, candidate=target,
                           requirement=replace(sample.requirement, target=target)), "evidence")


def test_source_range_target_uses_external_exact_mapping(sample):
    target = replace(sample.candidate, kind="source_range", symbol=None)
    data = replace(sample, candidate=target,
                   requirement=replace(sample.requirement, target=target),
                   mapping=replace(sample.mapping, target=target))
    assert evaluate(data).status is Q1Status.REACHED
    assert evaluate(miss(data)).status is Q1Status.NOT_REACHED


@pytest.mark.parametrize("context", ["client_side", "callback_v40", "ownerless_background",
                                      "transport_accept", "pre_dispatch"])
def test_unsupported_miss_produces_exact_gap_before_loss_gate(sample, context):
    data = replace(miss(sample), requirement=replace(sample.requirement, expected_context=context))
    result = expect_unknown(observe(data, counter_deltas=()), "unsupported_attribution")
    assert result.gap_signal.gap_class is GapClass.REMOTE_KCOV_ATTRIBUTION
    assert result.gap_signal.missing_capability_id == f"remote_kcov.context.{context}"
    assert result.target_observed is False
    assert result.execution_valid is True


@pytest.mark.parametrize("context", ["request", "async_copy", "client_side"])
@pytest.mark.parametrize("deltas", [(), (CounterDelta(counter="lane_owner_failed",
                                                     window="begin-through-late-sections", value=99),)])
def test_actual_hit_precedes_unsupported_missing_or_excessive_loss(sample, context, deltas):
    data = replace(sample, requirement=replace(sample.requirement, expected_context=context))
    result = evaluate(observe(data, counter_deltas=deltas))
    assert result.status is Q1Status.REACHED
    assert result.gap_signal is None


def test_supported_miss_without_context_policy_is_unknown(sample):
    data = replace(miss(sample), requirement=replace(sample.requirement, expected_context="async_copy"))
    expect_unknown(data, "loss", "context_loss_policy_absent")


@pytest.mark.parametrize("change", [{"window": "other-window"}, {"window": None},
                                   {"value": None}, {"counter": "different_counter"}])
def test_missing_required_counter_or_window_fails_closed(sample, change):
    delta, *rest = sample.observation.counter_deltas
    data = observe(miss(sample), counter_deltas=(replace(delta, **change), *rest))
    expect_unknown(data, "loss", "required_counter_window_absent:lane_owner_failed")


def test_every_required_counter_is_required(sample):
    deltas = sample.observation.counter_deltas
    for index, missing in enumerate(deltas):
        data = observe(miss(sample), counter_deltas=deltas[:index] + deltas[index + 1:])
        expect_unknown(data, "loss", f"required_counter_window_absent:{missing.counter}")


@pytest.mark.parametrize("delta,status", [(0, Q1Status.NOT_REACHED), (2, Q1Status.NOT_REACHED),
                                          (3, Q1Status.INCONCLUSIVE)])
def test_profile_delta_threshold_inclusive(sample, delta, status):
    *rest, last = sample.observation.counter_deltas
    result = evaluate(observe(miss(sample), counter_deltas=(*rest, replace(last, value=delta))))
    assert result.status is status
    if status is Q1Status.INCONCLUSIVE:
        assert result.reason == "loss"


def test_normal_counters_and_post_window_close_do_not_replace_in_window_counter(sample):
    deltas = sample.observation.counter_deltas + (
        CounterDelta(counter="lane_owner_no_generation", window="between-programs", value=100),
        CounterDelta(counter="lane_owner_failed", window="post-finish-close-fds", value=5),
    )
    assert evaluate(observe(miss(sample), counter_deltas=deltas)).status is Q1Status.NOT_REACHED
    expect_unknown(observe(miss(sample), counter_deltas=deltas[1:]), "loss")


def test_callback_rejection_after_finish_must_be_in_profile_window(sample):
    callback_policy = ContextLossPolicy(
        context="callback_v41", window="begin-through-post-finish-late-callbacks",
        counters=(CounterLimit(counter="cb_section_owner_none"),),
    )
    data = replace(miss(sample), requirement=replace(sample.requirement, expected_context="callback_v41"),
                   profile=replace(sample.profile, contexts=(callback_policy,)))
    delta = CounterDelta(counter="cb_section_owner_none", window="begin-through-finish", value=0)
    expect_unknown(observe(data, counter_deltas=(delta,)), "loss")
    delta = replace(delta, window=callback_policy.window)
    assert evaluate(observe(data, counter_deltas=(delta,))).status is Q1Status.NOT_REACHED
    expect_unknown(observe(data, counter_deltas=(replace(delta, value=1),)), "loss")


@pytest.mark.parametrize("invalid", [False, True, "0", 0.0, -1, 2**64, float("nan"), float("inf")])
@pytest.mark.parametrize("field", tuple(GenerationCounters.model_fields))
def test_counters_are_strict_unsigned_integers_not_bool_or_float(sample, field, invalid):
    with pytest.raises(ValidationError):
        count(sample, **{field: invalid})


@pytest.mark.parametrize("invalid", [False, True, "0", 0.0, -1, float("nan"), float("inf")])
def test_loss_deltas_are_strict_integers(invalid):
    with pytest.raises(ValidationError):
        CounterDelta(counter="loss", window="window", value=invalid)


@pytest.mark.parametrize("field", ["boot_ok", "collection_completed", "generation_attributed",
                                  "guest_target_observed"])
@pytest.mark.parametrize("invalid", [0, 1, "false", "true"])
def test_flags_are_strict_booleans(sample, field, invalid):
    with pytest.raises(ValidationError):
        observe(sample, **{field: invalid})


@pytest.mark.parametrize("invalid", [False, True, 0, -1, "4096", 4096.0, float("nan"), 2**64])
def test_pcs_are_strict_nonzero_addresses(sample, invalid):
    with pytest.raises(ValidationError):
        observe(sample, published_pcs=(invalid,))
    with pytest.raises(ValidationError):
        replace(sample.mapping, target_pcs=(invalid,))


@pytest.mark.parametrize("field,invalid", [
    ("lane", False), ("lane", True), ("lane", "0"), ("generation_id", False),
    ("generation_id", True), ("generation_id", "1"), ("generation_id", float("nan")),
])
def test_correlation_never_coerces_numbers(sample, field, invalid):
    with pytest.raises(ValidationError):
        replace(sample.expected_correlation, **{field: invalid})


@pytest.mark.parametrize("path", ["/fs/nfsd/file.c", "../fs/nfsd/file.c", "fs/./nfsd/file.c",
                                 "fs//nfsd/file.c", "fs\\nfsd\\file.c"])
def test_source_path_must_be_normalized(sample, path):
    with pytest.raises(ValidationError):
        replace(sample.candidate, path=path)


@pytest.mark.parametrize("changes", [{"symbol": None}, {"start_line": True},
                                     {"end_line": 99}, {"kind": "source_range"}])
def test_candidate_shape_is_checked(sample, changes):
    with pytest.raises(ValidationError):
        replace(sample.candidate, **changes)


def test_disabled_kaslr_cannot_have_relocation(sample):
    with pytest.raises(ValidationError):
        replace(sample.expected_identity, kaslr_offset=1)


def test_unknown_fields_are_rejected_at_every_input_level(sample):
    records = (
        sample, sample.candidate, sample.requirement, sample.expected_identity,
        sample.expected_correlation, sample.observation, sample.observation.generation,
        sample.observation.counter_deltas[0], sample.profile, sample.profile.contexts[0],
        sample.profile.contexts[0].counters[0], sample.boundary, sample.mapping,
    )
    for record in records:
        with pytest.raises(ValidationError):
            replace(record, unknown="reject me")


def test_duplicate_and_conflicting_policy_entries_rejected(sample):
    context = sample.profile.contexts[0]
    with pytest.raises(ValidationError):
        replace(sample.profile, contexts=(context, context))
    with pytest.raises(ValidationError):
        replace(sample.profile, allowed_trace_modes=("off", "off"))
    with pytest.raises(ValidationError):
        replace(context, counters=(context.counters[0], context.counters[0]))
    with pytest.raises(ValidationError):
        replace(context, normal_counters=(context.counters[0].counter,))
    with pytest.raises(ValidationError):
        replace(context, normal_counters=("normal", "normal"))
    with pytest.raises(ValidationError):
        replace(context, counters=())
    with pytest.raises(ValidationError):
        replace(sample.boundary, supported_contexts=("request", "request"))
    delta = sample.observation.counter_deltas[0]
    with pytest.raises(ValidationError):
        observe(sample, counter_deltas=(delta, delta))


def test_input_and_output_are_deeply_immutable(sample):
    decision = evaluate(sample)
    for record, field, value in (
        (sample, "evidence_verified", False), (sample.candidate, "path", "other.c"),
        (sample.profile.contexts[0].counters[0], "max_delta", 100),
        (sample.observation.generation, "aggregate_published", 0),
        (decision, "status", Q1Status.NOT_REACHED),
    ):
        with pytest.raises(ValidationError):
            setattr(record, field, value)
    with pytest.raises(TypeError):
        sample.observation.published_pcs[0] = 1


def test_unvalidated_copies_cannot_bypass_evaluate(sample):
    unsafe_generation = sample.observation.generation.model_copy(update={"generation_aborted": False})
    unsafe_observation = sample.observation.model_copy(update={"generation": unsafe_generation})
    unsafe_input = sample.model_copy(update={"observation": unsafe_observation})
    with pytest.raises(ValidationError):
        evaluate(unsafe_input)
    with pytest.raises(ValidationError):
        evaluate(sample.model_copy(update={"unknown": 1}))


def test_determinism_pc_set_semantics_and_no_input_mutation(sample):
    before = canonical_json(sample)
    result = evaluate(sample)
    assert result == evaluate(sample)
    assert canonical_json(sample) == before
    same_sets = observe(sample, published_pcs=(0x2000, 0x1010, 0x1010))
    same_sets = replace(same_sets, mapping=replace(sample.mapping, target_pcs=(0x1020, 0x1010, 0x1020)))
    assert evaluate(same_sets) == result


@pytest.mark.parametrize("reference", ["plan_ref", "hcap_revision", "evidence_manifest_sha256",
                                      "profile", "boundary", "mapping"])
def test_identity_binds_all_evaluation_references(sample, reference):
    value = {"plan_ref": digest("other-plan"), "hcap_revision": "hcap-2",
             "evidence_manifest_sha256": digest("other-manifest"),
             "profile": replace(sample.profile, revision="2"),
             "boundary": replace(sample.boundary, revision="2"),
             "mapping": replace(sample.mapping, mapping_method="other-verified-mapper")}[reference]
    before = evaluate(sample)
    after = evaluate(replace(sample, **{reference: value}))
    assert before.status is after.status is Q1Status.REACHED
    assert before.verdict_id != after.verdict_id
    assert before.evaluation_input_sha256 != after.evaluation_input_sha256


def test_profile_content_changes_identity_even_when_label_is_reused(sample):
    profile = replace(sample.profile, minimum_remote_start_ok=2)
    assert profile.name == sample.profile.name
    assert profile.revision == sample.profile.revision
    assert profile.digest != sample.profile.digest
    assert evaluate(replace(sample, profile=profile)).verdict_id != evaluate(sample).verdict_id


@pytest.mark.parametrize("variant", ["hit", "miss", "gap", "invalid"])
def test_canonical_storage_round_trip_uses_shared_helpers(sample, tmp_path, variant):
    if variant == "miss":
        sample = miss(sample)
    elif variant == "gap":
        sample = replace(miss(sample), requirement=replace(sample.requirement, expected_context="client_side"))
    elif variant == "invalid":
        sample = replace(sample, evidence_verified=False)
    store = ArtifactStore(tmp_path / "artifacts")
    restored = load_record(store, put_record(store, sample), Q1Input)
    assert restored == sample
    result = evaluate(restored)
    assert load_record(store, put_record(store, result), Q1Decision) == result


@pytest.mark.parametrize("corrupt", ["duplicate", "nan", "infinity", "noncanonical", "unknown"])
def test_shared_loader_rejects_bad_json_before_evaluation(sample, tmp_path, corrupt):
    store = ArtifactStore(tmp_path / "artifacts")
    encoded = canonical_json(sample)
    if corrupt == "duplicate":
        encoded = encoded.replace(b'"evidence_verified":true',
                                  b'"evidence_verified":false,"evidence_verified":true')
    elif corrupt == "nan":
        encoded = encoded.replace(b'"generation_aborted":0', b'"generation_aborted":NaN')
    elif corrupt == "infinity":
        encoded = encoded.replace(b'"generation_aborted":0', b'"generation_aborted":1e400')
    elif corrupt == "noncanonical":
        encoded = json.dumps(json.loads(encoded), indent=2).encode()
    else:
        encoded = encoded[:-1] + b',"unknown":true}'
    with pytest.raises(ValueError):
        load_record(store, store.put(encoded), Q1Input)
