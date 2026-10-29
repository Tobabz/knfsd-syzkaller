"""Pure Q2 decision tests; no artifact store or runtime is involved."""

from __future__ import annotations

from hashlib import sha256

import pytest
from pydantic import ValidationError

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import load_record, put_record
from agent_pipeline.evidence import ExecutionCorrelation
from agent_pipeline.q2 import (
    CandidateAssociation,
    ManagerCrashReport,
    Q2CollectionWindow,
    Q2Evidence,
    Q2Input,
    Q2JudgeProfile,
    Q2ParseRule,
    Q2SignalClass,
    Q2Status,
    default_q2_profile,
    evaluate,
)


def digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def replace(record, **changes):
    return type(record).model_validate({**record.model_dump(), **changes})


@pytest.fixture
def sample() -> Q2Input:
    harness_id = digest("execution-harness")
    correlation = ExecutionCorrelation(
        job_id="job-1",
        task_id="task-1",
        execution_harness_id=harness_id,
        vm_instance_id="vm-1",
        lane=0,
        generation_id=1,
    )
    evidence = Q2Evidence(
        execution_harness_id=harness_id,
        correlation=correlation,
        console_log_ref=digest("console"),
        console_log_completeness="complete",
        manager_crash_reports=(),
        vm_termination="runner_stopped",
        collection_window=Q2CollectionWindow(
            start_marker="campaign-segment-start",
            end_marker="campaign-segment-end",
        ),
    )
    return Q2Input(
        evidence_manifest_sha256=digest("manifest"),
        evidence_verified=True,
        expected_execution_harness_id=harness_id,
        expected_correlation=correlation,
        evidence=evidence,
        profile=default_q2_profile(),
    )


def with_evidence(sample: Q2Input, **changes) -> Q2Input:
    return replace(sample, evidence=replace(sample.evidence, **changes))


def report(name: str, text: str) -> ManagerCrashReport:
    return ManagerCrashReport(
        artifact_identity=name,
        report_ref=digest(name),
        text=text,
    )


def test_valid_sanitizer_report_is_observed_without_candidate_symbol(sample):
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "report-0",
            "BUG: KASAN: use-after-free in unrelated_worker\n"
            "Read of size 8 at addr ffff0000\n",
        ),),
        candidate_association=CandidateAssociation(
            candidate_id="candidate-1",
            symbol="nfsd4_open",
            symbol_present=False,
        ),
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert decision.reason is None
    assert decision.signals[0].signal_class == "KASAN"
    assert decision.candidate_association.symbol_present is False
    assert decision == evaluate(inputs)


def test_nonfatal_report_is_observed_without_vm_crash(sample):
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "warning", "WARNING: CPU: 0 PID: 1 at fs/locks.c:10 lock_warn+0x1/0x2\n"
        ),),
        vm_termination="runner_stopped",
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert decision.signals[0].signal_class == "WARNING"
    assert decision.signals[0].fatal is False
    assert decision.vm_termination == "runner_stopped"


@pytest.mark.parametrize("quality", ["campaign", "ambiguous", "none"])
def test_attribution_quality_never_suppresses_a_classified_signal(
        sample, quality):
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "report", "BUG: KASAN: slab-out-of-bounds in worker\n"),),
        attribution_quality=quality,
        attribution_warnings=("exact_generation_unavailable",),
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert decision.attribution_quality == quality
    assert decision.attribution_warnings == (
        "exact_generation_unavailable",)
    assert decision.as_result().attribution_quality == quality


@pytest.mark.parametrize("legacy", [
    "crash_before_generation_attributed_campaign_execution",
    "report_before_generation_attributed_campaign_execution",
    "uncorrelated_program_results:1",
])
def test_legacy_attribution_error_is_migrated_to_campaign_warning(
        sample, legacy):
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "report", "BUG: KASAN: slab-out-of-bounds in worker\n"),),
        internal_errors=(legacy,),
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert decision.attribution_quality == "campaign"
    assert decision.attribution_warnings == (legacy,)


def test_verdict_without_attribution_keeps_its_earlier_id(sample):
    # The id main computed for this evidence before attribution existed.
    decision = evaluate(sample)
    assert decision.attribution_quality == "none"
    assert decision.verdict_id == (
        "6a43a1c394bd0c3b97752d683993222788580757fc64570f419f95dab6f5220e")
    assert "attribution_quality" not in decision.as_result().model_dump(
        mode="json")
    graded = evaluate(with_evidence(
        sample, attribution_quality="campaign",
        attribution_warnings=("exact_generation_unavailable",)))
    assert graded.verdict_id != decision.verdict_id


def test_legacy_foreign_execution_is_ambiguous_but_still_observed(sample):
    legacy = "foreign_program_execution:19"
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "report", "BUG: KASAN: slab-out-of-bounds in worker\n"),),
        internal_errors=(legacy,),
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert decision.attribution_quality == "ambiguous"
    assert decision.attribution_warnings == (legacy,)


def test_legacy_attribution_warning_does_not_hide_integrity_error(sample):
    legacy = "crash_before_generation_attributed_campaign_execution"
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report(
            "report", "BUG: KASAN: slab-out-of-bounds in worker\n"),),
        internal_errors=(legacy, "collector contradiction"),
    )
    decision = evaluate(inputs)
    assert decision.status is Q2Status.INCONCLUSIVE
    assert decision.reason == "invalid_evidence"
    assert decision.signals == ()
    assert decision.attribution_quality == "campaign"
    assert decision.attribution_warnings == (legacy,)


@pytest.mark.parametrize("flavor", ["rcu", "rcu_preempt", "rcu_sched", "rcu_bh"])
@pytest.mark.parametrize("header", [
    "detected stalls on CPUs/tasks:",
    "self-detected stall on CPU",
    "detected stall, but suppressed full report due to a stuck CSD-lock.",
    "detected expedited stalls on CPUs/tasks: {",
    "detected expedited stalls, but suppressed full report due to a stuck CSD-lock.",
])
def test_rcu_stall_headers_are_hangs(sample, flavor, header):
    # kernel/rcu/tree_stall.h: print_other_cpu_stall(), print_cpu_stall(),
    # and the suppressed-report branch of check_cpu_stall().
    # kernel/rcu/tree_exp.h: synchronize_rcu_expedited_stall().
    inputs = with_evidence(sample, manager_crash_reports=(report(
        "rcu", f"[  123.456789] rcu: INFO: {flavor} {header}\n"),))
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert [(signal.signal_class, signal.fatal) for signal in decision.signals] == [
        ("hang", True),
    ]


def test_rcu_tasks_stall_header_is_a_hang(sample):
    # kernel/rcu/tasks.h: check_holdout_task().
    inputs = with_evidence(sample, manager_crash_reports=(report(
        "rcu-tasks", "rcu: INFO: rcu_tasks detected stalls on tasks:\n"),))
    decision = evaluate(inputs)
    assert decision.status is Q2Status.OBSERVED
    assert [(signal.signal_class, signal.fatal) for signal in decision.signals] == [
        ("hang", True),
    ]


@pytest.mark.parametrize("text", [
    "rcu: INFO: rcu_preempt detected\n",
    "rcu: INFO: rcu_sched starting stall detector\n",
    "rcu: INFO: rcu_preempt detected stallion\n",
    "rcu: INFO: rcu_preempt\nother component detected stall\n",
    "rcu: INFO: rcu_preempt detected\nstall from another component\n",
    "rcu: INFO: rcu_preempt detected expedited\nstalls on CPUs/tasks:\n",
    "rcu: INFO: rcu_preempt detected expedited stallion\n",
    "rcu: INFO: rcu_tasks starting stall detector\n",
    "rcu: INFO: rcu_taskstats detected stalls on tasks:\n",
])
def test_non_stall_rcu_messages_are_unclassified(sample, text):
    decision = evaluate(with_evidence(
        sample, manager_crash_reports=(report("rcu", text),)))
    assert decision.status is Q2Status.INCONCLUSIVE
    assert decision.reason == "unclassified_report"
    assert decision.signals == ()


@pytest.mark.parametrize("text,expected,fatal", [
    ("watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [syz-executor:1234]\n",
     "hang", True),
    ("INFO: task syz-executor:1234 blocked for more than 143 seconds.\n", "hang", True),
    ("BUG: unable to handle kernel NULL pointer dereference\n", "BUG", True),
    ("Kernel panic - not syncing: Fatal exception\n", "panic", True),
    ("BUG: KASAN: use-after-free in worker\n", "KASAN", True),
    ("BUG: KMSAN: uninit-value in worker\n", "KMSAN", True),
    ("BUG: KCSAN: data-race in worker\n", "KCSAN", False),
    ("UBSAN: array-index-out-of-bounds in worker\n", "UBSAN", False),
    ("general protection fault, probably for non-canonical address "
     "0xdffffc0000000000: 0000 [#1] PREEMPT SMP KASAN\n"
     "KASAN: null-ptr-deref in range [0x0-0x7]\n", "KASAN", True),
    ("general protection fault: 0000 [#1] PREEMPT SMP\n", "BUG", True),
    ("kernel BUG at fs/nfsd/nfs4state.c:1234!\n"
     "invalid opcode: 0000 [#1] PREEMPT SMP KASAN\n", "BUG", True),
    ("invalid opcode: 0000 [#1] PREEMPT SMP\n", "BUG", True),
    ("Oops: 0000 [#1] PREEMPT SMP\n", "BUG", True),
    ("Unable to handle kernel NULL pointer dereference at virtual address "
     "0000000000000008\n", "BUG", True),
])
def test_specific_report_classification_precedes_generic_bug(sample, text, expected, fatal):
    decision = evaluate(with_evidence(
        sample, manager_crash_reports=(report("report", text),)))
    assert decision.status is Q2Status.OBSERVED
    assert [(signal.signal_class, signal.fatal) for signal in decision.signals] == [
        (expected, fatal),
    ]


def test_sanitizer_still_precedes_a_secondary_lockup(sample):
    text = ("BUG: KASAN: use-after-free in worker\n"
            "watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [worker:12]\n")
    decision = evaluate(with_evidence(
        sample, manager_crash_reports=(report("report", text),)))
    assert decision.status is Q2Status.OBSERVED
    assert [signal.signal_class for signal in decision.signals] == ["KASAN"]


def test_classified_report_precedes_ordinary_collection_incompleteness(sample):
    inputs = with_evidence(
        sample,
        console_log_ref=None,
        console_log_completeness="missing",
        collection_window=Q2CollectionWindow(start_marker="start"),
        manager_crash_reports=(report("report", "UBSAN: array-index-out-of-bounds\n"),),
        vm_termination="unknown",
    )
    assert evaluate(inputs).status is Q2Status.OBSERVED


@pytest.mark.parametrize(("changes", "reason"), [
    ({"console_log_completeness": "truncated"}, "console_log_truncated"),
    ({"console_log_ref": None, "console_log_completeness": "missing"},
     "console_log_missing"),
    ({"collection_window": Q2CollectionWindow(start_marker="start")},
     "collection_window_open"),
    ({"collection_window": Q2CollectionWindow()}, "collection_window_not_started"),
    ({"vm_termination": "guest_crashed"}, "guest_crashed_without_report"),
    ({"vm_termination": "lost"}, "runner_lost"),
    ({"vm_termination": "unknown"}, "termination_unknown"),
])
def test_incomplete_no_signal_runs_are_inconclusive(sample, changes, reason):
    decision = evaluate(with_evidence(sample, **changes))
    assert decision.status is Q2Status.INCONCLUSIVE
    assert decision.reason == reason


def test_only_complete_closed_runner_stopped_no_report_is_not_observed(sample):
    decision = evaluate(sample)
    assert decision.status is Q2Status.NOT_OBSERVED
    assert decision.reason is None
    assert decision.signals == ()


def test_unclassified_or_profile_truncated_report_is_inconclusive(sample):
    unknown = with_evidence(
        sample,
        manager_crash_reports=(report("unknown", "manager saved opaque output\n"),),
    )
    assert evaluate(unknown).reason == "unclassified_report"

    profile_data = sample.profile.model_dump()
    rules = list(profile_data["parse_rules"])
    warning = next(index for index, rule in enumerate(rules)
                   if rule["rule_id"] == "warning")
    rules[warning] = {**rules[warning], "required_patterns": (r"END-OF-REPORT",)}
    profile_data.update(revision="requires-report-footer", parse_rules=tuple(rules))
    profile = Q2JudgeProfile.model_validate(profile_data)
    partial = replace(
        with_evidence(sample, manager_crash_reports=(report(
            "partial", "WARNING: incomplete report\n"),)),
        profile=profile,
    )
    assert evaluate(partial).reason == "unclassified_report"


@pytest.mark.parametrize("mutate", [
    lambda s: replace(s, evidence_verified=False),
    lambda s: with_evidence(s, internal_errors=("collector contradiction",)),
    lambda s: with_evidence(s, execution_harness_id=digest("other-harness")),
    lambda s: with_evidence(s, correlation=s.evidence.correlation.model_copy(
        update={"task_id": "other-task"})),
    lambda s: with_evidence(s, collection_window=Q2CollectionWindow(
        end_marker="end-without-start")),
    lambda s: with_evidence(s, console_log_ref=digest("unexpected-console"),
                            console_log_completeness="missing"),
    lambda s: with_evidence(s, manager_crash_reports=(
        report("duplicate", "WARNING: first\n"),
        report("duplicate", "WARNING: second\n"),
    )),
])
def test_invalid_or_mismatched_evidence_precedes_signals(sample, mutate):
    inputs = mutate(sample)
    decision = evaluate(inputs)
    assert decision.status is Q2Status.INCONCLUSIVE
    assert decision.reason == "invalid_evidence"


def test_profile_change_creates_new_decision_and_preserves_old_one(sample):
    inputs = with_evidence(
        sample,
        manager_crash_reports=(report("warning", "WARNING: recoverable warning\n"),),
    )
    old = evaluate(inputs)

    profile_data = sample.profile.model_dump()
    rules = tuple(
        {**rule, "pattern": r"NEVER-MATCH-THIS-PROFILE"}
        if rule["rule_id"] == "warning" else rule
        for rule in profile_data["parse_rules"]
    )
    profile_data.update(revision="2", parse_rules=rules)
    changed_profile = Q2JudgeProfile.model_validate(profile_data)
    changed = evaluate(replace(inputs, profile=changed_profile))

    assert old.status is Q2Status.OBSERVED
    assert changed.status is Q2Status.INCONCLUSIVE
    assert old.evidence_manifest_sha256 == changed.evidence_manifest_sha256
    assert old.judge_profile_id != changed.judge_profile_id
    assert old.verdict_id != changed.verdict_id
    assert evaluate(inputs) == old


def test_pure_evaluator_does_not_open_or_write_files(sample, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("pure Q2 evaluator attempted filesystem I/O")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr("os.open", forbidden)
    assert evaluate(sample).status is Q2Status.NOT_OBSERVED


def test_profile_and_decision_are_canonical_artifact_records(sample, tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    profile_ref = put_record(store, sample.profile)
    assert profile_ref == sample.profile.digest
    assert load_record(store, profile_ref, Q2JudgeProfile) == sample.profile

    decision = evaluate(sample)
    decision_ref = put_record(store, decision)
    from agent_pipeline.q2 import Q2Decision
    assert load_record(store, decision_ref, Q2Decision) == decision


def test_profile_rejects_unknown_classes_and_unsafe_termination():
    base = default_q2_profile().model_dump()
    base["parse_rules"] = ({
        "rule_id": "unknown",
        "signal_class": "UNKNOWN",
        "pattern": "UNKNOWN:",
        "required_patterns": (),
    },)
    with pytest.raises(ValidationError, match="unknown signal class"):
        Q2JudgeProfile.model_validate(base)

    with pytest.raises(ValidationError, match="only runner_stopped"):
        from agent_pipeline.q2 import Q2TerminationRule
        Q2TerminationRule(termination="lost", no_signal_status="not_observed")


def test_profile_rejects_empty_matching_regex():
    with pytest.raises(ValidationError, match="must not match empty"):
        Q2ParseRule(rule_id="bad", signal_class="BUG", pattern=r".*")

    # A minimal valid class remains constructible for repository tooling.
    assert Q2SignalClass(name="CUSTOM", fatal=False).name == "CUSTOM"
