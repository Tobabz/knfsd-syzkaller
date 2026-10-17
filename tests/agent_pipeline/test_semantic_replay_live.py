"""M6/S1c end to end on the host: production, then replay, then the verdict.

The built Proxy runs in target mode against the real `HostJournal` twice:
once as production (two generations of one lane, the second cut by a
crash), and once per replay, with the rule set the plan read back from the
sealed production journal, a fresh replay journal, different generation
numbers and different dynamic field values.  The crash log the plan reads
has the format syzkaller patch 0024 prints.  What the KVM step adds (the
executor driving activation, syz-execprog running the window, knfsd) is
not here; the activation driver and fake client stand in for it, as in
`test_journal_live`.
"""

from __future__ import annotations

import hashlib
import struct
import time

import pytest

from agent_pipeline.journal_sink import HostJournal
from agent_pipeline.replay_runner import (
    check_rule_set, install_replay, invalid_plan_input, judge_input, parse_crash_context,
    parse_execprog_barriers, plan_replay, write_replay_inputs,
)
from agent_pipeline.semantic_delta import DeltaReadError, SealedJournal
from agent_pipeline.semantic_replay import (
    DeliveryState, InvalidReason, RefusalEvidence, ReplayJudgeProfile, ReplayVerdict,
    Termination, evaluate,
)

from . import test_journal_live as live_mod
from .test_journal_live import (
    CHANNEL, DIGEST, LANE, SESSION, VM, Live, _build_proxy, rule_set,
)

pytestmark = live_mod.pytestmark
PROFILE = ReplayJudgeProfile(name="replay", revision="1")
BARRIER = ("activation=Acked/0 deactivation=Acked/0 executed=true lease_cleared=true")


@pytest.fixture(scope="module")
def proxy_binary(tmp_path_factory):
    return _build_proxy(tmp_path_factory)


def _run(binary, tmp, journal, script, *, crash: bool) -> None:
    """Drive one lane: `script` is [(generation, [slotid, ...]), ...]; the
    last generation is cut by a crash (SIGKILL before deactivation)."""
    live = Live(binary, tmp, journal)
    xid = 100
    try:
        for index, (generation, slots) in enumerate(script):
            assert live.request(1, generation) == 0
            for slot in slots:
                xid += 1
                live.call(xid, slot)
            last = index == len(script) - 1
            if last and crash:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    types = live.types()
                    if types.count("FORWARD_COMPLETE") == types.count("EXPOSURE_INTENT"):
                        break
                    time.sleep(0.02)
                live.proc.kill()
                live.proc.wait(timeout=10)
                live.client.close()
                live.act.close()
                live.channel.close()
                live.backend.close()
                return
            closed = live.types().count("GENERATION_COMPLETE") + 1
            assert live.request(2, generation) == 0
            deadline = time.monotonic() + 10
            while live.types().count("GENERATION_COMPLETE") < closed:
                assert time.monotonic() < deadline, live.types()
                time.sleep(0.02)
        live.stop()
    finally:
        if live.proc.poll() is None:
            live.proc.kill()


def _journal(directory, rules: bytes) -> HostJournal:
    journal = HostJournal(directory, "lane0")
    journal.install_session(vm_instance_id=VM, channel_id=CHANNEL, proxy_session_id=SESSION,
                            lane_id=LANE, rule_set=rules)
    return journal


def _crash_log(first_generation: int) -> str:
    return (
        "last executing test programs:\n\n"
        f"1.2s ago: executing program {LANE} (id=10):\n"
        f"nfs-proxy: lane={LANE} generation={first_generation} "
        f"program_digest={DIGEST.hex()} {BARRIER}\n"
        "getpid()\n\n"
        f"0s ago: executing program {LANE} (id=11):\n"
        "getuid()\n\n"
        "kernel console output (not intermixed with test programs):\n\n"
        "BUG: KASAN: use-after-free in nfsd4_sequence\n"
    )


def _replay(binary, tmp, plan, script, monkeypatch) -> SealedJournal:
    # The Proxy is started with the plan's recorded bytes, not a rule set
    # built here, and records on a journal of its own.
    monkeypatch.setattr(live_mod, "rule_set", lambda: plan.rule_set)
    tmp.mkdir()
    journal = _journal(tmp / "journal", plan.rule_set)
    _run(binary, tmp, journal, script, crash=True)
    journal.close()
    return SealedJournal(tmp / "journal", "lane0")


@pytest.fixture(scope="module")
def production(proxy_binary, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("production")
    journal = _journal(tmp / "journal", rule_set())
    # g1: slot 5 -> r1, slot 2 no match.  g2 (crash): slot 4 -> r1.
    _run(proxy_binary, tmp, journal, [(1, [5, 2]), (2, [4])], crash=True)
    journal.close()
    return tmp / "journal"


def _barriers(generation: int, n: int = 1) -> str:
    return "".join(f"2026/10/17 nfs proxy barrier: generation={generation + i} "
                   f"program_digest={DIGEST.hex()} {BARRIER}\n" for i in range(n))


def _judge(plan, production_dir, replay, barriers, compat):
    return evaluate(judge_input(
        plan, SealedJournal(production_dir, "lane0"), replay, replay_vm_instance_id=VM,
        replay_lane_id=LANE, replay_barriers=parse_execprog_barriers(barriers),
        production_termination=Termination.GUEST_CRASH,
        replay_termination=Termination.GUEST_CRASH, compatibility=compat,
        evidence_verified=True, profile=PROFILE))


def test_window_replays_equivalent_with_other_dynamic_values(
        proxy_binary, production, tmp_path, monkeypatch):
    before = SealedJournal(production, "lane0")
    raw_before = {p.name: p.read_bytes() for p in production.iterdir()}
    window = parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4)
    assert [e.barrier is not None for e in window.entries] == [True, False]
    plan = plan_replay(before, window)
    assert plan.rule_set == rule_set()
    assert [(p.kcov_generation, p.program_digest) for p in plan.positions] == [
        (1, DIGEST.hex()), (2, DIGEST.hex())]
    paths = write_replay_inputs(plan, tmp_path / "inputs")
    assert paths["rules"].read_bytes() == rule_set()
    assert paths["programs"].read_text().splitlines()[:2] == [
        "executing program 0 (id=0):", "getpid()"]
    compat = check_rule_set(proxy_binary, plan.rule_set, tmp_path)
    assert compat.ok, compat.line

    # Other generation numbers and other original slot ids (9, 8 instead of
    # 5, 4): the same rule resolves on new bytes (05 oracle §1).
    replay = _replay(proxy_binary, tmp_path / "replay", plan, [(11, [9, 1]), (12, [8])],
                     monkeypatch)
    result = _judge(plan, production, replay, _barriers(11), compat)
    assert result.semantic_verdict is ReplayVerdict.EQUIVALENT, result.positions
    first, second = result.positions
    assert (first.production_generation, first.replay_generation) == (1, 11)
    assert (second.production_generation, second.replay_generation) == (2, 12)
    assert first.production.refusal_evidence is RefusalEvidence.COMPLETE
    assert second.production.refusal_evidence is RefusalEvidence.PREFIX_COMPLETE
    assert dict(first.replay.delivery)[DeliveryState.COMPLETE] == 1

    # The production MutationDelta was only read (05 oracle §13).
    assert {p.name: p.read_bytes() for p in production.iterdir()} == raw_before
    assert SealedJournal(production, "lane0").manifest() == before.manifest()
    assert result.production_evidence_manifest_sha256 == before.manifest_sha256()


def test_extra_match_in_replay_diverges(proxy_binary, production, tmp_path, monkeypatch):
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    compat = check_rule_set(proxy_binary, plan.rule_set, tmp_path)
    replay = _replay(proxy_binary, tmp_path / "replay", plan, [(3, [5, 10]), (4, [4])],
                     monkeypatch)
    result = _judge(plan, production, replay, _barriers(3), compat)
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    assert [bool(p.differences) for p in result.positions] == [True, False]


def test_hard_refusal_in_replay_diverges(proxy_binary, production, tmp_path, monkeypatch):
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    compat = check_rule_set(proxy_binary, plan.rule_set, tmp_path)
    # slot 6 is the r1/r2 conflict: written ahead, then the record moves.
    replay = _replay(proxy_binary, tmp_path / "replay", plan, [(5, [5, 2]), (6, [4, 6])],
                     monkeypatch)
    result = _judge(plan, production, replay, _barriers(5), compat)
    assert result.semantic_verdict is ReplayVerdict.DIVERGED
    hard = result.positions[1].replay.hard_refusals
    assert {(r.rule_id, r.refusal) for r in hard} == {("r1", "conflict"), ("r2", "conflict")}


def test_replay_cut_before_the_last_program_is_inconclusive(
        proxy_binary, production, tmp_path, monkeypatch):
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    compat = check_rule_set(proxy_binary, plan.rule_set, tmp_path)
    replay = _replay(proxy_binary, tmp_path / "replay", plan, [(7, [5, 2])], monkeypatch)
    result = _judge(plan, production, replay, "", compat)
    assert result.semantic_verdict is ReplayVerdict.INCONCLUSIVE
    assert result.positions[1].replay is None


def test_incompatible_recorded_rule_set_is_invalid(proxy_binary, production, tmp_path):
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    schema = plan.schema_id.encode()
    other = plan.rule_set.replace(schema, schema[:-1] + (b"0" if schema[-1:] != b"0" else b"1"))
    compat = check_rule_set(proxy_binary, other, tmp_path)
    assert not compat.ok and compat.reason is InvalidReason.SCHEMA_UNAVAILABLE, compat.line
    compat = check_rule_set(proxy_binary, b"NFSPRUL1" + struct.pack(">I", 9) + other[12:],
                            tmp_path)
    assert compat.reason is InvalidReason.RUNTIME_INCOMPATIBLE, compat.line
    production_view = SealedJournal(production, "lane0")
    result = evaluate(invalid_plan_input(
        candidate_id=plan.candidate_id,
        production_manifest_sha256=production_view.manifest_sha256(),
        reason=compat.reason, profile=PROFILE, evidence_verified=True,
        rule_set_id=plan.rule_set_id, schema_id=plan.schema_id, window_size=2))
    assert result.semantic_verdict is ReplayVerdict.INVALID
    assert result.invalid_reasons == (InvalidReason.RUNTIME_INCOMPATIBLE,)


def test_series_install_uses_the_recorded_bytes(production, tmp_path):
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    journal = HostJournal(tmp_path / "replay", "lane0")
    install_replay(journal, plan, vm_instance_id="vm-replay", channel_id=CHANNEL,
                   session_prefix="replay-1", lane_id=0)
    series = journal._series[("vm-replay", CHANNEL)]  # noqa: SLF001
    assert series.rule_set == plan.rule_set == rule_set()
    journal.close()


def test_torn_tail_is_a_prefix_and_middle_corruption_is_refused(production, tmp_path):
    # 05 oracles §11 and §12 on a copy of the sealed production journal.
    segment = sorted(production.iterdir())[0].read_bytes()
    torn = tmp_path / "torn"
    torn.mkdir()
    (torn / "lane0.0000.njnl").write_bytes(segment + segment[:100])
    view = SealedJournal(torn, "lane0")
    assert view.torn_tail and view.segments[0].torn_tail_bytes == 100
    assert SealedJournal(production, "lane0").sessions[SESSION].generations.keys() == \
        view.sessions[SESSION].generations.keys()
    bad = tmp_path / "bad"
    bad.mkdir()
    corrupt = bytearray(segment)
    corrupt[200] ^= 0xFF
    (bad / "lane0.0000.njnl").write_bytes(bytes(corrupt))
    with pytest.raises(DeltaReadError):
        SealedJournal(bad, "lane0")
    with pytest.raises(DeltaReadError):
        SealedJournal(tmp_path / "missing", "lane0")
    assert hashlib.sha256(segment).hexdigest() == SealedJournal(production, "lane0").segments[0].sha256
