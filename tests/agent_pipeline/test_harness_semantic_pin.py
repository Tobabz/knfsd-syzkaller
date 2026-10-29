"""M7 stage 1 of a generated semantic subset (07 §5.2, 03-nfs-proxy/06 §30).

The guest sides are the M6 host run of `test_semantic_replay_live`: the
built Proxy against the real sink, a production that ends without a crash
and a replay on other dynamic values.  It checks the host's staged pin over
them, not KVM evidence.
"""

from __future__ import annotations

import json

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import load_record, put_record
from agent_pipeline.replay_runner import PlanError, execprog_window
from agent_pipeline.semantic_promotion import (
    GuestValidationRun, PromotedSemanticCapabilityRegistry, promote,
    promoted_registry, with_semantic_capability)
from agent_pipeline.semantic_replay import Termination
from agent_pipeline.stage1.host.semantic import (
    SemanticRefused, SideRun, pinned_hcap, read_inputs, staged_pin)

from agent_pipeline import live_probe

from . import test_journal_live as live_mod
from .test_journal_live import VM
from .test_semantic_promotion import (  # noqa: F401  (fixtures)
    KERNEL, ONE_RULE, _catalog, build, proxy_binary, run, subset)
from .test_semantic_replay_live import _barriers, _journal, _run

pytestmark = live_mod.pytestmark
PROGRAM = "getpid()\n"


class LiveGuest:
    """Both sides on the host: g1 of production runs slots 5 and 2, the
    replay's g11 other originals (9, 1) unless told otherwise."""

    def __init__(self, binary, replay_slots=(9, 1)) -> None:
        self.binary, self.replay_slots = binary, replay_slots
        self.ran: list[str] = []

    def _side(self, work, rules, generation, slots) -> None:
        work.mkdir(parents=True)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(live_probe, "rule_set", lambda schema_id=None: rules)
            journal = _journal(work / "journal", rules)
            _run(self.binary, work, journal, [(generation, list(slots))],
                 crash=False)
            journal.close()

    def production(self, program, rules, work) -> SideRun:
        self.ran.append(("production", program.read_text()))
        self._side(work, rules, 1, (5, 2))
        return SideRun(work / "journal", "lane0", VM, _barriers(1),
                       Termination.VM_TEARDOWN)

    def replay(self, programs, rules, work) -> SideRun:
        self.ran.append(("replay", programs.read_text()))
        self._side(work, rules, 11, self.replay_slots)
        return SideRun(work / "journal", "lane0", VM, _barriers(11),
                       Termination.VM_TEARDOWN)


def _inputs(tmp_path, **over):
    directory = tmp_path / "generation"
    directory.mkdir()
    (directory / "subset.json").write_text(json.dumps(
        subset(**over).model_dump(mode="json")))
    (directory / "rules.nfsprul1").write_bytes(ONE_RULE)
    (directory / "production.syz").write_text(PROGRAM)
    return read_inputs(directory)


def test_a_window_without_a_crash_is_planned_from_its_barriers():
    window = execprog_window(_barriers(1), ("a()\n", "b()"),
                             vm_instance_id=VM, lane_id=0, bound=4)
    assert [e.barrier is not None for e in window.entries] == [True, False]
    assert window.entries[1].program == "b()\n"
    assert len(execprog_window(_barriers(1), ("a()", "b()"), vm_instance_id=VM,
                               lane_id=0, bound=1).entries) == 1
    with pytest.raises(PlanError, match="2 barriers for 1 programs"):
        execprog_window(_barriers(1, 2), ("a()",), vm_instance_id=VM,
                        lane_id=0, bound=4)


def test_the_generated_subset_is_pinned_pending(proxy_binary, build, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    guest = LiveGuest(proxy_binary)
    pinned, run_ref = staged_pin(store, proxy_binary, _inputs(tmp_path),
                                 guest, tmp_path / "work",
                                 kernel_commit=KERNEL)
    assert pinned.pending == (subset().subset_id,)
    assert (pinned.proxy_sha256, pinned.registry_digest) == (
        build.proxy_sha256, build.registry_digest)
    recorded = load_record(store, run_ref, GuestValidationRun)
    assert recorded.judge_input.positions[0].production.termination is \
        Termination.VM_TEARDOWN
    # The replay ran the production program, on the recorded rules.
    assert guest.ran[0] == ("production", PROGRAM)
    assert guest.ran[1][1].splitlines()[1] == "getpid()"
    hcap = pinned_hcap(store, _catalog(), pinned)
    assert promoted_registry(store, hcap).pending == (subset().subset_id,)
    entry = next(c for c in hcap.capabilities if c.id == "HCAP-10")
    assert entry.evidence_refs == (run_ref,)


def test_a_promoted_base_on_the_same_build_is_kept(proxy_binary, build, run,
                                                  tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    other = subset(subset_id="semantic.base")
    base_promoted = promote(store, build, other, (put_record(store, run.model_copy(
        update={"subset_id": other.subset_id})),))
    base = with_semantic_capability(_catalog(), put_record(store, base_promoted),
                                    base_promoted)
    pinned, _ = staged_pin(store, proxy_binary, _inputs(tmp_path),
                           LiveGuest(proxy_binary), tmp_path / "work",
                           kernel_commit=KERNEL, base_hcap=base)
    assert [p.subset.subset_id for p in pinned.subsets] == [
        "semantic.base", subset().subset_id]
    assert pinned.pending == (subset().subset_id,)


def test_replay_on_the_production_originals_is_refused(proxy_binary, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    with pytest.raises(SemanticRefused) as refused:
        staged_pin(store, proxy_binary, _inputs(tmp_path),
                   LiveGuest(proxy_binary, replay_slots=(5, 2)),
                   tmp_path / "work", kernel_commit=KERNEL)
    assert refused.value.reason == "semantic_pin_refused"
    assert "dynamic_original_semantic_replay" in refused.value.detail


def test_a_subset_outside_the_build_is_refused_before_a_guest(
        proxy_binary, tmp_path):
    guest = LiveGuest(proxy_binary)
    with pytest.raises(SemanticRefused, match="semantic_subset_not_built"):
        staged_pin(ArtifactStore(tmp_path / "cas"), proxy_binary,
                   _inputs(tmp_path, mutation_kinds=("insert", "replace")),
                   guest, tmp_path / "work", kernel_commit=KERNEL)
    assert guest.ran == []


def test_the_patch_set_supplies_all_three_inputs(tmp_path):
    (tmp_path / "subset.json").write_text("{}")
    with pytest.raises(SemanticRefused, match="rules.nfsprul1, production.syz"):
        read_inputs(tmp_path)
    (tmp_path / "rules.nfsprul1").write_bytes(b"")
    (tmp_path / "production.syz").write_text(PROGRAM)
    with pytest.raises(SemanticRefused, match="semantic_subset_malformed"):
        read_inputs(tmp_path)


def test_pinned_registry_round_trips(proxy_binary, tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    pinned, _ = staged_pin(store, proxy_binary, _inputs(tmp_path),
                           LiveGuest(proxy_binary), tmp_path / "work",
                           kernel_commit=KERNEL)
    assert load_record(store, put_record(store, pinned),
                       PromotedSemanticCapabilityRegistry) == pinned
