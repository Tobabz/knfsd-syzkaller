"""M7 on the host: the build's registry, then the promotion gate over a run.

The registry and rule descriptions come from the built Proxy.  The run is
the M6 live production/replay of `test_semantic_replay_live` (the built
Proxy, the real sink, a crash cut), recorded as a GuestValidationRun the
way `semantic_promotion record` records one.  It is a host run standing in
for the KVM step: this test checks the gate's logic, it is not evidence,
and nothing here is promoted for real.
"""

from __future__ import annotations

import json
import struct

import pytest

from agent_pipeline.agent_tasks.mutation import MutationRuleSet
from agent_pipeline.agent_tasks.tools import ArtifactHcapSource, Stage1Toolbox
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.hcap import (ArtifactHcapChecker, Capability, CapabilityInterface,
                                 HcapCatalog)
from agent_pipeline.replay_runner import (
    check_rule_set, judge_input, parse_crash_context, parse_execprog_barriers,
    plan_replay, write_replay_inputs,
)
from agent_pipeline.semantic_delta import SealedJournal
from agent_pipeline.semantic_promotion import (
    UNPROMOTED_GAP_ID, GuestValidationRun, PromotedSemanticCapabilityRegistry,
    PromotionRefused, SemanticSubset, ValidationItem, check_runtime,
    describe_rule_set, main, promote, promoted_registry, read_build_registry,
    required_items, rule_set_scope, run_problems, subset_problems,
    with_semantic_capability,
)
from agent_pipeline.semantic_replay import (
    ReplayVerdict, Termination, evaluate,
)

from . import test_journal_live as live_mod
from .test_journal_live import VM, LANE, _build_proxy, _rule, _schema_id, _xdr_string
from .test_semantic_replay_live import (
    PROFILE, _barriers, _crash_log, _journal, _replay, _run,
)

pytestmark = live_mod.pytestmark
KERNEL = "a" * 40


def _set(*rules: bytes) -> bytes:
    return (b"NFSPRUL1" + struct.pack(">I", 1) + _xdr_string(_schema_id().encode())
            + _xdr_string(b"cand-live") + struct.pack(">I", len(rules)) + b"".join(rules))


ONE_RULE = _set(_rule("r1", 4, 3, 7))          # slotid > 3 -> 7


def subset(**over) -> SemanticSubset:
    data = dict(
        subset_id="semantic.nfs4_1.call_value_literal_preserve",
        description="NFSv4.1 CALL leaf values replaced by a literal, preserve",
        schema_ids=(_schema_id(),), directions=("C2S",), message_types=("call",),
        target_kinds=("field",), parts=("value",), mutation_kinds=("replace",),
        transforms=("literal",), structure_policies=("preserve",),
        value_sources=("target",), predicate_ops=("gt",))
    data.update(over)
    return SemanticSubset(**data)


@pytest.fixture(scope="module")
def proxy_binary(tmp_path_factory):
    return _build_proxy(tmp_path_factory)


@pytest.fixture(scope="module")
def build(proxy_binary):
    return read_build_registry(proxy_binary)


# ---------------------------------------------------------------- registry


def test_registry_is_canonical_and_names_the_build(proxy_binary, build):
    reg = build.registry
    assert reg.semantic_runtime_version == 1
    assert _schema_id() in reg.schema_ids
    assert {s.schema_id.split("/")[0] for s in reg.schemas} == {
        "nfs3", "nfs4.0", "nfs4.1", "nfs4.2"}
    assert reg.mutation_kinds == ("replace",)
    assert reg.transforms == ("copy", "literal")
    assert "encoded" not in reg.parts
    assert read_build_registry(proxy_binary) == build          # deterministic
    assert len(build.proxy_sha256) == 64 and build.registry_digest == reg.digest


def _variant(kind: int, *, transform: bytes | None = None, part: int = 0,
             policy: int = 0) -> bytes:
    """`_rule`'s SEQUENCE.sa_slotid rule (slotid > 3) with another mutation
    (rule.c `rule()` field order)."""
    u32 = lambda v: struct.pack(">I", v)  # noqa: E731
    return b"".join([
        _xdr_string(b"v"), _xdr_string(b"intent-v"), u32(0), u32(0), u32(0),
        u32(0), u32(100003), u32(4), u32(1), u32(1),
        _xdr_string(b"nfs4"), u32(1), u32(4), u32(1), u32(1),
        u32(1), _xdr_string(b"SEQUENCE"),
        u32(0), _xdr_string(b"nfs4.request.SEQUENCE.args.sa_slotid"), u32(part),
        u32(1), u32(0), _xdr_string(b""), u32(4), u32(0), u32(1), u32(3),
        u32(kind), u32(0) if transform is None else u32(1) + transform,
        u32(policy), u32(0) * 3, u32(0) * 3, u32(0),
    ])


LITERAL_7 = struct.pack(">III", 0, 1, 7)             # literal, uint, 7


@pytest.mark.parametrize("variant, accepted", [
    (_variant(0, transform=LITERAL_7), True),                  # replace preserve
    (_variant(0, transform=LITERAL_7, policy=1), True),        # replace raw
    (_variant(1, transform=LITERAL_7), False),                 # insert
    (_variant(2), False),                                      # delete
    (_variant(0, transform=struct.pack(">I", 2) + _xdr_string(b"xf") + struct.pack(">I", 0)),
     False),                                                   # builtin
    (_variant(0, transform=LITERAL_7, part=1), False),         # encoded part
])
def test_registry_agrees_with_rule_validation(proxy_binary, build, tmp_path,
                                              variant, accepted):
    compat = check_rule_set(proxy_binary, _set(variant), tmp_path)
    assert compat.ok is accepted, compat.line
    if not accepted:
        assert "status=unsupported_capability" in compat.line
        return
    rule = describe_rule_set(proxy_binary, _set(variant), tmp_path).rules[0]
    assert rule.kind in build.registry.mutation_kinds
    assert rule.part in build.registry.parts
    assert rule.transform in build.registry.transforms
    assert rule.structure_policy in build.registry.structure_policies


def test_describe_rules_uses_the_runtime_parser(proxy_binary, tmp_path):
    described = describe_rule_set(proxy_binary, live_mod.rule_set(), tmp_path)
    assert described.schema_id == _schema_id()
    assert [(r.rule_id, r.predicate_ops, r.value_sources, r.transform)
            for r in described.rules] == [
        ("r1", ("gt",), ("target",), "literal"), ("r2", ("eq",), ("target",), "literal")]
    r1 = described.rules[0]
    assert (r1.direction, r1.message_type, r1.operation, r1.target_path, r1.part,
            r1.kind, r1.structure_policy, r1.minor_version) == (
        "C2S", "call", "SEQUENCE", "nfs4.request.SEQUENCE.args.sa_slotid", "value",
        "replace", "preserve", 1)
    refused = check_rule_set(proxy_binary, b"NFSPRUL1" + b"\0" * 4, tmp_path)
    assert not refused.ok


# ---------------------------------------------------------------- one validation run


def _production(binary, tmp, rules: bytes):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(live_mod, "rule_set", lambda: rules)
        journal = _journal(tmp / "journal", rules)
        # g1: slot 5 -> r1, slot 2 no match.  g2 (crash): slot 4 -> r1.
        _run(binary, tmp, journal, [(1, [5, 2]), (2, [4])], crash=True)
        journal.close()
    return tmp / "journal"


def _record(binary, build, tmp, rules: bytes, the_subset) -> GuestValidationRun:
    production = _production(binary, tmp / "production", rules)
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    compat = check_rule_set(binary, plan.rule_set, tmp)
    with pytest.MonkeyPatch.context() as mp:
        replay = _replay(binary, tmp / "replay", plan, [(11, [9, 1]), (12, [8])], mp)
    data = judge_input(
        plan, SealedJournal(production, "lane0"), replay, replay_vm_instance_id=VM,
        replay_lane_id=LANE, replay_barriers=parse_execprog_barriers(_barriers(11)),
        production_termination=Termination.GUEST_CRASH,
        replay_termination=Termination.GUEST_CRASH, compatibility=compat,
        evidence_verified=True, profile=PROFILE)
    return GuestValidationRun(
        subset_id=the_subset.subset_id, environment="kvm_guest",
        proxy_sha256=build.proxy_sha256, registry_digest=build.registry_digest,
        kernel_commit=KERNEL, production_vm_instance_id=VM, replay_vm_instance_id=VM,
        rule_set=describe_rule_set(binary, plan.rule_set, tmp),
        judge_input=data, replay_result=evaluate(data))


@pytest.fixture(scope="module")
def run(proxy_binary, build, tmp_path_factory):
    return _record(proxy_binary, build, tmp_path_factory.mktemp("one-rule"), ONE_RULE,
                   subset())


@pytest.fixture
def store(tmp_path):
    return ArtifactStore(tmp_path / "artifacts")


def test_equivalent_crash_run_promotes_its_subset(build, run, store):
    assert run.replay_result.semantic_verdict is ReplayVerdict.EQUIVALENT
    assert run_problems(run, build, subset()) == []
    promoted = promote(store, build, subset(), (put_record(store, run),))
    (entry,) = promoted.subsets
    assert entry.validation_items == required_items(subset()) == (
        ValidationItem.DYNAMIC_ORIGINAL_REPLAY, ValidationItem.PRESERVE_BEHAVIOR,
        ValidationItem.REQUEST_MUTATION, ValidationItem.DELTA_CRASH_SURVIVAL)
    assert promoted.registry_digest == build.registry_digest
    # Canonical and content addressed like every other authority.
    ref = put_record(store, promoted)
    assert load_record(store, ref, PromotedSemanticCapabilityRegistry) == promoted


def test_every_element_needs_guest_evidence(build, run, store):
    ref = put_record(store, run)
    wider = subset(predicate_ops=("eq", "gt"), structure_policies=("preserve", "raw"),
                   message_types=("call", "reply"))
    with pytest.raises(PromotionRefused) as refused:
        promote(store, build, wider, (ref,))
    text = str(refused.value)
    assert "predicate_ops ['eq']" in text and "structure_policies ['raw']" in text
    assert "message_types ['reply']" in text
    assert "response_mutation" in text and "raw_behavior" in text


def test_subset_must_be_implemented_by_the_build(build):
    assert subset_problems(subset(mutation_kinds=("insert", "replace")),
                           build.registry) == [
        "mutation_kinds not in the build registry: ['insert']"]
    assert subset_problems(subset(schema_ids=("nfs9/sha256:" + "0" * 64,)),
                           build.registry)


def test_rules_outside_the_subset_disqualify_the_run(proxy_binary, build, tmp_path, store):
    # r2 compares with eq: a run of both rules is evidence only for a subset
    # that admits eq, and then eq itself was never exercised.
    two = _record(proxy_binary, build, tmp_path, live_mod.rule_set(), subset())
    assert any("predicate_ops ['eq']" in p for p in run_problems(two, build, subset()))
    with pytest.raises(PromotionRefused, match=r"exercises predicate_ops \['eq'\]"):
        promote(store, build, subset(predicate_ops=("eq", "gt")),
                (put_record(store, two),))


@pytest.mark.parametrize("change, problem", [
    (lambda r: r.model_copy(update={"proxy_sha256": "0" * 64}), "another Proxy build"),
    (lambda r: r.model_copy(update={"subset_id": "semantic.other"}), "another subset"),
    (lambda r: r.model_copy(update={"replay_result": r.replay_result.model_copy(
        update={"semantic_verdict": ReplayVerdict.DIVERGED})}), "not the judgment"),
    (lambda r: r.model_copy(update={"judge_input": r.judge_input.model_copy(
        update={"evidence_verified": False})}), "not verified"),
])
def test_run_problems(build, run, change, problem):
    assert any(problem in p for p in run_problems(change(run), build, subset()))


def test_a_clean_production_end_is_not_crash_survival(build, run):
    positions = tuple(
        p.model_copy(update={"production": p.production.model_copy(
            update={"termination": Termination.CLEAN})}) for p in run.judge_input.positions)
    data = run.judge_input.model_copy(update={"positions": positions})
    changed = run.model_copy(update={"judge_input": data, "replay_result": evaluate(data)})
    assert "the production side did not end in a guest crash" in run_problems(
        changed, build, subset())


def test_another_build_starts_afresh(build, run, store):
    ref = put_record(store, run)
    promoted = promote(store, build, subset(), (ref,))
    other = build.model_copy(update={"proxy_sha256": "1" * 64})
    with pytest.raises(PromotionRefused, match="promoted afresh"):
        promote(store, other, subset(), (ref,), promoted)
    assert check_runtime(promoted, build) and not check_runtime(promoted, other)
    # The same subset again keeps one entry; a changed definition is refused.
    again = promote(store, build, subset(), (ref,), promoted)
    assert again == promoted
    with pytest.raises(PromotionRefused, match="another definition"):
        promote(store, build, subset(description="changed"), (ref,), promoted)


# ---------------------------------------------------------------- HCAP and Agent use


def _catalog() -> HcapCatalog:
    return HcapCatalog(capabilities=(Capability(
        id="HCAP-02", name="Raw NFS/RPC send", purpose="send", usable_stage=("stage1",),
        usable_by=("agent_stage1",), interface=CapabilityInterface(), status="validated",
        scope=("nfs4",)),), missing_capability_ids=("state_lineage",))


def _intent(message_type="call", op="gt", direction="C2S"):
    return {
        "intent_id": "slot", "targets_baseline_traffic": True,
        "traffic_scope": {"direction": direction, "backend": "knfsd", "client": "c0"},
        "selector": {
            "rpc": {"message_type": message_type, "program": 100003, "version": 4,
                    "procedure": 1},
            "protocol": {"family": "nfs4", "nfs_version": 4, "minor_version": 1},
            "operation": "SEQUENCE",
            "target": {"kind": "field", "path": "nfs4.request.SEQUENCE.args.sa_slotid"},
            "predicates": [{"lhs": {"source": "target"}, "op": op,
                            "rhs": {"kind": "uint", "value": 3}}]},
        "mutation": {"kind": "replace", "structure_policy": "preserve",
                     "transform": {"kind": "literal",
                                   "value": {"kind": "uint", "value": 7}}},
        "expected_effect": {"target_state": "slot", "rationale": "slot"}}


def _rules(*intents) -> MutationRuleSet:
    named = [dict(i, intent_id=f"i{n}") for n, i in enumerate(intents)]
    return MutationRuleSet.model_validate({
        "candidate_id": "VC-1", "intents": named,
        "hypotheses": [{"hypothesis_id": "h", "intents": [i["intent_id"] for i in named],
                        "requirement": "all"}], "uncertainties": []})


def test_promotion_becomes_a_new_hcap_revision_the_agent_reads(build, run, store):
    promoted = promote(store, build, subset(), (put_record(store, run),))
    promoted_ref = put_record(store, promoted)
    catalog = with_semantic_capability(_catalog(), promoted_ref, promoted)
    revision = put_record(store, catalog)
    entry = next(c for c in catalog.capabilities if c.id == "HCAP-10")
    assert (entry.usable_by, entry.status, entry.validated_scope) == (
        ("agent_stage2",), "validated_subset", (subset().subset_id,))
    assert entry.authority_refs[0].artifact_ref == promoted_ref
    assert UNPROMOTED_GAP_ID in catalog.missing_capability_ids
    # The checker verifies every evidence and authority artifact it pins.
    checker = ArtifactHcapChecker(store)
    assert checker.load_catalog(revision) == catalog
    assert promoted_registry(store, catalog) == promoted

    tools = Stage1Toolbox(None, ArtifactHcapSource(checker), kernel_commit=KERNEL,
                          hcap_revision=revision)
    scope = tools.invoke("lookup_semantic_scope", {})
    assert [s.subset_id for s in scope.subsets] == [subset().subset_id]
    assert scope.subsets[0].predicate_ops == ("gt",)
    assert scope.registry_digest == build.registry_digest

    bare = put_record(store, _catalog())
    empty = Stage1Toolbox(None, ArtifactHcapSource(checker), kernel_commit=KERNEL,
                          hcap_revision=bare).invoke("lookup_semantic_scope", {})
    assert empty.subsets == () and empty.registry_digest is None


def test_rule_set_scope(build, run, store):
    promoted = promote(store, build, subset(), (put_record(store, run),))
    assert rule_set_scope(_rules(_intent()), promoted).subset_id == subset().subset_id
    for outside in (_intent(message_type="reply"), _intent(op="eq"),
                    _intent(direction="S2C")):
        check = rule_set_scope(_rules(_intent(), outside), promoted)
        assert check.subset_id is None and check.missing_capability_id == UNPROMOTED_GAP_ID
        assert check.problems
    assert rule_set_scope(_rules(_intent()), None).missing_capability_id == \
        UNPROMOTED_GAP_ID


# ---------------------------------------------------------------- operator CLI


def test_cli_records_and_promotes(proxy_binary, build, tmp_path, capsys):
    production = _production(proxy_binary, tmp_path / "production", ONE_RULE)
    plan = plan_replay(SealedJournal(production, "lane0"),
                       parse_crash_context(_crash_log(1), vm_instance_id=VM, bound=4))
    paths = write_replay_inputs(plan, tmp_path / "inputs")
    with pytest.MonkeyPatch.context() as mp:
        _replay(proxy_binary, tmp_path / "replay", plan, [(11, [9, 1]), (12, [8])], mp)
    (tmp_path / "execprog.out").write_text(_barriers(11))
    subset_path = tmp_path / "subset.json"
    subset_path.write_text(json.dumps(subset().model_dump(mode="json")))
    store_dir = tmp_path / "artifacts"

    assert main(["registry", "--proxy", str(proxy_binary), "--store", str(store_dir)]) == 0
    build_ref = capsys.readouterr().out.split()[0].removeprefix("build=")
    assert main([
        "record", "--store", str(store_dir), "--subset", str(subset_path),
        "--proxy", str(proxy_binary), "--kernel-commit", KERNEL,
        "--environment", "kvm_guest", "--plan", str(paths["plan"]),
        "--journal-dir", str(production), "--production-vm", VM,
        "--replay-dir", str(tmp_path / "replay" / "journal"), "--replay-name", "lane0",
        "--replay-vm", VM, "--replay-lane", str(LANE),
        "--execprog-output", str(tmp_path / "execprog.out"),
        "--production-end", "guest_crash", "--replay-end", "guest_crash"]) == 0
    run_ref = capsys.readouterr().out.split()[0].removeprefix("run=")
    store = ArtifactStore(store_dir)
    hcap_ref = put_record(store, _catalog())
    assert main(["promote", "--store", str(store_dir), "--build", build_ref,
                 "--subset", str(subset_path), "--run", run_ref, "--hcap", hcap_ref]) == 0
    out = dict(item.split("=") for item in capsys.readouterr().out.split())
    catalog = ArtifactHcapChecker(store).load_catalog(out["hcap_revision"])
    assert promoted_registry(store, catalog).subsets[0].evidence_refs == (run_ref,)
    assert canonical_json(load_record(store, build_ref, type(build))) == canonical_json(build)

    # A wider subset over the same run is refused, and nothing is written.
    subset_path.write_text(json.dumps(subset(predicate_ops=("eq", "gt")).model_dump(
        mode="json")))
    assert main(["promote", "--store", str(store_dir), "--build", build_ref,
                 "--subset", str(subset_path), "--run", run_ref, "--hcap", hcap_ref]) == 3
