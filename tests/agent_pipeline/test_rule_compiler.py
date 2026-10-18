"""Mutation Rule Compiler (08 §12, 03-nfs-proxy/04 §19, §35) against the
built Proxy.

The promoted registry here is written directly, not by the M7 gate: these
tests check lowering, binding and refusal routing, and a subset promoted
for real comes only from KVM evidence (``semantic_promotion promote``).
"""

from __future__ import annotations

import hashlib

import pytest

from agent_pipeline.agent_tasks.mutation import MutationRuleSet
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import (COMPILER_AGENT_FIXABLE, CompileRejected,
                                      CompiledRuleSet)
from agent_pipeline.data import put_record
from agent_pipeline.hcap import (Capability, CapabilityInterface, HcapCatalog,
                                 Q1Observation, RuntimeSelection)
from agent_pipeline.materializer import ReachabilityHarness
from agent_pipeline.protocol_schema import (Resolution, SN_OPERATION,
                                            load_schemas)
from agent_pipeline.rule_compiler import (ArtifactMutationRuleCompiler,
                                          CompilerUnavailable, _Deps,
                                          _Lowered, _check, encode_rule_set,
                                          load_compiled)
from agent_pipeline.semantic_promotion import (
    UNPROMOTED_GAP_ID, PromotedSemanticCapabilityRegistry, PromotedSubset,
    SemanticSubset, describe_rule_set, read_build_registry, required_items,
    with_semantic_capability)

from . import test_journal_live as live_mod
from .fakes import binding, sha
from .test_journal_live import _build_proxy

pytestmark = live_mod.pytestmark

NFS41 = next(s for s in load_schemas().values() if s.minor == 1)
CANDIDATE = "VC-compile"


@pytest.fixture(scope="module")
def proxy(tmp_path_factory):
    return _build_proxy(tmp_path_factory)


@pytest.fixture(scope="module")
def build(proxy):
    return read_build_registry(proxy)


def subset(**over) -> SemanticSubset:
    data = dict(
        subset_id="semantic.nfs4_1.test", description="host test subset",
        schema_ids=(NFS41.schema_id,), directions=("C2S", "S2C"),
        message_types=("call", "reply"), target_kinds=("field",),
        parts=("metadata:count", "value"), mutation_kinds=("replace",),
        transforms=("copy", "literal"), structure_policies=("preserve", "raw"),
        value_sources=("current_message", "request_forwarded",
                       "request_original", "target"),
        predicate_ops=("eq", "gt", "ne"))
    data.update(over)
    return SemanticSubset(**data)


def harness(*routes: str, nfs_version: str = "4.1") -> ReachabilityHarness:
    routes = routes or ("client0_knfsd_v41",)
    return ReachabilityHarness(
        candidate_id=CANDIDATE, plan_ref=sha("plan"), program_kind="program",
        program_ref=sha("program"), neutral_program_ref=sha("neutral"),
        runtime_selection=RuntimeSelection(
            profile="knfsd-v41", nfs_version=nfs_version,
            fixture_mode="single", route="direct", topology="one-lane",
            enabled_interfaces=("remote_cover", *(
                f"syz_open_nfs_lane_profile${r}" for r in routes))),
        required_capability_ids=("HCAP-01",),
        selected_capability_ids=("HCAP-01",),
        q1_observation=Q1Observation(
            target={"kind": "function", "path": "fs/nfsd/nfs4state.c",
                    "symbol": "target", "start_line": 1, "end_line": 2},
            expected_context="nfsd", capability_id="HCAP-01"),
        hcap_revision=sha("hcap"), call_admission_profile_ref=sha("cap"),
        neutral_control_catalog_ref=sha("ncc"),
        execution_harness_id=sha("build-1"),
        scenario_parser_result_ref=sha("spr"),
        neutral_parser_result_ref=sha("npr"),
        review_manifest_sha256=sha("review"))


def _base_catalog() -> HcapCatalog:
    return HcapCatalog(capabilities=(Capability(
        id="HCAP-01", name="lane", purpose="lane", usable_stage=("stage1",),
        usable_by=("agent_stage1",), interface=CapabilityInterface(),
        status="validated", scope=("nfs4",)),),
        missing_capability_ids=("state_lineage",))


class World:
    def __init__(self, tmp_path, proxy, build, the_subset=None, *,
                 the_harness=None, promote=True, promoted_build=None):
        self.store = ArtifactStore(tmp_path / "artifacts")
        catalog = _base_catalog()
        if promote:
            b = promoted_build or build
            s = the_subset or subset()
            promoted = PromotedSemanticCapabilityRegistry(
                proxy_sha256=b.proxy_sha256, registry_digest=b.registry_digest,
                registry=b.registry, subsets=(PromotedSubset(
                    subset=s, validation_items=required_items(s),
                    evidence_refs=(self.store.put(b"guest evidence"),)),))
            catalog = with_semantic_capability(
                catalog, put_record(self.store, promoted), promoted)
        self.binding = binding(hcap=put_record(self.store, catalog))
        self.harness_ref = put_record(self.store, the_harness or harness())
        self.compiler = ArtifactMutationRuleCompiler(
            self.store, proxy, tmp_path / "compile")

    def compile(self, *intents):
        rule_set = MutationRuleSet.model_validate({
            "candidate_id": CANDIDATE,
            "intents": [dict(i, intent_id=i.get("intent_id", f"i{n}"))
                        for n, i in enumerate(intents)],
            "hypotheses": [{"hypothesis_id": "h", "requirement": "all",
                            "intents": [i.get("intent_id", f"i{n}")
                                        for n, i in enumerate(intents)]}],
            "uncertainties": []})
        return self.compiler.compile(put_record(self.store, rule_set),
                                     self.harness_ref, self.binding)


def _apply(value: dict, **over) -> dict:
    """Set ``a__b__c`` keys in a nested intent."""
    for key, v in over.items():
        node = value
        *parents, leaf = key.split("__")
        for p in parents:
            node = node[p]
        node[leaf] = v
    return value


def call_intent(**over) -> dict:
    """SEQUENCE.args.sa_slotid of a CALL: slotid > 3 -> 7, preserve."""
    return _apply({
        "targets_baseline_traffic": True,
        "traffic_scope": {"direction": "C2S", "backend": "knfsd",
                          "client": "client0"},
        "selector": {
            "rpc": {"message_type": "call", "program": 100003, "version": 4,
                    "procedure": 1},
            "protocol": {"family": "nfs4", "nfs_version": 4,
                         "minor_version": 1},
            "operation": "SEQUENCE",
            "target": {"kind": "field",
                       "path": "nfs4.request.SEQUENCE.args.sa_slotid"},
            "predicates": [{"lhs": {"source": "target"}, "op": "gt",
                            "rhs": {"kind": "uint", "value": 3}}]},
        "mutation": {"kind": "replace", "structure_policy": "preserve",
                     "transform": {"kind": "literal",
                                   "value": {"kind": "uint", "value": 7}}},
        "expected_effect": {"target_state": "slot", "rationale": "slot"}},
        **over)


def reply_intent(**over) -> dict:
    """SEQUENCE.result.ok.sr_slotid of a REPLY, selected on the status, the
    slot the server was asked for and the slot the client sent."""
    return _apply(call_intent(**{
        "traffic_scope__direction": "S2C",
        "selector__rpc__message_type": "reply",
        "selector__target__path": "nfs4.response.SEQUENCE.result.ok.sr_slotid",
        "selector__predicates": [
            {"lhs": {"source": "current_message",
                     "path": "nfs4.response.SEQUENCE.result.sr_status"},
             "op": "eq", "rhs": {"kind": "enum", "name": "NFS4_OK"}},
            {"lhs": {"source": "target"}, "op": "ne",
             "rhs": {"kind": "value_ref", "source": "request_forwarded",
                     "path": "nfs4.request.SEQUENCE.args.sa_slotid"}},
            {"lhs": {"source": "request_original",
                     "path": "nfs4.request.SEQUENCE.args.sa_slotid"},
             "op": "eq", "rhs": {"kind": "uint", "value": 0}}]}), **over)


def _describe(world, proxy, tmp_path, compiled: CompiledRuleSet):
    record, blob = load_compiled(world.store, compiled)
    assert hashlib.sha256(blob).hexdigest() == record.nfsprul1_ref
    return record, describe_rule_set(proxy, blob, tmp_path)


# ---------------------------------------------------------------- lowering


def test_call_rule_lowers_to_the_runtime_rule(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build)
    compiled = world.compile(call_intent(intent_id="slot"))
    assert isinstance(compiled, CompiledRuleSet)
    assert compiled.hcap_revision == world.binding.hcap_revision
    record, described = _describe(world, proxy, tmp_path, compiled)
    assert (record.schema_id, record.subset_id, record.candidate_id) == (
        NFS41.schema_id, "semantic.nfs4_1.test", CANDIDATE)
    assert [(r.rule_id, r.intent_id) for r in record.rules] == [("r000", "slot")]
    assert record.proxy_sha256 == build.proxy_sha256
    rule = described.rules[0]
    assert (rule.rule_id, rule.intent_id, rule.direction, rule.message_type,
            rule.procedure, rule.operation, rule.target_path, rule.kind,
            rule.transform, rule.structure_policy, rule.predicate_ops) == (
        "r000", "slot", "C2S", "call", 1, "SEQUENCE",
        "nfs4.request.SEQUENCE.args.sa_slotid", "replace", "literal",
        "preserve", ("gt",))


def test_compiling_is_a_pure_function(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build)
    first = world.compile(call_intent(), reply_intent())
    again = world.compile(call_intent(), reply_intent())
    assert isinstance(first, CompiledRuleSet) and first == again


def test_reply_rule_binds_enums_and_request_views(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build)
    compiled = world.compile(reply_intent())
    assert isinstance(compiled, CompiledRuleSet)
    _, described = _describe(world, proxy, tmp_path, compiled)
    rule = described.rules[0]
    assert rule.value_sources == ("current_message", "request_forwarded",
                                  "request_original", "target")
    # The runtime accepted the set, so the derived context dependencies are
    # exactly its own (dependencies_mismatch would have raised).  NFS4_OK is
    # nfsstat4's 0.
    _, blob = load_compiled(world.store, compiled)
    assert b"nfs4.request.SEQUENCE.args.sa_slotid" in blob


def test_rules_ascend_in_intent_order(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build)
    intents = [call_intent(intent_id=f"z{n}") for n in range(12)]
    record, _ = _describe(world, proxy, tmp_path, world.compile(*intents))
    assert [r.rule_id for r in record.rules] == [f"r{n:03d}" for n in range(12)]
    assert [r.intent_id for r in record.rules] == [f"z{n}" for n in range(12)]


def test_traffic_scope_binds_to_the_proxy_words(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build,
                  the_harness=harness("client1_ganesha_v41"))
    compiled = world.compile(call_intent(
        traffic_scope={"direction": "C2S", "backend": "ganesha",
                       "client": "client1"}))
    _, blob = load_compiled(world.store, compiled)
    # Header, then rule_id "r000" and intent_id "i0", each a padded string,
    # then direction, backend and client.
    at = 8 + 4 + 4 + len(NFS41.schema_id) + (-len(NFS41.schema_id) % 4) \
        + 4 + len(CANDIDATE) + (-len(CANDIDATE) % 4) + 4 + 8 + 8
    assert blob[at:at + 12] == bytes.fromhex("00000000" "00000001" "00000001")


# ---------------------------------------------------------------- refusals


@pytest.mark.parametrize("over, reason", [
    ({"selector__target__path": "nfs4.request.SEQUENCE.args.no_such"},
     "unknown_path"),
    ({"selector__target__path": "nfs4.response.SEQUENCE.result.ok.sr_slotid"},
     "message_type_inconsistent"),
    ({"selector__predicates": [{"lhs": {"source": "request_forwarded",
                                        "path": "nfs4.request.SEQUENCE.args.sa_slotid"},
                                "op": "eq", "rhs": {"kind": "uint", "value": 1}}]},
     "message_type_inconsistent"),
    ({"traffic_scope__client": "client1"}, "selector_mismatch"),
    ({"traffic_scope__backend": "nfs-server"}, "selector_mismatch"),
    ({"selector__protocol__minor_version": 2}, "selector_mismatch"),
    ({"selector__operation": "OPEN"}, "selector_mismatch"),
    ({"selector__rpc__version": 3}, "selector_mismatch"),
    ({"mutation__transform": {"kind": "literal",
                              "value": {"kind": "int", "value": 7}}},
     "type_mismatch"),
    ({"selector__predicates": [{"lhs": {"source": "target"}, "op": "eq",
                                "rhs": {"kind": "enum", "name": "NFS4_OK"}}]},
     "type_mismatch"),
    ({"selector__target__part": "metadata:count"}, "type_mismatch"),
])
def test_agent_fixable_refusals(tmp_path, proxy, build, over, reason):
    world = World(tmp_path, proxy, build)
    r = world.compile(call_intent(**over, intent_id="bad"))
    assert isinstance(r, CompileRejected), r
    assert (r.reason, r.intent_id, r.missing_capability_id) == (
        reason, "bad", None), r.detail
    assert r.reason in COMPILER_AGENT_FIXABLE


def test_an_enum_name_of_another_enum_is_refused(tmp_path, proxy, build):
    # OPEN4_NOCREATE is opentype4's 0, the same word as NFS4_OK: binding by
    # the compared value's own enum is what refuses it.
    world = World(tmp_path, proxy, build)
    preds = reply_intent()["selector"]["predicates"]
    preds[0]["rhs"]["name"] = "OPEN4_NOCREATE"
    r = world.compile(reply_intent(selector__predicates=preds))
    assert (r.reason, "OPEN4_NOCREATE" in r.detail) == ("type_mismatch", True)


@pytest.mark.parametrize("mutation", [
    {"kind": "replace", "structure_policy": "preserve",
     "transform": {"kind": "builtin", "transform_id": "integer_xor",
                   "args": [{"kind": "uint", "value": 1}]}},
    {"kind": "delete", "structure_policy": "raw"},
])
def test_what_the_runtime_cannot_apply_is_a_gap(tmp_path, proxy, build, mutation):
    world = World(tmp_path, proxy, build)
    r = world.compile(call_intent(mutation=mutation, intent_id="gap"))
    assert (r.reason, r.intent_id, r.missing_capability_id) == (
        "unsupported_capability", "gap", UNPROMOTED_GAP_ID)


def test_an_agent_fixable_refusal_wins_over_an_earlier_gap(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build)
    r = world.compile(
        call_intent(intent_id="gap", mutation={"kind": "delete",
                                               "structure_policy": "raw"}),
        call_intent(intent_id="bad", selector__target__path="nfs4.request.X"))
    assert (r.reason, r.intent_id) == ("unknown_path", "bad")


def test_outside_the_promoted_subset_is_a_gap(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build, subset(directions=("C2S",)))
    r = world.compile(call_intent(), reply_intent())
    assert (r.reason, r.missing_capability_id) == (
        "unsupported_capability", UNPROMOTED_GAP_ID)
    assert "directions 'S2C'" in r.detail


def test_without_promotion_nothing_is_supported(tmp_path, proxy, build):
    world = World(tmp_path, proxy, build, promote=False)
    world.compiler.proxy = tmp_path / "no-such-proxy"     # never run
    r = world.compile(call_intent())
    assert (r.reason, r.missing_capability_id) == (
        "unsupported_capability", UNPROMOTED_GAP_ID)


def test_another_proxy_build_is_not_the_capability(tmp_path, proxy, build):
    other = build.model_copy(update={"proxy_sha256": "1" * 64})
    world = World(tmp_path, proxy, build, promoted_build=other)
    with pytest.raises(CompilerUnavailable, match="not the promoted build"):
        world.compile(call_intent())


def test_a_harness_version_the_build_lacks_is_a_host_fault(tmp_path, proxy, build):
    registry = build.registry.model_copy(update={"schemas": tuple(
        s for s in build.registry.schemas if s.family != "nfs3")})
    narrowed = build.model_copy(update={"registry": registry,
                                        "registry_digest": registry.digest})
    world = World(tmp_path, proxy, build, subset(),
                  the_harness=harness("client0_knfsd_v3", nfs_version="3"),
                  promoted_build=narrowed)
    with pytest.raises(CompilerUnavailable):
        world.compile(call_intent())


# ---------------------------------------------------------------- path resolution


def _paths(s, response: bool) -> list[str]:
    """Paths the schema names, from the procedure and operation roots."""
    out: list[str] = []
    mine = "response" if response else "request"

    def walk(t, prefix, depth):
        out.append(prefix)
        ty = s.types[t]
        if depth > 5 or s._is_ops_union(ty):
            return
        k = ty["kind"]
        if k == "struct":
            for name, c in ty["fields"]:
                walk(c, f"{prefix}.{name}", depth + 1)
        elif k == "union":
            walk(ty["disc"][1], f"{prefix}.{ty['disc'][0]}", depth + 1)
            for a in s._arms(ty):
                if a.get("type") is not None:
                    walk(a["type"], f"{prefix}.{a['component']}", depth + 1)
        elif k in ("array_fixed", "array_var", "optional"):
            walk(ty["sub"], f"{prefix}[]", depth + 1)

    leaf = s.response_leaf if response else s.request_leaf
    for pr in s.procedures:
        rt = pr["res"] if response else pr["arg"]
        if rt is not None:
            walk(rt, f"{s.family}.{mine}.{pr['name']}.{leaf}", 0)
    for t, ty in enumerate(s.types):
        if s._is_ops_union(ty) and ty["operations"] == mine:
            for a in s._arms(ty):
                base = f"{s.family}.{mine}.{a['branch']}"
                out.append(base)
                out.append(f"{base}.{ty['disc'][0]}")
                if a.get("type") is not None:
                    walk(a["type"], f"{base}.{a['component']}", 0)
    return sorted(set(out))


@pytest.mark.parametrize("minor", [None, 1])
def test_path_resolution_agrees_with_the_runtime(tmp_path, proxy, minor):
    """Every path a sample resolves, misses or finds ambiguous in Python,
    the runtime's loader does the same (a delete rule: FOUND reaches the
    mutation check, unsupported_capability)."""
    s = next(x for x in load_schemas().values() if x.minor == minor)
    want = {"found": "unsupported_capability", "not_found": "unknown_path",
            "ambiguous": "ambiguous_path"}
    checked = {}
    for response in (False, True):
        paths = _paths(s, response)
        sample = paths[::max(1, len(paths) // 90)]
        sample += [p + ".nope" for p in sample[::9]] + [p + "[]" for p in sample[::11]]
        for path in sample:
            found, node = s.resolve(response, path)
            intent = MutationRuleSet.model_validate({
                "candidate_id": "c", "uncertainties": [],
                "hypotheses": [{"hypothesis_id": "h", "intents": ["i"],
                                "requirement": "all"}],
                "intents": [{
                    "intent_id": "i", "targets_baseline_traffic": False,
                    "traffic_scope": {"direction": "C2S", "backend": "knfsd",
                                      "client": "client0"},
                    "selector": {
                        "rpc": {"message_type": "reply" if response else "call",
                                "program": s.program, "version": s.version},
                        "protocol": {"family": s.family},
                        "operation": (node.root if node is not None
                                      and node.flags & SN_OPERATION else None),
                        "target": {"kind": "field", "path": path}},
                    "mutation": {"kind": "delete", "structure_policy": "raw"},
                    "expected_effect": {"target_state": "t",
                                        "rationale": "r"}}]}).intents[0]
            rule = _Lowered(rule_id="r", intent=intent, backend=0, client=0,
                            predicates=[], transform_word=None,
                            forwarded=_Deps(fields=set()),
                            original=_Deps(fields=set()))
            status = _check(proxy, tmp_path, encode_rule_set(
                s.schema_id, "c", [rule])).status
            assert status == want[found.value], (path, found, status)
            checked[found] = checked.get(found, 0) + 1
    assert checked[Resolution.FOUND] > 50 and checked[Resolution.NOT_FOUND] > 5
