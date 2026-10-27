"""Synthetic contract tests; no production catalog, VM or syz admission.

The authority/evidence/program bytes below deliberately do not constitute
runtime validation or usable CallAdmissionProfile/remote-KCOV artifacts.
"""

from __future__ import annotations

import copy
import hashlib
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.components import HcapChecker
from agent_pipeline.contracts import CandidateLocation
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.hcap import (STAGE1_LAYOUT, ArtifactHcapChecker,
                                 ExecutionLayout, HcapCatalog, ReachabilityPlan,
                                 calls_in_layout, layout_refusals)


@pytest.fixture
def synthetic(tmp_path):
    store = ArtifactStore(tmp_path / "synthetic-artifacts")
    evidence = store.put(b"SYNTHETIC ONLY: no runtime evidence")
    admission = store.put(b"SYNTHETIC ONLY: not a CallAdmissionProfile")
    boundary = store.put(b"SYNTHETIC ONLY: not a support boundary")
    program = store.put(b"SYNTHETIC ONLY: intentionally not a syz program")
    catalog = HcapCatalog.model_validate_json(canonical_json({
        "capabilities": [{
            "id": "TEST-lane",
            "name": "Synthetic lane",
            "purpose": "Exercise declarations without a runtime",
            "usable_stage": ["stage1"],
            "usable_by": ["agent_stage1"],
            "interface": {
                "syz_calls": ["synthetic_lane_open"],
                "host_tooling": ["synthetic-host-helper"],
            },
            "status": "validated_subset",
            "scope": ["lane-basic", "profile-open"],
            "validated_scope": ["lane-basic"],
            "evidence_refs": [evidence],
            "authority_refs": [{
                "kind": "CallAdmissionProfile", "artifact_ref": admission}],
        }, {
            "id": "TEST-remote",
            "name": "Synthetic coverage",
            "purpose": "Exercise a Q1 declaration",
            "usable_stage": ["stage1", "stage2"],
            "usable_by": ["agent_stage1", "agent_stage2"],
            "interface": {"runtime_features": ["remote_cover"]},
            "status": "validated",
            "scope": ["generation-coverage"],
            "authority_refs": [{
                "kind": "RemoteKcovSupportBoundary", "artifact_ref": boundary}],
        }],
        "authority_refs": [{
            "kind": "CallAdmissionProfile", "artifact_ref": admission}],
        "missing_capability_ids": [
            "state_lineage", "remote_kcov.context.synthetic_worker",
            "remote_kcov.kernel_revision." + "a" * 40,
            "neutral_control.synthetic-v41",
        ],
    }))
    revision = put_record(store, catalog)
    plan = ReachabilityPlan.model_validate_json(canonical_json({
        "candidate_id": "synthetic-candidate",
        "hcap_revision": revision,
        "selected_path": {
            "entry_surface": "synthetic lane",
            "path_summary": "Illustrate contract use, not kernel execution",
        },
        "nfs_version": "4.1",
        "scenario_steps": [{
            "capability_id": "TEST-lane",
            "action": "Describe synthetic acquisition",
            "parameters": {"client": 0},
            "expected_state_change": "synthetic state",
        }],
        "required_capabilities": ["TEST-lane", "TEST-remote"],
        "capability_uses": [{
            "capability_id": "TEST-lane",
            "status": "validated_subset",
            "scope": ["lane-basic"],
        }, {
            "capability_id": "TEST-remote",
            "status": "validated",
            "scope": ["generation-coverage"],
        }],
        "q1_observation": {
            "target": {
                "kind": "function", "path": "fs/nfsd/synthetic.c",
                "symbol": "synthetic_target", "start_line": 1, "end_line": 3,
            },
            "expected_context": "synthetic_worker",
            "capability_id": "TEST-remote",
        },
        "program_proposal": {"kind": "program", "artifact_ref": program},
        "runtime_selection": {
            "profile": "synthetic-v41", "nfs_version": "4.1",
            "fixture_mode": "single", "route": "synthetic-direct",
            "topology": "synthetic-one-lane",
            "enabled_interfaces": ["synthetic_lane_open", "remote_cover"],
        },
        "execution_constraints": [{"description": "Synthetic constraint"}],
        "uncertainties": ["No actual execution has been tested"],
    }))
    return SimpleNamespace(
        store=store, catalog=catalog, revision=revision, plan=plan,
        plan_ref=put_record(store, plan), checker=ArtifactHcapChecker(store),
        evidence=evidence, admission=admission, boundary=boundary, program=program)


def plan_data(synthetic):
    return synthetic.plan.model_dump(mode="json")


def catalog_data(synthetic):
    return synthetic.catalog.model_dump(mode="json")


def check(synthetic, *, plan=None, catalog=None):
    """Keep malformed inputs malformed; the checker, not this helper, parses."""
    revision = synthetic.revision
    if catalog is not None:
        revision = synthetic.store.put(canonical_json(catalog))
    plan = copy.deepcopy(plan if plan is not None else plan_data(synthetic))
    plan["hcap_revision"] = revision
    ref = synthetic.store.put(canonical_json(plan))
    return synthetic.checker.check_plan(ref, revision)


def test_canonical_revision_and_q1_adapter_api(synthetic):
    checker: HcapChecker = synthetic.checker
    assert checker.check_plan(synthetic.plan_ref, synthetic.revision).ok
    assert synthetic.revision == hashlib.sha256(
        canonical_json(synthetic.catalog)).hexdigest()
    assert synthetic.checker.load_catalog(synthetic.revision) == synthetic.catalog
    plan = load_record(synthetic.store, synthetic.plan_ref, ReachabilityPlan)
    assert plan.candidate_id == "synthetic-candidate"
    assert isinstance(plan.q1_observation.target, CandidateLocation)
    assert plan.q1_observation.target.symbol == "synthetic_target"
    assert plan.q1_observation.expected_context == "synthetic_worker"
    assert put_record(synthetic.store, plan) == synthetic.plan_ref
    # The program/authorities are intentionally unusable at runtime. Passing
    # this declaration check must never be represented as program admission.
    assert synthetic.store.get(plan.program_proposal.artifact_ref).startswith(
        b"SYNTHETIC ONLY")


@pytest.mark.parametrize("context", [
    "a", "synthetic_worker", "worker2", "nfsd.worker", "nfsd.v4_1.worker2",
])
def test_expected_context_accepts_q1_names_and_dotted_names(synthetic, context):
    plan = plan_data(synthetic)
    plan["q1_observation"]["expected_context"] = context
    assert check(synthetic, plan=plan).ok
    ref = synthetic.store.put(canonical_json(plan))
    loaded = load_record(synthetic.store, ref, ReachabilityPlan)
    assert loaded.q1_observation.expected_context == context


@pytest.mark.parametrize("context", [
    "synthetic-worker", "Worker", "0worker", "_worker", "worker/path",
    "worker:context", "worker..task", "worker.", ".worker", "worker.Task",
    "worker.1task", "", " worker", "worker\n", "worker.é",
])
def test_expected_context_rejects_names_q1_cannot_consume(synthetic, context):
    plan = plan_data(synthetic)
    plan["q1_observation"]["expected_context"] = context
    with pytest.raises(ValidationError) as error:
        ReachabilityPlan.model_validate_json(canonical_json(plan))
    assert error.value.errors()[0]["loc"] == (
        "q1_observation", "expected_context")
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


def test_machine_readable_schema_and_frozen_records(synthetic):
    for model in (HcapCatalog, ReachabilityPlan):
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert canonical_json(schema)
    with pytest.raises(ValidationError):
        synthetic.catalog.schema_version = "hcap.other"


def test_replay_is_deterministic(synthetic):
    first = synthetic.checker.check_plan(synthetic.plan_ref, synthetic.revision)
    for _ in range(3):
        again = ArtifactHcapChecker(synthetic.store)
        assert again.check_plan(synthetic.plan_ref, synthetic.revision) == first


def test_revision_must_match_binding(synthetic):
    plan = plan_data(synthetic)
    plan["hcap_revision"] = "f" * 64
    ref = synthetic.store.put(canonical_json(plan))
    assert synthetic.checker.check_plan(ref, synthetic.revision).violations == (
        "hcap_revision_mismatch",)


def test_required_capability_must_exist_not_just_be_a_gap_id(synthetic):
    catalog = catalog_data(synthetic)
    catalog["capabilities"].pop(0)
    catalog["missing_capability_ids"].append("TEST-lane")
    result = check(synthetic, catalog=catalog)
    assert "unknown_capability:TEST-lane" in result.violations


@pytest.mark.parametrize("consumers", [[], ["manual_legacy_campaigns"],
                                      ["agent_stage2"]])
def test_no_agent_stage1_consumer_is_refused(synthetic, consumers):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0]["usable_by"] = consumers
    assert "not_usable_by_agent_stage1:TEST-lane" in check(
        synthetic, catalog=catalog).violations


def test_legacy_missing_usable_by_fails_closed(synthetic):
    catalog = catalog_data(synthetic)
    del catalog["capabilities"][0]["usable_by"]
    assert check(synthetic, catalog=catalog).violations == ("invalid_hcap_artifact",)
    ref = synthetic.store.put(canonical_json(catalog))
    assert not synthetic.checker.knows_capability(ref, "state_lineage")


def test_functional_stage_is_also_checked(synthetic):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0]["usable_stage"] = ["stage2"]
    assert "not_usable_in_stage1:TEST-lane" in check(
        synthetic, catalog=catalog).violations


@pytest.mark.parametrize("status,scope,unvalidated,accepted", [
    ("validated", "lane-basic", [], True),
    ("validated", "profile-open", [], True),
    ("validated", "lane-basic", ["lane-basic"], False),
    ("validated_subset", "lane-basic", [], True),
    ("validated_subset", "profile-open", [], False),
    ("validated_subset", "profile-open", ["profile-open"], True),
    ("partially_validated", "lane-basic", [], False),
    ("partially_validated", "lane-basic", ["lane-basic"], True),
    ("partially_validated", "profile-open", ["profile-open"], True),
    ("experimental", "lane-basic", [], False),
    ("experimental", "lane-basic", ["lane-basic"], True),
    ("experimental", "profile-open", ["profile-open"], True),
])
def test_status_and_scope_opt_in(synthetic, status, scope, unvalidated, accepted):
    catalog = catalog_data(synthetic)
    cap = catalog["capabilities"][0]
    cap["status"] = status
    if status == "validated":
        cap["validated_scope"] = []
    plan = plan_data(synthetic)
    plan["capability_uses"][0].update(
        status=status, scope=[scope], unvalidated_scope=unvalidated)
    result = check(synthetic, catalog=catalog, plan=plan)
    assert result.ok is accepted
    if not accepted:
        assert result.violations == ("unvalidated_scope_not_explicit:TEST-lane",)


@pytest.mark.parametrize("scope", ["lane-basic.child", "unlisted", "all"])
@pytest.mark.parametrize("status", ["validated", "validated_subset",
                                   "partially_validated", "experimental"])
def test_opt_in_never_invents_scope(synthetic, scope, status):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0].update(status=status)
    if status == "validated":
        catalog["capabilities"][0]["validated_scope"] = []
    plan = plan_data(synthetic)
    plan["capability_uses"][0].update(
        status=status, scope=[scope], unvalidated_scope=[scope])
    assert f"undeclared_scope:TEST-lane:{scope}" in check(
        synthetic, catalog=catalog, plan=plan).violations


def test_status_is_not_inferred_or_upgraded_from_plan(synthetic):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0]["status"] = "experimental"
    plan = plan_data(synthetic)
    plan["capability_uses"][0].update(
        status="validated", unvalidated_scope=["lane-basic"])
    assert "capability_status_mismatch:TEST-lane" in check(
        synthetic, catalog=catalog, plan=plan).violations


def test_mixed_subset_use_requires_exact_unvalidated_labels(synthetic):
    plan = plan_data(synthetic)
    use = plan["capability_uses"][0]
    use.update(scope=["lane-basic", "profile-open"],
               unvalidated_scope=["profile-open"])
    assert check(synthetic, plan=plan).ok
    use["unvalidated_scope"] = ["lane-basic", "profile-open"]
    assert not check(synthetic, plan=plan).ok


@pytest.mark.parametrize("path", [
    (), ("capabilities", 0), ("capabilities", 0, "interface"),
    ("capabilities", 0, "authority_refs", 0), ("authority_refs", 0),
])
def test_unknown_catalog_fields_are_rejected(synthetic, path):
    catalog = catalog_data(synthetic)
    node = catalog
    for key in path:
        node = node[key]
    node["unknown_field"] = "cannot extend support"
    assert check(synthetic, catalog=catalog).violations == ("invalid_hcap_artifact",)


@pytest.mark.parametrize("path", [
    (), ("selected_path",), ("scenario_steps", 0), ("capability_uses", 0),
    ("q1_observation",), ("q1_observation", "target"), ("program_proposal",),
    ("runtime_selection",), ("execution_constraints", 0),
])
def test_unknown_plan_fields_are_rejected(synthetic, path):
    plan = plan_data(synthetic)
    node = plan
    for key in path:
        node = node[key]
    node["unknown_field"] = "not a contract field"
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("field", ["sanitizer", "timeout", "retry_budget",
                                  "resource_limit", "environment", "shell"])
def test_runtime_selection_cannot_carry_operational_policy(synthetic, field):
    plan = plan_data(synthetic)
    plan["runtime_selection"][field] = "untrusted"
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("interface", ["synthetic-host-helper", "unlisted_call"])
def test_host_tooling_and_unknown_interfaces_are_not_runtime_inputs(
        synthetic, interface):
    plan = plan_data(synthetic)
    plan["runtime_selection"]["enabled_interfaces"].append(interface)
    assert check(synthetic, plan=plan).violations == (
        f"interface_not_declared:{interface}",)


def test_no_interface_glob_expansion(synthetic):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0]["interface"]["syz_calls"] = ["synthetic_*"]
    assert "interface_not_declared:synthetic_lane_open" in check(
        synthetic, catalog=catalog).violations


@pytest.mark.parametrize("field", ["scope", "status", "capability_id"])
def test_plan_use_requires_explicit_fields(synthetic, field):
    plan = plan_data(synthetic)
    del plan["capability_uses"][0][field]
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("mutation", [
    "duplicate_capability", "duplicate_vocabulary", "duplicate_authority",
    "conflicting_authority", "cross_capability_conflict", "duplicate_scope",
    "empty_scope", "missing_scope", "wildcard_scope", "empty_validated_subset",
    "undeclared_validated_scope", "partial_scope_with_validated_status",
    "unknown_status", "unknown_consumer", "unknown_authority_kind",
])
def test_invalid_catalog_shapes_fail_closed(synthetic, mutation):
    catalog = catalog_data(synthetic)
    cap = catalog["capabilities"][0]
    if mutation == "duplicate_capability":
        catalog["capabilities"].append(copy.deepcopy(cap))
    elif mutation == "duplicate_vocabulary":
        catalog["missing_capability_ids"].append("state_lineage")
    elif mutation == "duplicate_authority":
        cap["authority_refs"].append(copy.deepcopy(cap["authority_refs"][0]))
    elif mutation == "conflicting_authority":
        cap["authority_refs"][0]["artifact_ref"] = synthetic.boundary
    elif mutation == "cross_capability_conflict":
        catalog["authority_refs"] = []
        catalog["capabilities"][1]["authority_refs"] = [{
            "kind": "CallAdmissionProfile", "artifact_ref": synthetic.boundary}]
    elif mutation == "duplicate_scope":
        cap["scope"].append("lane-basic")
    elif mutation == "empty_scope":
        cap["scope"] = []
    elif mutation == "missing_scope":
        del cap["scope"]
    elif mutation == "wildcard_scope":
        cap["scope"].append("*")
    elif mutation == "empty_validated_subset":
        cap["validated_scope"] = []
    elif mutation == "undeclared_validated_scope":
        cap["validated_scope"] = ["undeclared"]
    elif mutation == "partial_scope_with_validated_status":
        cap["status"] = "validated"
    elif mutation == "unknown_status":
        cap["status"] = "advertised_by_runtime"
    elif mutation == "unknown_consumer":
        cap["usable_by"] = ["everyone"]
    else:
        cap["authority_refs"][0]["kind"] = "UnknownAuthority"
    assert check(synthetic, catalog=catalog).violations == ("invalid_hcap_artifact",)
    ref = synthetic.store.put(canonical_json(catalog))
    assert not synthetic.checker.knows_capability(ref, "state_lineage")


@pytest.mark.parametrize("mutation", [
    "duplicate_required", "duplicate_use", "missing_use", "extra_use",
    "empty_scope", "duplicate_scope", "unrequested_unvalidated_scope",
    "undeclared_step", "undeclared_oracle", "nonremote_oracle",
    "runtime_version_mismatch", "integer_version", "missing_proposal",
    "agent_neutral_program", "string_scope", "numeric_candidate",
])
def test_invalid_plan_shapes_fail_closed(synthetic, mutation):
    plan = plan_data(synthetic)
    use = plan["capability_uses"][0]
    if mutation == "duplicate_required":
        plan["required_capabilities"].append("TEST-lane")
    elif mutation == "duplicate_use":
        plan["capability_uses"].append(copy.deepcopy(use))
    elif mutation == "missing_use":
        plan["capability_uses"].pop(0)
    elif mutation == "extra_use":
        plan["capability_uses"].append(dict(use, capability_id="extra"))
    elif mutation == "empty_scope":
        use["scope"] = []
    elif mutation == "duplicate_scope":
        use["scope"].append("lane-basic")
    elif mutation == "unrequested_unvalidated_scope":
        use["unvalidated_scope"] = ["profile-open"]
    elif mutation == "undeclared_step":
        plan["scenario_steps"][0]["capability_id"] = "extra"
    elif mutation == "undeclared_oracle":
        plan["q1_observation"]["capability_id"] = "extra"
    elif mutation == "nonremote_oracle":
        plan["q1_observation"]["oracle"] = "tracepoint"
    elif mutation == "runtime_version_mismatch":
        plan["runtime_selection"]["nfs_version"] = "4.2"
    elif mutation == "integer_version":
        plan["nfs_version"] = 3
    elif mutation == "missing_proposal":
        del plan["program_proposal"]
    elif mutation == "agent_neutral_program":
        plan["program_proposal"]["neutral_program_ref"] = synthetic.program
    elif mutation == "string_scope":
        use["scope"] = "lane-basic"
    else:
        plan["candidate_id"] = 123
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("missing_id,known", [
    ("state_lineage", True),
    ("remote_kcov.context.synthetic_worker", True),
    ("remote_kcov.kernel_revision." + "a" * 40, True),
    ("neutral_control.synthetic-v41", True),
    ("remote_kcov.kernel_revision." + "b" * 40, False),
    ("remote_kcov.context.unknown-worker", False),
    ("neutral_control.other-profile", False),
    ("remote_kcov.context", False),
    ("TEST-lane", False), ("state_lineage.child", False),
    (" state_lineage", False), ("state_lineage\n", False),
    ("", False), (None, False), (123, False),
])
def test_vocabulary_is_exact_and_revision_owned(synthetic, missing_id, known):
    assert synthetic.checker.knows_capability(
        synthetic.revision, missing_id) is known


@pytest.mark.parametrize("kind", ["catalog", "plan"])
@pytest.mark.parametrize("malformation", [
    "whitespace", "duplicate_key", "missing_default", "nonfinite",
    "out_of_range_number", "invalid_json", "invalid_utf8",
])
def test_noncanonical_or_malformed_artifacts_fail_closed(
        synthetic, kind, malformation):
    payload = catalog_data(synthetic) if kind == "catalog" else plan_data(synthetic)
    data = canonical_json(payload)
    if malformation == "whitespace":
        data += b"\n"
    elif malformation == "duplicate_key":
        data = b'{"schema_version":"shadow",' + data[1:]
    elif malformation == "missing_default":
        del payload["schema_version"]
        data = canonical_json(payload)
    elif malformation == "nonfinite":
        data = b'{"untrusted":NaN,' + data[1:]
    elif malformation == "out_of_range_number":
        data = b'{"untrusted":1e1000,' + data[1:]
    elif malformation == "invalid_json":
        data = b"not json"
    else:
        data = b"\xff"
    ref = synthetic.store.put(data)
    if kind == "catalog":
        assert synthetic.checker.check_plan(
            synthetic.plan_ref, ref).violations == ("invalid_hcap_artifact",)
        assert not synthetic.checker.knows_capability(ref, "state_lineage")
    else:
        assert synthetic.checker.check_plan(
            ref, synthetic.revision).violations == ("invalid_plan_artifact",)


def test_duplicate_nested_json_key_cannot_override_consumer(synthetic):
    data = canonical_json(synthetic.catalog).replace(
        b'"usable_by":["agent_stage1"]',
        b'"usable_by":["manual_legacy_campaigns"],"usable_by":["agent_stage1"]',
        1)
    ref = synthetic.store.put(data)
    assert synthetic.checker.check_plan(
        synthetic.plan_ref, ref).violations == ("invalid_hcap_artifact",)
    assert not synthetic.checker.knows_capability(ref, "state_lineage")


@pytest.mark.parametrize("ref", [None, 123, "", "../outside", "/tmp/artifact",
                                "A" * 64, "a" * 63, "a" * 64 + "\n"])
def test_invalid_references_do_not_reach_store(synthetic, monkeypatch, ref):
    original_get = synthetic.store.get

    def get(sha):
        assert sha != ref
        return original_get(sha)

    monkeypatch.setattr(synthetic.store, "get", get)
    assert synthetic.checker.check_plan(
        synthetic.plan_ref, ref).violations == ("invalid_hcap_artifact",)
    assert not synthetic.checker.knows_capability(ref, "state_lineage")
    assert synthetic.checker.check_plan(
        ref, synthetic.revision).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("dependency", ["revision", "plan_ref", "evidence",
                                      "admission", "boundary", "program"])
@pytest.mark.parametrize("fault", ["missing", "tampered"])
def test_artifacts_and_direct_dependencies_fail_closed_after_success(
        synthetic, dependency, fault):
    assert synthetic.checker.check_plan(synthetic.plan_ref, synthetic.revision).ok
    assert synthetic.checker.knows_capability(synthetic.revision, "state_lineage")
    ref = getattr(synthetic, dependency)
    path = synthetic.store.root / ref[:2] / ref
    if fault == "missing":
        path.unlink()
    else:
        path.write_bytes(b"SYNTHETIC TAMPERING")
    catalog_fault = dependency not in ("plan_ref", "program")
    if fault == "missing":
        # Host availability: propagates so the Controller keeps pending work.
        with pytest.raises(FileNotFoundError):
            synthetic.checker.check_plan(synthetic.plan_ref, synthetic.revision)
    else:
        expected = "invalid_hcap_artifact" if catalog_fault else "invalid_plan_artifact"
        result = synthetic.checker.check_plan(synthetic.plan_ref, synthetic.revision)
        assert result.violations == (expected,)
        # Only a corrupt host catalog is a host failure, not a plan finding.
        assert result.host_authority == catalog_fault
    if catalog_fault:
        assert not synthetic.checker.knows_capability(synthetic.revision, "state_lineage")
        with pytest.raises((OSError, ValueError)):
            synthetic.checker.load_catalog(synthetic.revision)


def test_public_loader_raises_for_invalid_or_absent_catalog(synthetic):
    with pytest.raises(ValueError):
        synthetic.checker.load_catalog("not-a-digest")
    with pytest.raises(FileNotFoundError):
        synthetic.checker.load_catalog("f" * 64)


def test_io_failure_propagates_and_is_not_a_plan_finding(synthetic, monkeypatch):
    def unreadable(_):
        raise PermissionError("synthetic read failure")

    monkeypatch.setattr(synthetic.store, "get", unreadable)
    with pytest.raises(PermissionError):
        synthetic.checker.check_plan(synthetic.plan_ref, synthetic.revision)
    assert not synthetic.checker.knows_capability(synthetic.revision, "state_lineage")


def test_seed_declaration_requires_pinned_provenance_but_not_admission(synthetic):
    plan = plan_data(synthetic)
    plan["program_proposal"]["kind"] = "seed"
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)
    manifest = synthetic.store.put(b"SYNTHETIC ONLY: not a seed manifest")
    plan["program_proposal"].update(
        seed_manifest_ref=manifest, seed_id="synthetic-seed")
    assert check(synthetic, plan=plan).ok
    path = synthetic.store.root / manifest[:2] / manifest
    path.write_bytes(b"SYNTHETIC TAMPERING")
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize("missing", ["program", "manifest", "both"])
def test_missing_agent_proposed_seed_is_a_plan_finding(synthetic, missing):
    """An existing seed is an Agent-proposed reference: one that does not
    exist goes to repair, unlike a missing host artifact."""
    plan = plan_data(synthetic)
    manifest = synthetic.store.put(b"SYNTHETIC ONLY: seed manifest")
    plan["program_proposal"].update(
        kind="seed", seed_manifest_ref=manifest, seed_id="synthetic-seed")
    assert check(synthetic, plan=plan).ok
    absent = "f" * 64
    if missing in ("program", "both"):
        plan["program_proposal"]["artifact_ref"] = absent
    if missing in ("manifest", "both"):
        plan["program_proposal"]["seed_manifest_ref"] = "e" * 64
    result = check(synthetic, plan=plan)
    assert result.violations == ("seed_reference_not_found",)
    assert not result.host_authority


def test_program_cannot_claim_seed_provenance(synthetic):
    plan = plan_data(synthetic)
    plan["program_proposal"].update(
        seed_manifest_ref=synthetic.evidence, seed_id="synthetic-seed")
    assert check(synthetic, plan=plan).violations == ("invalid_plan_artifact",)


@pytest.mark.parametrize(("layout", "message"), [
    ({"procs": 2, "lanes": [1, 0]}, "sorted and unique"),
    ({"procs": 2, "lanes": [0, 0]}, "sorted and unique"),
    ({"procs": 2, "lanes": [0, 2]}, "outside the layout's procs"),
    ({"procs": 0, "lanes": [0]}, "greater than or equal to 1"),
    ({"procs": 1, "lanes": []}, "at least 1 item"),
])
def test_execution_layout_shape(layout, message):
    with pytest.raises(ValidationError, match=message):
        ExecutionLayout.model_validate(layout)


def test_execution_layout_covers_runs_inside_it():
    # #99: proc i uses lane i, so a run needs every lane below its procs.
    four = ExecutionLayout(procs=4, lanes=(0, 1, 2, 3))
    assert [four.covers(n) for n in (1, 3, 4, 5)] == [True, True, True, False]
    lane0 = ExecutionLayout(procs=4, lanes=(0,))
    assert [lane0.covers(n) for n in (1, 2)] == [True, False]
    assert STAGE1_LAYOUT == ExecutionLayout(procs=1, lanes=(0,))


def test_capability_without_a_layout_is_validated_on_stage1_only(synthetic):
    catalog = HcapCatalog.model_validate_json(
        canonical_json(catalog_data(synthetic)))
    lane = catalog.capabilities[0]
    assert lane.validated_layout is None and lane.layout() == STAGE1_LAYOUT
    entries = [SimpleNamespace(call="synthetic_lane_open",
                               capability_ids=("TEST-lane",)),
               SimpleNamespace(call="synthetic_shared",
                               capability_ids=("TEST-lane", "TEST-remote"))]
    assert calls_in_layout(catalog, entries, 1) == {
        "synthetic_lane_open", "synthetic_shared"}
    assert calls_in_layout(catalog, entries, 2) == set()
    assert layout_refusals(
        catalog, entries, enabled_calls=["synthetic_lane_open", "close"],
        runtime_features=["remote_cover"], procs=2) == [
        "call_outside_validated_layout:synthetic_lane_open",
        "runtime_feature_outside_validated_layout:remote_cover"]
    # One admitting capability that covers the run admits a shared call.
    data = catalog_data(synthetic)
    data["capabilities"][1]["validated_layout"] = {"procs": 2,
                                                   "lanes": [0, 1]}
    wider = HcapCatalog.model_validate_json(canonical_json(data))
    assert calls_in_layout(wider, entries, 2) == {"synthetic_shared"}
    assert layout_refusals(
        wider, entries, enabled_calls=["synthetic_shared"],
        runtime_features=["remote_cover"], procs=2) == []


def test_stage1_plan_needs_a_layout_with_lane_zero(synthetic):
    catalog = catalog_data(synthetic)
    catalog["capabilities"][0]["validated_layout"] = {"procs": 2,
                                                      "lanes": [1]}
    assert "layout_not_validated:TEST-lane" in check(
        synthetic, catalog=catalog).violations
