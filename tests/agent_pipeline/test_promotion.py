"""Promotion criteria (#100)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from agent_pipeline.hcap import (Capability, CapabilityContract, GapContract,
                                 HcapCatalog)
from agent_pipeline.promotion import (ArgumentLeaf, CallShape, CallShapes,
                                      PromotionProbeEvidence,
                                      argument_generality_refusals,
                                      contract_sha256, gap_contract_refusals,
                                      promotion_refusals)
from agent_pipeline.q1 import KernelIdentity

CALL = "syz_nfs_lane_link$partition_client0"


def contract(**change) -> CapabilityContract:
    value = {
        "entry_points": [{"kind": "syz_call", "name": CALL}],
        "boundary_functions": ["nfsd_break_deleg_cb", "nfsd4_exchange_id"],
        **change}
    return CapabilityContract.model_validate_json(json.dumps(value))


def capability(value: CapabilityContract | None = None, **change) -> Capability:
    data = {
        "id": "CAP-new", "name": "partition", "purpose": "test",
        "usable_stage": ["stage1"], "usable_by": ["agent_stage1"],
        "interface": {"syz_calls": [CALL]}, "status": "validated",
        "scope": ["client0_partition"], **change}
    if value is not None:
        data["contract"] = value.model_dump(mode="json")
    return Capability.model_validate_json(json.dumps(data))


def shapes(*leaves: ArgumentLeaf, call: str = CALL) -> CallShapes:
    return CallShapes(syzkaller_commit="a" * 40,
                      calls=(CallShape(call=call, leaves=leaves),))


# --- contract shape -------------------------------------------------------

def test_contract_entry_points_are_the_interface_calls():
    assert capability(contract()).contract.syz_calls() == (CALL,)
    with pytest.raises(ValidationError, match="interface's syz calls"):
        capability(contract(entry_points=[
            {"kind": "syz_call", "name": "close"}]))


def test_contract_fixes_only_its_own_calls():
    with pytest.raises(ValidationError, match="not an entry point"):
        contract(fixed_arguments=[{"call": "close", "path": "fd",
                                   "value": 0}])
    with pytest.raises(ValidationError, match="duplicate boundary"):
        contract(boundary_functions=["f", "f"])
    with pytest.raises(ValidationError):
        contract(boundary_functions=[])


def test_gap_contracts_belong_to_the_vocabulary():
    gap = GapContract(missing_capability_id="lane.partition",
                      contract=contract())
    HcapCatalog(capabilities=(), missing_capability_ids=("lane.partition",),
                gap_contracts=(gap,))
    with pytest.raises(ValidationError, match="outside the vocabulary"):
        HcapCatalog(capabilities=(), missing_capability_ids=(),
                    gap_contracts=(gap,))


def test_a_gap_filler_declares_the_gap_contract():
    catalog = HcapCatalog(
        capabilities=(), missing_capability_ids=("lane.partition",),
        gap_contracts=(GapContract(missing_capability_id="lane.partition",
                                   contract=contract()),))
    assert gap_contract_refusals(catalog, "lane.partition",
                                 capability(contract())) == []
    # A contract narrowed to the candidate's target is not the gap's.
    narrowed = contract(boundary_functions=["nfsd_break_deleg_cb"])
    assert gap_contract_refusals(catalog, "lane.partition",
                                 capability(narrowed)) == [
        "contract_differs_from_gap:lane.partition"]
    assert gap_contract_refusals(catalog, "other", capability(contract())) \
        == ["gap_contract_missing:other"]


# --- argument generality -------------------------------------------------

def test_literals_need_the_contract():
    client = ArgumentLeaf(path="client", literal=True, value=0)
    op = ArgumentLeaf(path="op", literal=True, value=0)
    assert argument_generality_refusals(contract(), shapes(client, op)) == [
        f"literal_argument:{CALL}:client", f"literal_argument:{CALL}:op"]
    fixed = contract(fixed_arguments=[
        {"call": CALL, "path": "client", "value": 0},
        {"call": CALL, "path": "op", "value": 0}])
    assert argument_generality_refusals(fixed, shapes(client, op)) == []
    # The fixed value is the contract's, not the candidate's.
    other = contract(fixed_arguments=[
        {"call": CALL, "path": "client", "value": 1},
        {"call": CALL, "path": "op", "value": 0}])
    assert argument_generality_refusals(other, shapes(client, op)) == [
        f"literal_argument:{CALL}:client",
        f"fixed_argument_not_literal:{CALL}:client"]


def test_open_arguments_and_fixed_types_pass():
    leaves = (ArgumentLeaf(path="fd", literal=False),
              ArgumentLeaf(path="buf.msg.prog", literal=True, value=100003,
                           types=("rpc_nfs41_call_t[42, args]",)),
              ArgumentLeaf(path="name", literal=True,
                           types=("lane_name",)))
    value = contract(fixed_types=["rpc_nfs41_call_t"],
                     fixed_arguments=[{"call": CALL, "path": "name"}])
    assert argument_generality_refusals(value, shapes(*leaves)) == []
    assert argument_generality_refusals(contract(), shapes(*leaves)) == [
        f"literal_argument:{CALL}:buf.msg.prog",
        f"literal_argument:{CALL}:name"]


def test_a_missing_shape_is_refused():
    assert argument_generality_refusals(contract(), shapes(call="close")) == [
        f"call_shape_missing:{CALL}"]


# --- probe campaign -----------------------------------------------------

IDENTITY = KernelIdentity(execution_harness_id="1" * 64,
                          kernel_commit="2" * 40,
                          instrumentation_sha256="3" * 64,
                          vmlinux_sha256="4" * 64,
                          kaslr_enabled=False, kaslr_offset=0)


def evidence(value: CapabilityContract | None = None, **change):
    value = value or contract()
    probes = list(value.boundary_functions)
    data = {
        "schema_version": "promotion-probe-evidence.v1",
        "capability_id": "CAP-new",
        "contract_sha256": contract_sha256(value),
        "observed_at": "2026-10-26",
        "execution_harness_id": IDENTITY.execution_harness_id,
        "mapping_identity": IDENTITY.model_dump(mode="json"),
        "guest_lane_script_sha256": "5" * 64,
        "layout": {"procs": 1, "lanes": [0]},
        "accelerator": "kvm", "exec_slowdown": 1,
        "probes": probes,
        "probe_mapping_sha256": {p: "6" * 64 for p in probes},
        "minimal": {"program_sha256s": ["7" * 64], "runs": 3,
                    "runs_hitting": 3, "probes_hit": probes},
        "generated": {"program_sha256s": ["8" * 64], "runs": 40,
                      "runs_hitting": 10, "probes_hit": probes},
        "neutral": {"program_sha256s": ["9" * 64], "runs": 3,
                    "runs_hitting": 0, "probes_hit": []},
        "generated_without_entry_call": 0, "crash_signature_count": 0,
        "shareable_result_contains_target_metadata_or_addresses": False,
    }
    data.update(change)
    return PromotionProbeEvidence.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(("change", "message"), [
    ({"minimal": {"program_sha256s": ["7" * 64], "runs": 3,
                  "runs_hitting": 2,
                  "probes_hit": ["nfsd_break_deleg_cb", "nfsd4_exchange_id"]}},
     "minimal runs reached the probes"),
    ({"generated": {"program_sha256s": ["8" * 64], "runs": 40,
                    "runs_hitting": 9,
                    "probes_hit": ["nfsd_break_deleg_cb",
                                   "nfsd4_exchange_id"]}},
     "generated runs reached the probes"),
    ({"generated": {"program_sha256s": ["8" * 64], "runs": 31,
                    "runs_hitting": 31,
                    "probes_hit": ["nfsd_break_deleg_cb",
                                   "nfsd4_exchange_id"]}},
     "fewer than 32 generated runs"),
    ({"generated": {"program_sha256s": ["8" * 64], "runs": 40,
                    "runs_hitting": 40, "probes_hit": ["nfsd4_exchange_id"]}},
     "generated runs missed a probe"),
    ({"neutral": {"program_sha256s": ["9" * 64], "runs": 3,
                  "runs_hitting": 1, "probes_hit": ["nfsd4_exchange_id"]}},
     "neutral control run reached a probe"),
    ({"generated_without_entry_call": 1}, "call no entry point"),
    ({"crash_signature_count": 1}, "contains a crash"),
    ({"probe_mapping_sha256": {"nfsd4_exchange_id": "6" * 64}},
     "probe mappings differ"),
    ({"execution_harness_id": "0" * 64}, "harness identities differ"),
])
def test_probe_campaign_thresholds(change, message):
    with pytest.raises(ValidationError, match=message):
        evidence(**change)


def test_promotion_needs_a_contract_and_its_campaign():
    assert promotion_refusals(capability(), [evidence()]) == [
        "contract_missing"]
    assert promotion_refusals(capability(contract()), []) == [
        "promotion_evidence_missing"]
    assert promotion_refusals(capability(contract()), [evidence()]) == []


def test_probes_are_the_contract_boundary():
    # Evidence probing only the candidate's target is another contract.
    narrowed = contract(boundary_functions=["nfsd_break_deleg_cb"])
    assert promotion_refusals(capability(contract()), [evidence(narrowed)]) \
        == ["promotion_evidence_contract_mismatch",
            "probes_not_contract_boundary"]


def test_time_dependent_capabilities_need_kvm():
    timed = contract(time_dependent=True)
    assert promotion_refusals(capability(timed),
                              [evidence(timed, accelerator="tcg",
                                        exec_slowdown=10)]) == [
        "time_dependent_needs_kvm"]
    assert promotion_refusals(capability(timed), [
        evidence(timed, accelerator="tcg", exec_slowdown=10),
        evidence(timed)]) == []
    assert promotion_refusals(capability(contract()), [
        evidence(accelerator="tcg", exec_slowdown=10)]) == []
