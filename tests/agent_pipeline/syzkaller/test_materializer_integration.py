"""Real parser to Materializer handoff; host approvals/VM artifacts are fixtures.

These tests neither execute the programs nor validate an NFS capability.
"""

import os
from pathlib import Path

import pytest

from agent_pipeline.admission import (
    CallAdmissionEntry, NeutralControlCatalog, NeutralControlEntry,
    ResourceOriginConstraint, SyzkallerBuildManifest, SyzkallerTargetIdentity,
)
from agent_pipeline.contracts import Materialized, MaterializeRejected
from agent_pipeline.data import load_record, put_record
from agent_pipeline.hcap import AuthorityRef, CapabilityInterface, ProgramProposal
from agent_pipeline.materializer import (
    ArtifactHarnessMaterializer, CALL_NOT_ADMITTED, CALL_UNRESOLVED,
    DISALLOWED_OR_UNAVAILABLE_CALL, ExecutionHarnessApproval,
    MaterializationReviewManifest, ParsedProgram, PROFILE_FIXTURE_ROUTE_MISMATCH,
    StaticExecutionHarnessAuthority, _hcap11_program_error,
    descriptor_id,
)
from agent_pipeline.syzkaller import PinnedSyzParser
from tests.agent_pipeline.test_materializer import world as synthetic_world


LANE_CALL = "syz_open_nfs_lane_profile$client0_knfsd_v41"
LANE = f"r0 = {LANE_CALL}(0x2, 0x0)\n".encode()
REPO = Path(__file__).resolve().parents[3]
#: The validated HCAP-11 stimulus of the courtesy-expiry campaign.
HCAP11 = (REPO / "tools/nfs-lifecycle/programs/"
          "v41-courtesy-expiry.prog").read_bytes()


def _hcap11_edit(old: bytes, new: bytes) -> bytes:
    assert HCAP11.count(old) == 1, old
    return HCAP11.replace(old, new)


PARTITION = b"syz_nfs_lane_link$partition_client0(0x0, 0x0)\n"
HEAL = b"syz_nfs_lane_link$heal_client0(0x0, 0x1)\n"
CLIENT1_OPEN = (b"r3 = syz_open_nlm_lane_file(r2, &(0x7f0000000000)="
                b"'lock0\\x00', 0x2)\n")


@pytest.mark.parametrize("program,reason", [
    (LANE + b"fsync(r0)\n", None),
    (LANE + b"fsync(r0+1)\n", CALL_NOT_ADMITTED),
    (b"r0 = syz_open_nfs_lane_profile$client0_knfsd_v42(0x3, 0x0)\n"
     b"fsync(r0)\n", PROFILE_FIXTURE_ROUTE_MISMATCH),
    # Bridge refusals keep their typed reason and offending call.
    (LANE + b"clone3(0x0, 0x0)\n", DISALLOWED_OR_UNAVAILABLE_CALL),
    (LANE + b"syz_not_in_build()\n", CALL_UNRESOLVED),
    (LANE + b"syz_socket_connect_nfs$client0(0x0)\n", PROFILE_FIXTURE_ROUTE_MISMATCH),
])
def test_real_parser_materializer_handoff(tmp_path, program, reason):
    value = os.environ.get("KNFSD_SYZ_BUNDLE")
    if not value:
        pytest.skip("build the pinned Go bridge and set KNFSD_SYZ_BUNDLE")
    bundle = Path(value)
    identity = SyzkallerTargetIdentity.model_validate_json(
        (bundle / "identity.json").read_bytes())
    world = synthetic_world.__wrapped__(tmp_path)
    store = world.store
    manifest_bytes = (bundle / "build-manifest.json").read_bytes()
    manifest = SyzkallerBuildManifest.model_validate_json(manifest_bytes)
    assert store.put(manifest_bytes) == identity.build_manifest_sha256
    assert store.put((bundle / "call-table.json").read_bytes()) == identity.call_table_sha256
    assert store.put((bundle / "patch-series.bin").read_bytes()) == identity.patch_series_sha256
    for artifact in manifest.files:
        assert store.put((bundle / artifact.path).read_bytes()) == artifact.artifact_ref

    selection = world.runtime.model_copy(update={
        "enabled_interfaces": tuple(sorted(("remote_cover", LANE_CALL))),
    })
    profile = world.profile.model_copy(update={
        "identity": identity,
        "entries": (
            CallAdmissionEntry(call="fsync", capability_ids=("CAP-lane",),
                resource_constraints=(ResourceOriginConstraint(
                    argument_index=0, resource_type="fd",
                    allowed_origins=("nfs-profile:knfsd-v41:client0",)),)),
            CallAdmissionEntry(call=LANE_CALL, capability_ids=("CAP-lane",)),
        ),
    })
    profile_ref = put_record(store, profile)
    neutral_ref = store.put(LANE)
    neutral = NeutralControlCatalog(
        identity=identity, call_admission_profile_ref=profile_ref,
        entries=(NeutralControlEntry(runtime_selection=selection,
            program_ref=neutral_ref, required_capability_ids=("CAP-lane",)),))
    neutral_catalog_ref = put_record(store, neutral)
    capabilities = tuple(cap.model_copy(update={
        "status": "experimental",
        "interface": CapabilityInterface(syz_calls=("fsync", LANE_CALL)),
    }) if cap.id == "CAP-lane" else cap for cap in world.hcap.capabilities)
    hcap = world.hcap.model_copy(update={
        "capabilities": capabilities,
        "authority_refs": (
            AuthorityRef(kind="CallAdmissionProfile", artifact_ref=profile_ref),
            AuthorityRef(kind="NeutralControlCatalog", artifact_ref=neutral_catalog_ref),
        ),
    })
    hcap_ref = put_record(store, hcap)
    program_ref = store.put(program)
    plan = world.plan.model_copy(update={
        "hcap_revision": hcap_ref,
        "runtime_selection": selection,
        "program_proposal": ProgramProposal(kind="program", artifact_ref=program_ref),
        "capability_uses": tuple(use.model_copy(update={
            "status": "experimental", "unvalidated_scope": ("lane",),
        }) if use.capability_id == "CAP-lane" else use
            for use in world.plan.capability_uses),
    })
    descriptor = world.descriptor.model_copy(update={
        "syzkaller_identity": identity, "allowed_runtime_selections": (selection,),
    })
    binding = world.binding.model_copy(update={
        "hcap_revision": hcap_ref, "execution_harness_id": descriptor_id(descriptor),
    })
    builds = StaticExecutionHarnessAuthority((ExecutionHarnessApproval(
        descriptor=descriptor, approved_hcap_revisions=(hcap_ref,)),))
    with PinnedSyzParser(bundle, identity=identity) as parser:
        materializer = ArtifactHarnessMaterializer(store, builds, parser)
        result = materializer.materialize(put_record(store, plan), binding)

    if reason is not None:
        assert isinstance(result, MaterializeRejected), result
        assert result.reason == reason
        if reason == CALL_NOT_ADMITTED:
            assert "resource_constraint_unverified" in result.detail
        if b"clone3" in program:
            assert result.detail == "scenario:1:clone3:disabled"
        if b"syz_not_in_build" in program:
            assert result.detail == "scenario:1:syz_not_in_build"
        if b"syz_socket_connect_nfs" in program:
            assert result.detail == ("scenario:1:syz_socket_connect_nfs$client0:"
                                     "nfs_acquisition_unverified")
        return
    assert isinstance(result, Materialized), result
    review = load_record(store, result.review_manifest_sha256, MaterializationReviewManifest)
    scenario = load_record(store, review.scenario_parser_result_ref, ParsedProgram)
    control = load_record(store, review.neutral_parser_result_ref, ParsedProgram)
    assert scenario.identity == control.identity == identity
    assert scenario.program_sha256 == program_ref
    assert control.program_sha256 == neutral_ref
    assert tuple(call.call for call in scenario.calls) == (LANE_CALL, "fsync")
    assert review.selected_capability_ids == ("CAP-lane",)


@pytest.mark.parametrize(("program", "reason"), [
    (HCAP11, None),
    (_hcap11_edit(PARTITION, b""), "partition_count"),
    (_hcap11_edit(HEAL, b""), "heal_count"),
    (_hcap11_edit(HEAL, HEAL + HEAL), "heal_count"),
    (_hcap11_edit(PARTITION, b"@").replace(HEAL, PARTITION).replace(
        b"@", HEAL), "heal_precedes_partition"),
    (_hcap11_edit(b"'lock0\\x00', 0x2)\nsyz_nfs_lane_link$partition",
                  b"'lock0\\x00', 0x0)\nsyz_nfs_lane_link$partition"),
     "client0_open_missing"),
    (_hcap11_edit(CLIENT1_OPEN, b"").replace(b"close(r3)\n", b""),
     "client1_conflict_missing"),
    (_hcap11_edit(CLIENT1_OPEN, CLIENT1_OPEN + b"fsync(r0)\n"),
     "client0_io_while_partitioned"),
    (_hcap11_edit(b"statx(r0,", b"statx(r2,").replace(
        b"getdents64(r0,", b"getdents64(r2,"), "client0_recovery_io_missing"),
    (_hcap11_edit(b"syz_open_nfs_lane_profile$client1_knfsd_v41(0x2, 0x1)",
                  b"syz_open_nfs_lane_profile$client1_knfsd_v42(0x3, 0x1)"),
     "non_v41_lane_acquisition"),
])
def test_real_parser_hcap11_program_contract(program, reason):
    value = os.environ.get("KNFSD_SYZ_BUNDLE")
    if not value:
        pytest.skip("build the pinned Go bridge and set KNFSD_SYZ_BUNDLE")
    bundle = Path(value)
    identity = SyzkallerTargetIdentity.model_validate_json(
        (bundle / "identity.json").read_bytes())
    with PinnedSyzParser(bundle, identity=identity) as parser:
        parsed_program = parser.parse(program, identity=identity)
    assert _hcap11_program_error(parsed_program) == reason
