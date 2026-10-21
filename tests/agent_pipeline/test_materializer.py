"""Synthetic Materializer tests; no production parser, build, or VM exists."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from agent_pipeline.admission import (
    AdmissionLimits,
    BuildFile,
    CallAdmissionEntry,
    CallAdmissionProfile,
    CallResourceFacts,
    NeutralControlCatalog,
    NeutralControlEntry,
    ProgramResourceUsage,
    ResourceOriginConstraint,
    ResourceOriginFact,
    SyzkallerBuildManifest,
    SyzkallerCallTable,
    SyzkallerTargetIdentity,
)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.components import Materializer
from agent_pipeline.contracts import (
    HOST_AUTHORITY_UNAVAILABLE,
    HarnessBinding,
    MaterializationHcapAuthority,
    MaterializeRejected,
    Materialized,
    Sanitizer,
)
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.hcap import (
    ArtifactHcapChecker,
    AuthorityRef,
    Capability,
    CapabilityInterface,
    CapabilityUse,
    HcapCatalog,
    ProgramProposal,
    Q1Observation,
    ReachabilityPlan,
    RuntimeSelection,
    ScenarioStep,
    SelectedPath,
)
from agent_pipeline.materializer import (
    CALL_NOT_ADMITTED,
    CALL_UNRESOLVED,
    DISALLOWED_OR_UNAVAILABLE_CALL,
    INVALID_RUNTIME_SELECTION,
    PARSE_FAILURE,
    PROFILE_FIXTURE_ROUTE_MISMATCH,
    ArtifactHarnessMaterializer,
    ExecutionHarnessApproval,
    ExecutionHarnessDescriptor,
    HCAP11_ORIGIN,
    HCAP11_RECOVERY_IO,
    HarnessBuildArtifact,
    MaterializationReviewManifest,
    NfsAcquisition,
    NormalFlowSeed,
    NormalFlowSeedManifest,
    ParsedCall,
    ParsedProgram,
    ReachabilityHarness,
    StaticExecutionHarnessAuthority,
    SyzParseFailure,
    _Failure,
    _hcap11_program_error,
    _hcap12_program_error,
    descriptor_id,
)


COMMIT = "a" * 40


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def runtime(**updates) -> RuntimeSelection:
    value = {
        "profile": "knfsd-v41",
        "nfs_version": "4.1",
        "fixture_mode": "single",
        "route": "direct",
        "topology": "one-lane",
        "enabled_interfaces": ("openat$lane", "remote_cover"),
        "trace_mode": "off",
    }
    value.update(updates)
    return RuntimeSelection(**value)


def runtime_sort(values):
    def key(selection):
        data = selection.model_dump(mode="json")
        data["enabled_interfaces"] = sorted(data["enabled_interfaces"])
        return canonical_json(data)
    return tuple(sorted(values, key=key))


def empty_facts() -> CallResourceFacts:
    return CallResourceFacts()


def lane_facts(origin="lane-root") -> CallResourceFacts:
    return CallResourceFacts(origins=(ResourceOriginFact(
        argument_index=0, resource_type="fd", origin=origin),))


def parsed(program: bytes, identity: SyzkallerTargetIdentity, calls,
           *, profile="knfsd-v41", acquire=True,
           resource_count=1) -> ParsedProgram:
    acquisitions = () if not acquire else (
        NfsAcquisition(profile=profile, resource_origin="lane-root"),)
    return ParsedProgram(
        identity=identity, program_sha256=digest(program),
        calls=tuple(ParsedCall(
            index=index, call=name, availability=availability,
            resource_facts=facts)
            for index, (name, availability, facts) in enumerate(calls)),
        usage=ProgramResourceUsage(
            program_bytes=len(program), call_count=len(calls),
            resource_count=resource_count),
        nfs_acquisitions=acquisitions)


def hcap11_parsed(identity, calls, origins):
    program = b"hcap11 contract fixture"
    return ParsedProgram(
        identity=identity, program_sha256=digest(program),
        calls=tuple(ParsedCall(
            index=index, call=call, availability="available",
            resource_facts=(lane_facts(HCAP11_ORIGIN)
                            if call in HCAP11_RECOVERY_IO else empty_facts()))
            for index, call in enumerate(calls)),
        usage=ProgramResourceUsage(
            program_bytes=len(program), call_count=len(calls),
            resource_count=len(origins)),
        nfs_acquisitions=tuple(sorted((
            NfsAcquisition(profile="knfsd-v41", resource_origin=origin)
            for origin in origins),
            key=lambda item: (item.profile, item.resource_origin))))


class SyntheticParser:
    def __init__(self, results):
        self.results = dict(results)
        self.requests = []

    def parse(self, program, *, identity):
        self.requests.append((digest(program), identity))
        result = self.results[digest(program)]
        if isinstance(result, BaseException):
            raise result
        return result


class FixedBuildAuthority:
    def __init__(self, approval):
        self.approval = approval

    def resolve(self, binding):
        return self.approval


def _capabilities():
    return (
        Capability(
            id="CAP-extra", name="Extra call", purpose="Negative tests",
            usable_stage=("stage1",), usable_by=("agent_stage1",),
            interface=CapabilityInterface(syz_calls=("read$extra",)),
            status="validated", scope=("extra",)),
        Capability(
            id="CAP-lane", name="Lane access", purpose="Acquire NFS lane",
            usable_stage=("stage1",), usable_by=("agent_stage1",),
            interface=CapabilityInterface(
                syz_calls=("close", "openat$lane", "write$known")),
            status="validated", scope=("lane",)),
        Capability(
            id="CAP-observe", name="Remote observation",
            purpose="Observe Q1 target", usable_stage=("stage1",),
            usable_by=("agent_stage1",),
            interface=CapabilityInterface(
                runtime_features=("remote_cover",)),
            status="validated", scope=("generation",)),
    )


@pytest.fixture
def world(tmp_path):
    return materializer_world(tmp_path)


def materializer_world(tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    patch_ref = store.put(b"synthetic patch series\n")
    executor_ref = store.put(b"synthetic syz-executor")
    build_manifest = SyzkallerBuildManifest(
        syzkaller_commit="b" * 40, patch_series_sha256=patch_ref,
        target="linux/amd64", files=(BuildFile(
            path="bin/syz-executor", artifact_ref=executor_ref),))
    build_manifest_ref = put_record(store, build_manifest)
    call_table = SyzkallerCallTable(
        syzkaller_commit="b" * 40, target="linux/amd64",
        calls=("close", "openat$lane", "read$extra", "write$known"))
    call_table_ref = put_record(store, call_table)
    identity = SyzkallerTargetIdentity(
        syzkaller_commit="b" * 40,
        patch_series_sha256=patch_ref,
        build_manifest_sha256=build_manifest_ref,
        call_table_sha256=call_table_ref,
        target="linux/amd64")
    profile = CallAdmissionProfile(
        identity=identity,
        limits=AdmissionLimits(
            max_program_bytes=4096, max_calls_per_program=16,
            max_resources_per_program=8),
        entries=(
            CallAdmissionEntry(call="close", capability_ids=("CAP-lane",)),
            CallAdmissionEntry(
                call="openat$lane", capability_ids=("CAP-lane",),
                resource_constraints=(ResourceOriginConstraint(
                    argument_index=0, resource_type="fd",
                    allowed_origins=("lane-root",)),)),
            CallAdmissionEntry(
                call="read$extra", capability_ids=("CAP-extra",)),
        ))
    profile_ref = put_record(store, profile)

    scenario_bytes = b"synthetic scenario program\n"
    neutral_bytes = b"synthetic repository neutral program\n"
    scenario_ref = store.put(scenario_bytes)
    neutral_ref = store.put(neutral_bytes)
    selected_runtime = runtime()
    neutral_catalog = NeutralControlCatalog(
        identity=identity, call_admission_profile_ref=profile_ref,
        entries=(NeutralControlEntry(
            runtime_selection=selected_runtime, program_ref=neutral_ref,
            required_capability_ids=("CAP-lane",)),))
    neutral_catalog_ref = put_record(store, neutral_catalog)
    seed_manifest = NormalFlowSeedManifest(
        identity=identity, seeds=(NormalFlowSeed(
            seed_id="seed-1", program_ref=scenario_ref,
            runtime_selections=(selected_runtime,)),))
    seed_manifest_ref = put_record(store, seed_manifest)
    hcap = HcapCatalog(
        capabilities=_capabilities(), missing_capability_ids=(),
        authority_refs=(
            AuthorityRef(kind="CallAdmissionProfile",
                         artifact_ref=profile_ref),
            AuthorityRef(kind="NeutralControlCatalog",
                         artifact_ref=neutral_catalog_ref),
            AuthorityRef(kind="NormalFlowSeedManifest",
                         artifact_ref=seed_manifest_ref),
        ))
    hcap_ref = put_record(store, hcap)

    plan = ReachabilityPlan(
        candidate_id="candidate-1", hcap_revision=hcap_ref,
        selected_path=SelectedPath(
            entry_surface="synthetic lane", path_summary="synthetic path"),
        nfs_version="4.1",
        scenario_steps=(ScenarioStep(
            capability_id="CAP-lane", action="open synthetic lane",
            expected_state_change="lane acquired"),),
        required_capabilities=("CAP-lane", "CAP-observe"),
        capability_uses=(
            CapabilityUse(capability_id="CAP-lane", status="validated",
                          scope=("lane",)),
            CapabilityUse(capability_id="CAP-observe", status="validated",
                          scope=("generation",)),
        ),
        q1_observation=Q1Observation(
            target={
                "kind": "function", "path": "fs/nfsd/synthetic.c",
                "symbol": "target", "start_line": 1, "end_line": 2,
            }, expected_context="synthetic_worker",
            capability_id="CAP-observe"),
        program_proposal=ProgramProposal(
            kind="program", artifact_ref=scenario_ref),
        runtime_selection=selected_runtime)
    plan_ref = put_record(store, plan)

    kernel_ref = store.put(b"synthetic vmlinux")
    image_ref = store.put(b"synthetic VM image")
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit=COMMIT, sanitizer=Sanitizer.KASAN,
        syzkaller_identity=identity,
        build_artifacts=(
            HarnessBuildArtifact(name="kernel", artifact_ref=kernel_ref),
            HarnessBuildArtifact(name="vm-image", artifact_ref=image_ref),
        ),
        guest_kernel_command_line="nokaslr nfs.localio_enabled=N",
        allowed_runtime_selections=(selected_runtime,))
    execution_id = descriptor_id(descriptor)
    binding = HarnessBinding(
        kernel_commit=COMMIT, sanitizer=Sanitizer.KASAN,
        execution_harness_id=execution_id, hcap_revision=hcap_ref)
    approval = ExecutionHarnessApproval(
        descriptor=descriptor, approved_hcap_revisions=(hcap_ref,))
    builds = StaticExecutionHarnessAuthority((approval,))
    parser = SyntheticParser({
        scenario_ref: parsed(
            scenario_bytes, identity,
            (("openat$lane", "available", lane_facts()),
             ("close", "available", empty_facts()))),
        neutral_ref: parsed(
            neutral_bytes, identity,
            (("openat$lane", "available", lane_facts()),)),
    })
    materializer: Materializer = ArtifactHarnessMaterializer(
        store, builds, parser)
    return SimpleNamespace(
        store=store, identity=identity, profile=profile,
        profile_ref=profile_ref, call_table=call_table,
        neutral_catalog=neutral_catalog,
        neutral_catalog_ref=neutral_catalog_ref,
        seed_manifest=seed_manifest, seed_manifest_ref=seed_manifest_ref,
        scenario_bytes=scenario_bytes, scenario_ref=scenario_ref,
        neutral_bytes=neutral_bytes, neutral_ref=neutral_ref,
        runtime=selected_runtime, hcap=hcap, hcap_ref=hcap_ref,
        plan=plan, plan_ref=plan_ref, descriptor=descriptor,
        approval=approval, builds=builds, binding=binding,
        parser=parser, materializer=materializer)


def plan_ref(world, *, proposal=None, selected_runtime=None,
             nfs_version=None):
    plan = world.plan.model_copy(update={
        **({"program_proposal": proposal} if proposal is not None else {}),
        **({"runtime_selection": selected_runtime}
           if selected_runtime is not None else {}),
        **({"nfs_version": nfs_version} if nfs_version is not None else {}),
    })
    # Revalidate model_copy updates and all cross-field invariants.
    plan = ReachabilityPlan.model_validate_json(canonical_json(plan))
    return plan, put_record(world.store, plan)


def artifact_refs(store):
    return {path.name for path in store.root.glob("*/*") if path.is_file()}


def plan_with_lane_use(world, **updates):
    uses = tuple(
        CapabilityUse.model_validate_json(canonical_json(
            use.model_copy(update=updates)))
        if use.capability_id == "CAP-lane" else use
        for use in world.plan.capability_uses)
    plan = ReachabilityPlan.model_validate_json(canonical_json(
        world.plan.model_copy(update={"capability_uses": uses})))
    return plan, put_record(world.store, plan)


def plan_with_extra_capability(world):
    extra_use = CapabilityUse(
        capability_id="CAP-extra", status="validated", scope=("extra",))
    plan = ReachabilityPlan.model_validate_json(canonical_json(
        world.plan.model_copy(update={
            "required_capabilities": (
                "CAP-extra", *world.plan.required_capabilities),
            "capability_uses": (extra_use, *world.plan.capability_uses),
        })))
    return plan, put_record(world.store, plan)


def test_hcap11_program_contract_accepts_expiry_then_client0_recovery(world):
    parsed_program = hcap11_parsed(
        world.identity,
        ("syz_nfsd_client_ctl$expire_client0",
         "syz_open_nfs_lane_profile$client0_knfsd_v41", "fsync"),
        ("nfs-profile:knfsd-v41:client0",))
    assert _hcap11_program_error(parsed_program) is None


@pytest.mark.parametrize(("calls", "origins", "reason"), [
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client1_knfsd_v41", "fsync"),
     ("nfs-profile:knfsd-v41:client1",), "client0_recovery_missing"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41",
      "syz_open_nfs_lane_profile$client1_knfsd_v41"),
     ("nfs-profile:knfsd-v41:client0",
      "nfs-profile:knfsd-v41:client1"), "non_client0_acquisition"),
    (("syz_open_nfs_lane_profile$client0_knfsd_v41",
      "syz_nfsd_client_ctl$expire_client0"),
     ("nfs-profile:knfsd-v41:client0",),
     "client0_recovery_precedes_expiry"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41"),
     ("nfs-profile:knfsd-v41:client0",), "expiry_count"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41"),
     ("nfs-profile:knfsd-v41:client0",), "client0_recovery_io_missing"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41", "close"),
     ("nfs-profile:knfsd-v41:client0",), "client0_recovery_io_missing"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41", "lseek"),
     ("nfs-profile:knfsd-v41:client0",), "client0_recovery_io_missing"),
    (("syz_nfsd_client_ctl$expire_client0",
      "syz_open_nfs_lane_profile$client0_knfsd_v41",
      "syz_open_nfs_lane_profile$client0_knfsd_v41", "fsync"),
     ("nfs-profile:knfsd-v41:client0",), "client0_acquisition_count"),
])
def test_hcap11_program_contract_rejects_cross_client_order_and_count(
        world, calls, origins, reason):
    assert _hcap11_program_error(
        hcap11_parsed(world.identity, calls, origins)) == reason


def test_materializer_enforces_hcap11_program_contract_before_call_grants(
        world):
    parsed_program = hcap11_parsed(
        world.identity,
        ("syz_nfsd_client_ctl$expire_client0",
         "syz_open_nfs_lane_profile$client1_knfsd_v41", "fsync"),
        ("nfs-profile:knfsd-v41:client1",))
    from agent_pipeline.admission import CallAdmissionAuthority
    authority = CallAdmissionAuthority(
        hcap_revision=world.hcap_ref, profile_ref=world.profile_ref,
        profile=world.profile)
    with pytest.raises(_Failure) as caught:
        world.materializer._admit(
            parsed_program, role="scenario", selection=world.runtime,
            required_capabilities=("HCAP-11",), authority=authority,
            call_table=world.call_table)
    assert caught.value.result().reason == CALL_NOT_ADMITTED
    assert caught.value.result().detail.endswith("client0_recovery_missing")


HCAP12_EXPIRE = "syz_nfsd_client_ctl$expire_client0"
HCAP12_ACQUIRE = "syz_open_nfs_lane_profile$client0_knfsd_v41"
HCAP12_CLIENT0 = ("nfs-profile:knfsd-v41:client0",)


def test_hcap12_program_contract_accepts_reconnect_inside_recovery(world):
    parsed_program = hcap11_parsed(
        world.identity,
        (HCAP12_EXPIRE, "syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE,
         "fsync"), HCAP12_CLIENT0)
    assert _hcap12_program_error(parsed_program) is None
    assert _hcap11_program_error(parsed_program) is None


@pytest.mark.parametrize(("calls", "reason"), [
    ((HCAP12_EXPIRE, HCAP12_ACQUIRE, "fsync"), "cld_reconnect_count"),
    ((HCAP12_EXPIRE, "syz_nfsd_cld_ctl$reconnect",
      "syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE, "fsync"),
     "cld_reconnect_count"),
    (("syz_nfsd_cld_ctl$reconnect", HCAP12_EXPIRE, HCAP12_ACQUIRE,
      "fsync"), "cld_reconnect_order"),
    ((HCAP12_EXPIRE, HCAP12_ACQUIRE, "syz_nfsd_cld_ctl$reconnect",
      "fsync"), "cld_reconnect_order"),
    ((HCAP12_EXPIRE, "syz_nfsd_cld_ctl$daemon_down", HCAP12_ACQUIRE,
      "fsync"), "cld_operation_not_validated"),
    ((HCAP12_EXPIRE, "syz_nfsd_cld_ctl$reconnect",
      "syz_nfsd_cld_ctl$daemon_down", HCAP12_ACQUIRE, "fsync"),
     "cld_operation_not_validated"),
    (("syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE, "fsync"),
     "hcap11:expiry_count"),
    ((HCAP12_EXPIRE, "syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE),
     "hcap11:client0_recovery_io_missing"),
])
def test_hcap12_program_contract_rejects_count_order_and_operation(
        world, calls, reason):
    assert _hcap12_program_error(
        hcap11_parsed(world.identity, calls, HCAP12_CLIENT0)) == reason


@pytest.mark.parametrize(("role", "required", "calls", "detail"), [
    ("scenario", ("HCAP-11", "HCAP-12"),
     (HCAP12_EXPIRE, "syz_nfsd_cld_ctl$daemon_down", HCAP12_ACQUIRE,
      "fsync"), "cld_operation_not_validated"),
    ("scenario", ("HCAP-11",),
     (HCAP12_EXPIRE, "syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE,
      "fsync"), "cld_without_hcap12"),
    ("neutral", ("HCAP-11", "HCAP-12"),
     ("syz_nfsd_cld_ctl$reconnect", HCAP12_ACQUIRE, "fsync"),
     "cld_without_hcap12"),
])
def test_materializer_enforces_hcap12_program_contract_before_call_grants(
        world, role, required, calls, detail):
    from agent_pipeline.admission import CallAdmissionAuthority
    authority = CallAdmissionAuthority(
        hcap_revision=world.hcap_ref, profile_ref=world.profile_ref,
        profile=world.profile)
    with pytest.raises(_Failure) as caught:
        world.materializer._admit(
            hcap11_parsed(world.identity, calls, HCAP12_CLIENT0),
            role=role, selection=world.runtime,
            required_capabilities=required, authority=authority,
            call_table=world.call_table)
    assert caught.value.result().reason == CALL_NOT_ADMITTED
    assert caught.value.result().detail == (
        f"{role}_hcap12_program_contract:{detail}")


def test_program_flow_persists_and_reloads_complete_records(world):
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, Materialized)
    assert result.execution_harness_id == world.binding.execution_harness_id
    assert result.hcap_revision == world.binding.hcap_revision
    harness = load_record(world.store, result.harness_ref,
                          ReachabilityHarness)
    review = load_record(world.store, result.review_manifest_sha256,
                         MaterializationReviewManifest)
    assert harness.review_manifest_sha256 == result.review_manifest_sha256
    assert harness.program_ref == world.scenario_ref
    assert harness.neutral_program_ref == world.neutral_ref
    assert harness.runtime_selection == world.runtime
    assert harness.selected_capability_ids == ("CAP-lane",)
    assert review.plan_ref == world.plan_ref
    assert review.hcap_revision == world.hcap_ref
    assert review.call_admission_profile_ref == world.profile_ref
    assert review.neutral_control_catalog_ref == world.neutral_catalog_ref
    assert review.execution_harness_id == world.binding.execution_harness_id
    assert load_record(world.store, review.scenario_parser_result_ref,
                       ParsedProgram).program_sha256 == world.scenario_ref
    assert load_record(world.store, review.neutral_parser_result_ref,
                       ParsedProgram).program_sha256 == world.neutral_ref
    assert world.store.has(world.binding.execution_harness_id)


def test_compatible_replacement_uses_effective_hcap_with_new_build_identity(
        world):
    replacement_ref = put_record(world.store, world.hcap.model_copy(update={
        "missing_capability_ids": ("fixture.unrelated_future_capability",),
    }))
    descriptor = world.descriptor.model_copy(update={
        "guest_kernel_command_line":
        world.descriptor.guest_kernel_command_line + " replacement=1",
    })
    binding = world.binding.model_copy(update={
        "execution_harness_id": descriptor_id(descriptor),
        "hcap_revision": replacement_ref,
    })
    approval = ExecutionHarnessApproval(
        descriptor=descriptor,
        approved_hcap_revisions=tuple(sorted((world.hcap_ref,
                                              replacement_ref))))
    materializer = ArtifactHarnessMaterializer(
        world.store, StaticExecutionHarnessAuthority((approval,)),
        world.parser)

    exact = materializer.materialize(world.plan_ref, binding)
    assert isinstance(exact, MaterializeRejected)
    assert exact.detail == "hcap_revision_mismatch"

    result = materializer.materialize(
        world.plan_ref, binding,
        hcap_authority=MaterializationHcapAuthority(
            effective_hcap_revision=replacement_ref,
            validation="compatible_replacement"))
    assert isinstance(result, Materialized)
    assert result.hcap_revision == replacement_ref
    harness = load_record(world.store, result.harness_ref,
                          ReachabilityHarness)
    review = load_record(world.store, result.review_manifest_sha256,
                         MaterializationReviewManifest)
    assert harness.plan_ref == world.plan_ref
    assert harness.hcap_revision == review.hcap_revision == replacement_ref
    assert harness.execution_harness_id == binding.execution_harness_id


def _approved_for(world, *hcap_refs):
    approval = ExecutionHarnessApproval(
        descriptor=world.descriptor,
        approved_hcap_revisions=tuple(sorted({world.hcap_ref, *hcap_refs})))
    return ArtifactHarnessMaterializer(
        world.store, StaticExecutionHarnessAuthority((approval,)),
        world.parser)


def test_harness_authority_current_only_while_hcap_refs_are_unchanged(
        world):
    """09 §5: an HCAP-only change keeps a harness whose call admission
    profile and neutral control catalog refs are unchanged."""
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, Materialized)
    same_refs = put_record(world.store, world.hcap.model_copy(update={
        "missing_capability_ids": ("fixture.unrelated_future_capability",),
    }))
    profile = world.profile.model_copy(update={
        "limits": world.profile.limits.model_copy(
            update={"max_calls_per_program": 15})})
    profile_ref = put_record(world.store, profile)
    neutral_ref = put_record(world.store, world.neutral_catalog.model_copy(
        update={"call_admission_profile_ref": profile_ref}))
    new_refs = put_record(world.store, world.hcap.model_copy(update={
        "authority_refs": (
            AuthorityRef(kind="CallAdmissionProfile",
                         artifact_ref=profile_ref),
            AuthorityRef(kind="NeutralControlCatalog",
                         artifact_ref=neutral_ref),
            AuthorityRef(kind="NormalFlowSeedManifest",
                         artifact_ref=world.seed_manifest_ref),
        )}))
    materializer = _approved_for(world, same_refs, new_refs)

    def current(hcap_ref, **updates):
        return materializer.harness_authority_current(
            result.harness_ref, world.binding.model_copy(
                update={"hcap_revision": hcap_ref, **updates}))

    assert current(world.hcap_ref)
    assert current(same_refs)
    assert not current(new_refs)
    # Not approved for this execution harness, or another harness.
    assert not world.materializer.harness_authority_current(
        result.harness_ref,
        world.binding.model_copy(update={"hcap_revision": same_refs}))
    assert not current(same_refs, execution_harness_id="f" * 64)
    # A corrupt harness record is not current; a missing one is I/O.
    corrupt = world.store.put(b"not a harness")
    assert not materializer.harness_authority_current(
        corrupt, world.binding)
    with pytest.raises(OSError):
        materializer.harness_authority_current("e" * 64, world.binding)


@pytest.mark.parametrize("error", [TimeoutError("bridge timed out"),
                                   ChildProcessError("bridge killed")])
def test_parser_host_failure_is_raised_not_a_rejection(world, error):
    world.parser.results[world.scenario_ref] = error
    with pytest.raises(OSError):
        world.materializer.materialize(world.plan_ref, world.binding)


@pytest.mark.parametrize(("error", "reason", "detail"), [
    (SyzParseFailure("x", reason="call_unresolved", call="syz_not_in_build",
                     call_index=1),
     CALL_UNRESOLVED, "scenario:1:syz_not_in_build"),
    (SyzParseFailure("x", reason="call_disabled", call="clone3",
                     call_index=2),
     DISALLOWED_OR_UNAVAILABLE_CALL, "scenario:2:clone3:disabled"),
    (SyzParseFailure("x", reason="nfs_acquisition_unverified",
                     call="syz_socket_connect_nfs", call_index=0),
     PROFILE_FIXTURE_ROUTE_MISMATCH,
     "scenario:0:syz_socket_connect_nfs:nfs_acquisition_unverified"),
    # Untyped or malformed refusals stay a bare parse failure.
    (SyzParseFailure("x"), PARSE_FAILURE, "scenario_strict_parse_failed"),
    (SyzParseFailure("x", reason="other", call="clone3", call_index=0),
     PARSE_FAILURE, "scenario_strict_parse_failed"),
    (SyzParseFailure("x", reason="call_disabled", call="clone3\n",
                     call_index=0),
     PARSE_FAILURE, "scenario_strict_parse_failed"),
    (SyzParseFailure("x", reason="call_disabled", call="clone3",
                     call_index=-1),
     PARSE_FAILURE, "scenario_strict_parse_failed"),
])
def test_typed_parser_refusal_reaches_planning(world, error, reason, detail):
    world.parser.results[world.scenario_ref] = error
    refused = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(refused, MaterializeRejected)
    assert (refused.reason, refused.detail) == (reason, detail)


def test_seed_flow_has_no_admission_bypass(world):
    proposal = ProgramProposal(
        kind="seed", artifact_ref=world.scenario_ref,
        seed_manifest_ref=world.seed_manifest_ref, seed_id="seed-1")
    plan, ref = plan_ref(world, proposal=proposal)
    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, Materialized)
    harness = load_record(world.store, result.harness_ref,
                          ReachabilityHarness)
    assert harness.program_kind == "seed"
    assert harness.seed_manifest_ref == world.seed_manifest_ref
    assert harness.seed_id == "seed-1"

    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("read$extra", "available", empty_facts()),))
    refused = world.materializer.materialize(ref, world.binding)
    assert isinstance(refused, MaterializeRejected)
    assert refused.reason == CALL_NOT_ADMITTED
    assert "capability_not_required" in refused.detail


@pytest.mark.parametrize(("updates", "violation"), [
    ({"status": "experimental", "unvalidated_scope": ("lane",)},
     "capability_status_mismatch:CAP-lane"),
    ({"scope": ("outside",)}, "undeclared_scope:CAP-lane:outside"),
    ({"unvalidated_scope": ("lane",)},
     "unvalidated_scope_not_explicit:CAP-lane"),
])
def test_materializer_independently_enforces_hcap_capability_contract(
        world, updates, violation):
    _, ref = plan_with_lane_use(world, **updates)
    check = ArtifactHcapChecker(world.store).check_plan(
        ref, world.binding.hcap_revision)
    assert violation in check.violations

    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == CALL_NOT_ADMITTED
    assert result.detail == f"hcap_plan_violation:{violation}"


def test_materializer_requires_enabled_interfaces_declared_by_hcap(world):
    selected = runtime(enabled_interfaces=(
        "openat$lane", "remote_cover", "rogue-interface"))
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit=world.descriptor.kernel_commit,
        sanitizer=world.descriptor.sanitizer,
        syzkaller_identity=world.identity,
        build_artifacts=world.descriptor.build_artifacts,
        guest_kernel_command_line=world.descriptor.guest_kernel_command_line,
        allowed_runtime_selections=(selected,))
    binding = world.binding.model_copy(update={
        "execution_harness_id": descriptor_id(descriptor)})
    approval = ExecutionHarnessApproval(
        descriptor=descriptor, approved_hcap_revisions=(world.hcap_ref,))
    materializer = ArtifactHarnessMaterializer(
        world.store, StaticExecutionHarnessAuthority((approval,)),
        world.parser)
    _, ref = plan_ref(world, selected_runtime=selected)
    violation = "interface_not_declared:rogue-interface"
    assert violation in ArtifactHcapChecker(world.store).check_plan(
        ref, world.hcap_ref).violations

    result = materializer.materialize(ref, binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == CALL_NOT_ADMITTED
    assert result.detail == f"hcap_plan_violation:{violation}"


@pytest.mark.parametrize(("call", "reason", "detail"), [
    ("write$unresolved", CALL_UNRESOLVED, "write$unresolved"),
    ("write$known", CALL_NOT_ADMITTED, "unknown_call"),
    ("read$extra", CALL_NOT_ADMITTED, "capability_not_required"),
])
def test_unknown_and_unrequired_calls_are_closed(world, call, reason, detail):
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        ((call, "available", empty_facts()),))
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == reason
    assert detail in result.detail


@pytest.mark.parametrize(("facts", "resource_count", "detail"), [
    (empty_facts(), 1, "resource_constraint_unverified"),
    (lane_facts("ambient-fd"), 2, "resource_constraint_mismatch"),
])
def test_resource_facts_must_be_present_and_match(
        world, facts, resource_count, detail):
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("openat$lane", "available", facts),),
        resource_count=resource_count)
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == CALL_NOT_ADMITTED
    assert detail in result.detail


def test_neutral_calls_receive_the_same_closed_world_admission(world):
    world.parser.results[world.neutral_ref] = parsed(
        world.neutral_bytes, world.identity,
        (("write$known", "available", empty_facts()),))
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == CALL_NOT_ADMITTED
    assert result.detail == "neutral:0:write$known:unknown_call"


def test_neutral_uses_its_declared_capability_with_broader_plan(world):
    _, ref = plan_with_extra_capability(world)

    result = world.materializer.materialize(ref, world.binding)

    assert isinstance(result, Materialized)
    harness = load_record(world.store, result.harness_ref,
                          ReachabilityHarness)
    assert harness.selected_capability_ids == ("CAP-lane",)


def test_neutral_cannot_exercise_undeclared_plan_capability(world):
    _, ref = plan_with_extra_capability(world)
    world.parser.results[world.neutral_ref] = parsed(
        world.neutral_bytes, world.identity,
        (("openat$lane", "available", lane_facts()),
         ("read$extra", "available", empty_facts())))

    result = world.materializer.materialize(ref, world.binding)

    assert isinstance(result, MaterializeRejected)
    assert result.reason == CALL_NOT_ADMITTED
    assert result.detail == (
        "neutral:1:read$extra:capability_not_required")


@pytest.mark.parametrize(("calls", "resource_count", "detail"), [
    (("close",) * 17, 1, "scenario_call_count_exceeded"),
    (("close",), 9, "scenario_resource_count_exceeded"),
])
def test_profile_usage_limits_are_enforced(
        world, calls, resource_count, detail):
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        tuple((call, "available", empty_facts()) for call in calls),
        resource_count=resource_count)
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == DISALLOWED_OR_UNAVAILABLE_CALL
    assert result.detail == detail


def test_profile_program_byte_limit_is_enforced_before_parsing(world):
    oversized_ref = world.store.put(b"x" * 4097)
    proposal = ProgramProposal(kind="program", artifact_ref=oversized_ref)
    _, ref = plan_ref(world, proposal=proposal)
    world.parser.requests.clear()
    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == DISALLOWED_OR_UNAVAILABLE_CALL
    assert result.detail == "scenario_program_limit_exceeded"
    assert world.parser.requests == []


def test_disabled_call_and_profile_acquisition_are_enforced(world):
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("openat$lane", "disabled", lane_facts()),))
    disabled = world.materializer.materialize(world.plan_ref, world.binding)
    assert disabled.reason == DISALLOWED_OR_UNAVAILABLE_CALL

    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("openat$lane", "available", lane_facts()),), acquire=False,
        resource_count=1)
    no_root = world.materializer.materialize(world.plan_ref, world.binding)
    assert no_root.reason == PROFILE_FIXTURE_ROUTE_MISMATCH
    assert "not_acquired" in no_root.detail

    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("openat$lane", "available", lane_facts()),),
        profile="knfsd-v42")
    wrong_profile = world.materializer.materialize(
        world.plan_ref, world.binding)
    assert wrong_profile.reason == PROFILE_FIXTURE_ROUTE_MISMATCH
    assert "nfs_profile_mismatch" in wrong_profile.detail


def test_parser_and_build_identity_mismatch_are_refused(world):
    other_identity = world.identity.model_copy(update={"target": "linux/arm64"})
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, other_identity,
        (("openat$lane", "available", lane_facts()),))
    parser_mismatch = world.materializer.materialize(
        world.plan_ref, world.binding)
    assert parser_mismatch.reason == HOST_AUTHORITY_UNAVAILABLE
    assert "parser_identity_mismatch" in parser_mismatch.detail

    changed = world.descriptor.model_copy(update={
        "guest_kernel_command_line": "different command line"})
    approval = ExecutionHarnessApproval(
        descriptor=changed, approved_hcap_revisions=(world.hcap_ref,))
    materializer = ArtifactHarnessMaterializer(
        world.store, FixedBuildAuthority(approval), world.parser)
    build_mismatch = materializer.materialize(world.plan_ref, world.binding)
    assert build_mismatch.reason == HOST_AUTHORITY_UNAVAILABLE
    assert "identity_mismatch" in build_mismatch.detail


def test_neutral_miss_routes_with_profile(world):
    selected = runtime(trace_mode="on")
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit=world.descriptor.kernel_commit,
        sanitizer=world.descriptor.sanitizer,
        syzkaller_identity=world.identity,
        build_artifacts=world.descriptor.build_artifacts,
        guest_kernel_command_line=world.descriptor.guest_kernel_command_line,
        allowed_runtime_selections=(selected,))
    binding = world.binding.model_copy(update={
        "execution_harness_id": descriptor_id(descriptor)})
    approval = ExecutionHarnessApproval(
        descriptor=descriptor, approved_hcap_revisions=(world.hcap_ref,))
    materializer = ArtifactHarnessMaterializer(
        world.store, StaticExecutionHarnessAuthority((approval,)),
        world.parser)
    _, ref = plan_ref(world, selected_runtime=selected)
    result = materializer.materialize(ref, binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == "neutral_control_unavailable"
    assert result.profile == "knfsd-v41"


@pytest.mark.parametrize(("field", "value"), [
    ("profile", "knfsd-v42"),
    ("fixture_mode", "broad-knfsd"),
    ("route", "proxied"),
])
def test_profile_fixture_and_route_must_be_allowlisted(world, field, value):
    selected = runtime(**{field: value})
    _, ref = plan_ref(world, selected_runtime=selected)
    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == PROFILE_FIXTURE_ROUTE_MISMATCH


def test_interface_or_trace_change_is_invalid_runtime_selection(world):
    selected = runtime(trace_mode="on")
    _, ref = plan_ref(world, selected_runtime=selected)
    result = world.materializer.materialize(ref, world.binding)
    assert result.reason == INVALID_RUNTIME_SELECTION


@pytest.mark.parametrize("mutation", [
    "wrong_seed_id", "wrong_manifest", "wrong_program",
])
def test_seed_provenance_mismatch_is_refused_before_parse(world, mutation):
    seed_id = "seed-1"
    manifest_ref = world.seed_manifest_ref
    program_ref = world.scenario_ref
    if mutation == "wrong_seed_id":
        seed_id = "seed-missing"
    elif mutation == "wrong_manifest":
        manifest_ref = put_record(world.store, NormalFlowSeedManifest(
            identity=world.identity, seeds=()))
    else:
        program_ref = world.store.put(b"different seed bytes")
    proposal = ProgramProposal(
        kind="seed", artifact_ref=program_ref,
        seed_manifest_ref=manifest_ref, seed_id=seed_id)
    _, ref = plan_ref(world, proposal=proposal)
    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == PROFILE_FIXTURE_ROUTE_MISMATCH
    assert world.parser.requests == []


def test_seed_byte_corruption_is_not_accepted(world):
    proposal = ProgramProposal(
        kind="seed", artifact_ref=world.scenario_ref,
        seed_manifest_ref=world.seed_manifest_ref, seed_id="seed-1")
    _, ref = plan_ref(world, proposal=proposal)
    world.store._path(world.scenario_ref).write_bytes(b"corrupt")
    result = world.materializer.materialize(ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert result.reason == PARSE_FAILURE


def test_repeat_is_deterministic_and_does_not_add_artifacts(world):
    first = world.materializer.materialize(world.plan_ref, world.binding)
    after_first = artifact_refs(world.store)
    second = world.materializer.materialize(world.plan_ref, world.binding)
    assert second == first
    assert artifact_refs(world.store) == after_first


def test_review_manifest_changes_when_execution_identity_changes(world):
    first = world.materializer.materialize(world.plan_ref, world.binding)
    changed = ExecutionHarnessDescriptor(
        kernel_commit=world.descriptor.kernel_commit,
        sanitizer=world.descriptor.sanitizer,
        syzkaller_identity=world.identity,
        build_artifacts=world.descriptor.build_artifacts,
        guest_kernel_command_line="nokaslr nfs.localio_enabled=N debug",
        allowed_runtime_selections=world.descriptor.allowed_runtime_selections)
    changed_id = descriptor_id(changed)
    binding = world.binding.model_copy(update={
        "execution_harness_id": changed_id})
    approval = ExecutionHarnessApproval(
        descriptor=changed, approved_hcap_revisions=(world.hcap_ref,))
    other = ArtifactHarnessMaterializer(
        world.store, StaticExecutionHarnessAuthority((approval,)),
        world.parser)
    second = other.materialize(world.plan_ref, binding)
    assert isinstance(first, Materialized) and isinstance(second, Materialized)
    assert second.execution_harness_id == changed_id
    assert second.review_manifest_sha256 != first.review_manifest_sha256
    assert second.harness_ref != first.harness_ref
    first_review = load_record(
        world.store, first.review_manifest_sha256,
        MaterializationReviewManifest)
    second_review = load_record(
        world.store, second.review_manifest_sha256,
        MaterializationReviewManifest)
    assert first_review.execution_harness_id != \
        second_review.execution_harness_id


def test_corrupt_plan_is_rejected_but_missing_program_is_retryable(world):
    world.store._path(world.plan_ref).write_bytes(b"corrupt")
    corrupt = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(corrupt, MaterializeRejected)
    assert corrupt.reason == PARSE_FAILURE

    # Use a fresh canonical plan ref after restoring the same logical plan.
    world.store._path(world.plan_ref).write_bytes(canonical_json(world.plan))
    world.store._path(world.scenario_ref).unlink()
    before = artifact_refs(world.store)
    with pytest.raises(FileNotFoundError):
        world.materializer.materialize(world.plan_ref, world.binding)
    assert artifact_refs(world.store) == before


def test_missing_hcap_dependency_is_retryable_and_writes_nothing(world):
    world.store._path(world.profile_ref).unlink()
    before = artifact_refs(world.store)
    with pytest.raises(FileNotFoundError):
        world.materializer.materialize(world.plan_ref, world.binding)
    assert artifact_refs(world.store) == before


def test_malformed_unbounded_parser_facts_are_refused(world):
    facts = CallResourceFacts.model_construct(origins=tuple(
        ResourceOriginFact(
            argument_index=index, resource_type="fd", origin=f"origin-{index}")
        for index in range(65)), integers=(), byte_lengths=())
    call = ParsedCall.model_construct(
        index=0, call="openat$lane", availability="available",
        resource_facts=facts)
    malformed = ParsedProgram.model_construct(
        schema_version="parsed-syz-program.v1", identity=world.identity,
        program_sha256=world.scenario_ref, calls=(call,),
        usage=ProgramResourceUsage(
            program_bytes=len(world.scenario_bytes), call_count=1,
            resource_count=65),
        nfs_acquisitions=(NfsAcquisition(
            profile="knfsd-v41", resource_origin="lane-root"),))
    world.parser.results[world.scenario_ref] = malformed
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert result.reason == PARSE_FAILURE
    assert "parser_result_invalid" in result.detail


def test_rejection_writes_no_partial_materialized_artifacts(world):
    before = artifact_refs(world.store)
    world.parser.results[world.scenario_ref] = parsed(
        world.scenario_bytes, world.identity,
        (("write$known", "available", empty_facts()),))
    result = world.materializer.materialize(world.plan_ref, world.binding)
    assert isinstance(result, MaterializeRejected)
    assert artifact_refs(world.store) == before


def test_missing_trusted_seed_program_is_a_host_failure(world):
    """A seed the host's trusted manifest lists is a host artifact: its
    missing program is retried, not charged to Agent repair.  A seed the
    manifest does not list is a reference the Agent invented."""
    checker = ArtifactHcapChecker(world.store)
    trusted = ProgramProposal(
        kind="seed", artifact_ref=world.scenario_ref,
        seed_manifest_ref=world.seed_manifest_ref, seed_id="seed-1")
    _, ref = plan_ref(world, proposal=trusted)
    assert checker.check_plan(ref, world.hcap_ref).ok
    (world.store.root / world.scenario_ref[:2] / world.scenario_ref).unlink()
    with pytest.raises(FileNotFoundError):
        checker.check_plan(ref, world.hcap_ref)

    for invented in (
            trusted.model_copy(update={"seed_id": "seed-unlisted"}),
            trusted.model_copy(update={"artifact_ref": "f" * 64}),
            trusted.model_copy(update={"seed_manifest_ref": "e" * 64})):
        _, ref = plan_ref(world, proposal=invented)
        check = checker.check_plan(ref, world.hcap_ref)
        assert check.violations == ("seed_reference_not_found",)
        assert not check.host_authority


def test_untyped_parse_failure_carries_the_bounded_parser_message(world):
    world.parser.results[world.scenario_ref] = SyzParseFailure(
        "bridge refused (2): failed to parse program\n"
        "line 2: unknown syscall \x1b[31mfoo$bar\n" + "x" * 4000)
    refused = world.materializer.materialize(world.plan_ref, world.binding)
    assert (refused.reason, refused.detail) == (
        PARSE_FAILURE, "scenario_strict_parse_failed")
    assert refused.message.startswith(
        "bridge refused (2): failed to parse program | line 2: unknown "
        "syscall ?[31mfoo$bar")
    assert len(refused.message) == 1024 and refused.message.endswith("...")
    # A typed refusal keeps its typed detail and adds no message.
    world.parser.results[world.scenario_ref] = SyzParseFailure(
        "x", reason="call_disabled", call="clone3", call_index=2)
    typed = world.materializer.materialize(world.plan_ref, world.binding)
    assert typed.message == ""


def _stored_files(store) -> set:
    return {p for p in store.root.rglob("*") if p.is_file()}


def test_check_draft_matches_materialize_and_writes_nothing(world):
    before = _stored_files(world.store)
    assert world.materializer.check_draft(
        world.plan, world.scenario_bytes, world.binding) is None
    assert _stored_files(world.store) == before

    # An inline draft whose bytes were never stored is checked from memory.
    draft = b"draft program\n"
    world.parser.results[digest(draft)] = SyzParseFailure(
        "line 1: unexpected token")
    plan = world.plan.model_copy(update={"program_proposal": ProgramProposal(
        kind="program", artifact_ref=digest(draft))})
    refused = world.materializer.check_draft(plan, draft, world.binding)
    assert (refused.reason, refused.detail, refused.message) == (
        PARSE_FAILURE, "scenario_strict_parse_failed",
        "line 1: unexpected token")
    assert _stored_files(world.store) == before

    # The same refusal materialize gives for the stored plan.
    world.parser.results[digest(draft)] = parsed(
        draft, world.identity,
        (("read$extra", "available", empty_facts()),))
    refused = world.materializer.check_draft(plan, draft, world.binding)
    assert refused.reason == CALL_NOT_ADMITTED
    world.store.put(draft)
    assert world.materializer.materialize(
        put_record(world.store, plan), world.binding) == refused


def test_check_draft_bounds_in_memory_program_bytes(world):
    draft = b"x" * 5000
    plan = world.plan.model_copy(update={"program_proposal": ProgramProposal(
        kind="program", artifact_ref=digest(draft))})
    refused = world.materializer.check_draft(plan, draft, world.binding)
    assert (refused.reason, refused.detail) == (
        DISALLOWED_OR_UNAVAILABLE_CALL, "scenario_program_limit_exceeded")
