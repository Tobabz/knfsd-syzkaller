"""Synthetic authority tests; no production syzkaller build is claimed."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent_pipeline.admission import (
    AdmissionLimits,
    AuthorityIdentityMismatch,
    BuildFile,
    ByteLengthConstraint,
    ByteLengthFact,
    CallAdmissionEntry,
    CallAdmissionProfile,
    CallResourceFacts,
    IntegerFact,
    IntegerRangeConstraint,
    NeutralControlCatalog,
    NeutralControlEntry,
    ProgramResourceUsage,
    ResourceOriginConstraint,
    ResourceOriginFact,
    SyzkallerBuildManifest,
    SyzkallerCallTable,
    SyzkallerTargetIdentity,
    UntrustedAuthority,
    load_call_admission_authority,
    load_call_admission_profile,
    load_neutral_control_authority,
    load_neutral_control_catalog,
)
from agent_pipeline.admission_generation import (
    AdmissionProfileSource,
    AuthorityGenerationError,
    DriftDetected,
    MAX_GIT_OUTPUT_BYTES,
    PinnedSyzkallerInputs,
    generate_call_admission_profile,
    inspect_pinned_syzkaller,
    write_or_check_profile,
)
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.hcap import (
    AuthorityRef,
    Capability,
    CapabilityInterface,
    HcapCatalog,
    RuntimeSelection,
)


CAPABILITIES = (
    Capability(
        id="CAP-fs", name="Synthetic filesystem", purpose="Test admission",
        usable_stage=("stage1",), usable_by=("agent_stage1",),
        interface=CapabilityInterface(syz_calls=("close", "openat$lane")),
        status="validated", scope=("lane",)),
    Capability(
        id="CAP-lane", name="Synthetic lane", purpose="Test multi mapping",
        usable_stage=("stage1",), usable_by=("agent_stage1",),
        interface=CapabilityInterface(syz_calls=("openat$lane",)),
        status="validated", scope=("open",)),
)


def runtime_selection(*, enabled_interfaces=("lane", "remote-cover")
                      ) -> RuntimeSelection:
    return RuntimeSelection(
        profile="knfsd-v41", nfs_version="4.1", fixture_mode="single",
        route="direct", topology="one-lane",
        enabled_interfaces=enabled_interfaces, trace_mode="off")


def constrained_entry() -> CallAdmissionEntry:
    return CallAdmissionEntry(
        call="openat$lane", capability_ids=("CAP-fs", "CAP-lane"),
        resource_constraints=(
            ResourceOriginConstraint(
                argument_index=0, resource_type="fd",
                allowed_origins=("lane-root",)),
            IntegerRangeConstraint(argument_index=1, minimum=0, maximum=7),
            ByteLengthConstraint(
                argument_index=2, minimum_bytes=1, maximum_bytes=4096),
        ))


def valid_facts(*, origin: str = "lane-root") -> CallResourceFacts:
    return CallResourceFacts(
        origins=(ResourceOriginFact(
            argument_index=0, resource_type="fd", origin=origin),),
        integers=(IntegerFact(argument_index=1, value=3),),
        byte_lengths=(ByteLengthFact(argument_index=2, length_bytes=128),))


@pytest.fixture
def authority(tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    patch_ref = store.put(b"0015-test.patch\n")
    executor_ref = store.put(b"synthetic syz-executor build")
    manifest = SyzkallerBuildManifest(
        syzkaller_commit="a" * 40, patch_series_sha256=patch_ref,
        target="linux/amd64",
        files=(BuildFile(path="bin/syz-executor",
                         artifact_ref=executor_ref),))
    manifest_ref = put_record(store, manifest)
    call_table = SyzkallerCallTable(
        syzkaller_commit="a" * 40, target="linux/amd64",
        calls=("close", "openat$lane"))
    call_table_ref = put_record(store, call_table)
    identity = SyzkallerTargetIdentity(
        syzkaller_commit="a" * 40,
        patch_series_sha256=patch_ref,
        build_manifest_sha256=manifest_ref,
        call_table_sha256=call_table_ref,
        target="linux/amd64")
    profile = CallAdmissionProfile(
        identity=identity,
        limits=AdmissionLimits(
            max_program_bytes=4096, max_calls_per_program=8,
            max_resources_per_program=4),
        entries=(
            CallAdmissionEntry(call="close", capability_ids=("CAP-fs",)),
            constrained_entry(),
        ))
    profile_ref = put_record(store, profile)
    neutral_program_ref = store.put(b"openat$lane(0x0, 0x0, 0x0)\n")
    neutral = NeutralControlCatalog(
        identity=identity, call_admission_profile_ref=profile_ref,
        entries=(NeutralControlEntry(
            runtime_selection=runtime_selection(),
            program_ref=neutral_program_ref,
            required_capability_ids=("CAP-lane",)),))
    neutral_ref = put_record(store, neutral)
    hcap = HcapCatalog(
        capabilities=CAPABILITIES, missing_capability_ids=(),
        authority_refs=(
            AuthorityRef(kind="CallAdmissionProfile",
                         artifact_ref=profile_ref),
            AuthorityRef(kind="NeutralControlCatalog",
                         artifact_ref=neutral_ref),
        ))
    hcap_ref = put_record(store, hcap)
    return SimpleNamespace(
        store=store, identity=identity, manifest=manifest,
        call_table=call_table, profile=profile, profile_ref=profile_ref,
        neutral=neutral, neutral_ref=neutral_ref,
        neutral_program_ref=neutral_program_ref, hcap=hcap,
        hcap_ref=hcap_ref)


def test_authority_records_are_canonical_content_addressed(authority):
    expected = hashlib.sha256(canonical_json(authority.profile)).hexdigest()
    assert authority.profile_ref == expected
    assert load_call_admission_profile(
        authority.store, authority.profile_ref,
        expected_identity=authority.identity) == authority.profile
    assert load_neutral_control_catalog(
        authority.store, authority.neutral_ref,
        trusted_profile_ref=authority.profile_ref,
        expected_identity=authority.identity) == authority.neutral

    with pytest.raises(ValidationError, match="must be sorted"):
        CallAdmissionProfile(
            identity=authority.identity, limits=authority.profile.limits,
            entries=tuple(reversed(authority.profile.entries)))


@pytest.mark.parametrize("path", [
    "bin//syz-executor", "bin/./syz-executor", "./bin/syz-executor",
])
def test_build_file_paths_require_one_normalized_posix_spelling(path):
    with pytest.raises(ValidationError, match="normalized relative POSIX"):
        BuildFile(path=path, artifact_ref="a" * 64)


def test_exact_build_and_target_identity_is_required(authority):
    other_target = authority.identity.model_copy(update={"target": "linux/arm64"})
    with pytest.raises(AuthorityIdentityMismatch, match="identity mismatch"):
        load_call_admission_profile(
            authority.store, authority.profile_ref,
            expected_identity=other_target)

    admission = load_call_admission_authority(
        authority.store, authority.hcap_ref,
        expected_identity=authority.identity)
    decision = admission.admit(
        "close", ("CAP-fs",), identity=other_target)
    assert not decision.admitted
    assert decision.reason == "identity_mismatch"


def test_one_call_can_be_admitted_by_multiple_capabilities(authority):
    admission = load_call_admission_authority(
        authority.store, authority.hcap_ref,
        expected_identity=authority.identity)
    one = admission.admit(
        "openat$lane", ("CAP-lane",), identity=authority.identity,
        resource_facts=valid_facts())
    both = admission.admit(
        "openat$lane", ("CAP-fs", "CAP-lane"),
        identity=authority.identity, resource_facts=valid_facts())
    assert one.admitted and one.capability_ids == ("CAP-lane",)
    assert both.admitted and both.capability_ids == ("CAP-fs", "CAP-lane")


def test_unknown_unrequired_and_unverified_calls_are_refused(authority):
    admission = load_call_admission_authority(
        authority.store, authority.hcap_ref,
        expected_identity=authority.identity)
    assert admission.admit(
        "read$unknown", ("CAP-fs",),
        identity=authority.identity).reason == "unknown_call"
    assert admission.admit(
        "close", ("CAP-other",),
        identity=authority.identity).reason == "capability_not_required"
    assert admission.admit(
        "openat$lane", ("CAP-lane",),
        identity=authority.identity).reason == "resource_constraint_unverified"
    assert admission.admit(
        "openat$lane", ("CAP-lane",), identity=authority.identity,
        resource_facts=valid_facts(origin="ambient-fd")
    ).reason == "resource_constraint_mismatch"


def test_resource_constraints_and_program_bounds_are_closed(authority):
    admission = load_call_admission_authority(
        authority.store, authority.hcap_ref,
        expected_identity=authority.identity)
    assert admission.check_limits(ProgramResourceUsage(
        program_bytes=4096, call_count=8, resource_count=4)).accepted
    assert admission.check_limits(ProgramResourceUsage(
        program_bytes=4097, call_count=1,
        resource_count=1)).reason == "program_bytes_exceeded"
    assert admission.check_limits(ProgramResourceUsage(
        program_bytes=1, call_count=9,
        resource_count=1)).reason == "call_count_exceeded"
    assert admission.check_limits(ProgramResourceUsage(
        program_bytes=1, call_count=1,
        resource_count=5)).reason == "resource_count_exceeded"
    with pytest.raises(ValidationError, match="minimum exceeds maximum"):
        IntegerRangeConstraint(argument_index=0, minimum=2, maximum=1)


def test_neutral_control_uses_exact_runtime_key_and_immutable_program(authority):
    neutral = load_neutral_control_authority(
        authority.store, authority.hcap_ref,
        expected_identity=authority.identity)
    selected = neutral.select(runtime_selection(), identity=authority.identity)
    assert selected.selected
    assert selected.program_ref == authority.neutral_program_ref
    assert authority.store.get(selected.program_ref).startswith(b"openat$lane")

    different_route = runtime_selection().model_copy(update={"route": "proxied"})
    unavailable = neutral.select(different_route, identity=authority.identity)
    assert not unavailable.selected
    assert unavailable.reason == "neutral_control_unavailable"
    other_target = authority.identity.model_copy(update={"target": "linux/arm64"})
    assert neutral.select(
        runtime_selection(), identity=other_target).reason == "identity_mismatch"
    reordered = runtime_selection(
        enabled_interfaces=("remote-cover", "lane"))
    same_selection = neutral.select(reordered, identity=authority.identity)
    assert same_selection.selected
    assert same_selection.program_ref == authority.neutral_program_ref


def test_neutral_catalog_cannot_switch_profiles(authority):
    wrong = NeutralControlCatalog(
        identity=authority.identity,
        call_admission_profile_ref="0" * 64,
        entries=authority.neutral.entries)
    wrong_ref = put_record(authority.store, wrong)
    with pytest.raises(UntrustedAuthority, match="different admission profile"):
        load_neutral_control_catalog(
            authority.store, wrong_ref,
            trusted_profile_ref=authority.profile_ref,
            expected_identity=authority.identity)


def test_missing_neutral_program_is_not_selected(authority):
    authority.store._path(authority.neutral_program_ref).unlink()
    with pytest.raises(FileNotFoundError):
        load_neutral_control_authority(
            authority.store, authority.hcap_ref,
            expected_identity=authority.identity)


def _git(*arguments: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=cwd, check=True, capture_output=True,
        text=True, env={
            **os.environ,
            "GIT_AUTHOR_NAME": "Authority Test",
            "GIT_AUTHOR_EMAIL": "authority@example.invalid",
            "GIT_COMMITTER_NAME": "Authority Test",
            "GIT_COMMITTER_EMAIL": "authority@example.invalid",
        })
    return result.stdout.strip()


def _write_record(path: Path, value) -> None:
    path.write_bytes(canonical_json(value))


@pytest.fixture
def pinned_inputs(tmp_path):
    checkout = tmp_path / "syzkaller"
    checkout.mkdir()
    _git("init", "-q", cwd=checkout)
    (checkout / "README").write_text("synthetic pinned checkout\n")
    _git("add", "README", cwd=checkout)
    _git("commit", "-q", "-m", "synthetic pin", cwd=checkout)
    commit = _git("rev-parse", "HEAD", cwd=checkout)

    patch_series = tmp_path / "series"
    patch_series.write_bytes(b"0015-test.patch\n")
    patch_ref = hashlib.sha256(patch_series.read_bytes()).hexdigest()
    build_root = tmp_path / "build"
    binary = build_root / "bin/syz-executor"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"synthetic target executor")
    binary_ref = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_path = tmp_path / "build-manifest.json"
    _write_record(manifest_path, SyzkallerBuildManifest(
        syzkaller_commit=commit, patch_series_sha256=patch_ref,
        target="linux/amd64",
        files=(BuildFile(path="bin/syz-executor",
                         artifact_ref=binary_ref),)))
    call_table_path = tmp_path / "call-table.json"
    _write_record(call_table_path, SyzkallerCallTable(
        syzkaller_commit=commit, target="linux/amd64",
        calls=("close", "openat$lane")))
    mapping_path = tmp_path / "mapping.json"
    _write_record(mapping_path, AdmissionProfileSource(
        schema_version="call-admission-source.v1", target="linux/amd64",
        limits=AdmissionLimits(
            max_program_bytes=4096, max_calls_per_program=8,
            max_resources_per_program=4),
        entries=(
            CallAdmissionEntry(call="close", capability_ids=("CAP-fs",)),
            constrained_entry(),
        )))
    hcap_path = tmp_path / "hcap.json"
    _write_record(hcap_path, HcapCatalog(
        capabilities=CAPABILITIES, missing_capability_ids=()))
    inputs = PinnedSyzkallerInputs(
        checkout=checkout, expected_commit=commit,
        patch_series=patch_series, build_root=build_root,
        build_manifest=manifest_path, call_table=call_table_path,
        target="linux/amd64")
    return SimpleNamespace(
        inputs=inputs, checkout=checkout, commit=commit,
        patch_series=patch_series, build_root=build_root,
        manifest_path=manifest_path, call_table_path=call_table_path,
        mapping_path=mapping_path, hcap_path=hcap_path)


def test_generator_is_deterministic_and_detects_drift(pinned_inputs, tmp_path):
    profile = generate_call_admission_profile(
        pinned_inputs.inputs, mapping_path=pinned_inputs.mapping_path,
        hcap_path=pinned_inputs.hcap_path)
    output = tmp_path / "generated-profile.json"
    digest = write_or_check_profile(profile, output, check=False)
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    assert write_or_check_profile(profile, output, check=True) == digest

    table = SyzkallerCallTable(
        syzkaller_commit=pinned_inputs.commit, target="linux/amd64",
        calls=("close", "openat$lane", "read$drift"))
    _write_record(pinned_inputs.call_table_path, table)
    drifted = generate_call_admission_profile(
        pinned_inputs.inputs, mapping_path=pinned_inputs.mapping_path,
        hcap_path=pinned_inputs.hcap_path)
    before = output.read_bytes()
    with pytest.raises(DriftDetected, match="has drifted"):
        write_or_check_profile(drifted, output, check=True)
    assert output.read_bytes() == before


def test_generator_rejects_wrong_pin_and_unresolved_calls(pinned_inputs):
    wrong_pin = PinnedSyzkallerInputs(
        checkout=pinned_inputs.checkout, expected_commit="f" * 40,
        patch_series=pinned_inputs.patch_series,
        build_root=pinned_inputs.build_root,
        build_manifest=pinned_inputs.manifest_path,
        call_table=pinned_inputs.call_table_path, target="linux/amd64")
    with pytest.raises(AuthorityGenerationError, match="checkout is"):
        generate_call_admission_profile(
            wrong_pin, mapping_path=pinned_inputs.mapping_path,
            hcap_path=pinned_inputs.hcap_path)

    bad_mapping = pinned_inputs.mapping_path.with_name("bad-mapping.json")
    _write_record(bad_mapping, AdmissionProfileSource(
        schema_version="call-admission-source.v1", target="linux/amd64",
        limits=AdmissionLimits(
            max_program_bytes=1, max_calls_per_program=1,
            max_resources_per_program=0),
        entries=(CallAdmissionEntry(
            call="write$missing", capability_ids=("CAP-fs",)),)))
    with pytest.raises(AuthorityGenerationError, match="absent from pinned table"):
        generate_call_admission_profile(
            pinned_inputs.inputs, mapping_path=bad_mapping,
            hcap_path=pinned_inputs.hcap_path)


@pytest.mark.parametrize("dirty_kind", ["tracked", "untracked"])
def test_generator_rejects_dirty_checkout(pinned_inputs, dirty_kind):
    if dirty_kind == "tracked":
        (pinned_inputs.checkout / "README").write_text("changed worktree\n")
    else:
        (pinned_inputs.checkout / "UNTRACKED").write_text("untracked input\n")
    with pytest.raises(AuthorityGenerationError, match="worktree changes"):
        generate_call_admission_profile(
            pinned_inputs.inputs, mapping_path=pinned_inputs.mapping_path,
            hcap_path=pinned_inputs.hcap_path)


@pytest.mark.parametrize("failure", ["timeout", "oversized_output"])
def test_git_inspection_is_time_and_output_bounded(
        pinned_inputs, monkeypatch, failure):
    def fail(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
        kwargs["stdout"].write(b"x" * (MAX_GIT_OUTPUT_BYTES + 1))
        return subprocess.CompletedProcess(args[0], 0)

    monkeypatch.setattr(
        "agent_pipeline.admission_generation.subprocess.run", fail)
    expected = "timed out" if failure == "timeout" else "exceeded the limit"
    with pytest.raises(AuthorityGenerationError, match=expected):
        inspect_pinned_syzkaller(pinned_inputs.inputs)


def test_cli_uses_only_explicit_pinned_inputs(pinned_inputs, tmp_path):
    output = tmp_path / "cli-profile.json"
    tool = Path(__file__).parents[2] / "tools/generate-call-admission.py"
    command = [
        sys.executable, str(tool),
        "--syzkaller-checkout", str(pinned_inputs.checkout),
        "--expected-commit", pinned_inputs.commit,
        "--patch-series", str(pinned_inputs.patch_series),
        "--build-root", str(pinned_inputs.build_root),
        "--build-manifest", str(pinned_inputs.manifest_path),
        "--call-table", str(pinned_inputs.call_table_path),
        "--target", "linux/amd64",
        "--mapping", str(pinned_inputs.mapping_path),
        "--hcap", str(pinned_inputs.hcap_path),
        "--output", str(output),
    ]
    generated = subprocess.run(command, check=False, capture_output=True,
                               text=True)
    assert generated.returncode == 0, generated.stderr
    checked = subprocess.run([*command, "--check"], check=False,
                             capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    assert output.read_bytes() == canonical_json(
        generate_call_admission_profile(
            pinned_inputs.inputs, mapping_path=pinned_inputs.mapping_path,
            hcap_path=pinned_inputs.hcap_path))
