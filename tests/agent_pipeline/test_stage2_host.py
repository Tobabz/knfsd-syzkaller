"""Read-only Stage 2 KVM readiness checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

import agent_pipeline.stage2.host as stage2_host
from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.contracts import (CandidateSubmission, JudgeVersions,
                                      LocationKind, LocationRequest)
from agent_pipeline.controller.records import Job, JobState
from agent_pipeline.runner.process_supervisor import ProcessLimits
from agent_pipeline.semantic_promotion import (
    BuildRegistry, CapabilityRegistry, PromotedSemanticCapabilityRegistry,
    PromotedSubset, RegistryLimits, RegistrySchema, SemanticSubset,
    ValidationItem,
)
from agent_pipeline.stage1.config import EngineConfig, Stage1Config
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage1.host.pins import pin_file
from agent_pipeline.stage2.host import (
    KVM_API_VERSION, PreflightError, _ApprovedHarness, _Checks,
    _check_command, _check_kernel_repo, _check_kvm, _check_manager,
    _check_job_authority, _check_policies, _check_runtime, _check_stage2_job,
    _check_stage2_timeout, _load_job_read_only,
    _verify_pins_read_only, preflight,
)
from agent_pipeline.stage2.kvm import stage2_timeout_budget

from .fakes import policy, sha


def _identity() -> SyzkallerTargetIdentity:
    return SyzkallerTargetIdentity(
        syzkaller_commit="a" * 40, patch_series_sha256=sha("patches"),
        build_manifest_sha256=sha("manifest"),
        call_table_sha256=sha("calls"), target="linux/amd64")


def _config(tmp_path: Path) -> Stage1Config:
    engine = EngineConfig(
        argv=("/bin/true", "{input}", "{output}"), cwd=tmp_path,
        resource_key="test-kvm")
    return Stage1Config(
        state_dir=tmp_path / "state", artifact_root=tmp_path / "cas",
        kernel_repo=tmp_path / "linux", harness_catalog_ref=sha("catalog"),
        execution_harness_approvals=(sha("approval"),),
        syzkaller_bundle=tmp_path / "parser", syzkaller_identity=_identity(),
        policies=(policy(),), judge_versions=JudgeVersions(
            judge_profile_id=sha("q1-profile"),
            support_boundary_id=sha("boundary")), engine=engine)


def _build(proxy: str = "proxy") -> tuple[
        BuildRegistry, PromotedSemanticCapabilityRegistry]:
    registry = CapabilityRegistry(
        schema_version="semantic-capability-registry.v1",
        semantic_runtime_version=1,
        schemas=(RegistrySchema(
            schema_id="nfs4.1/test", family="nfs4", program=100003,
            version=4, minor_version=1),),
        directions=("C2S",), message_types=("call",),
        target_kinds=("field",), parts=("value",),
        mutation_kinds=("replace",), transforms=("literal",),
        structure_policies=("preserve",), value_sources=("target",),
        predicate_ops=("gt",), constraints=(), limits=RegistryLimits(
            literal_bytes=64, path_bytes=256, predicates_per_rule=4,
            rule_set_bytes=4096, rules=16))
    build = BuildRegistry(proxy_sha256=sha(proxy),
                          registry_digest=registry.digest,
                          registry=registry)
    subset = SemanticSubset(
        subset_id="semantic.nfs4_1.test", description="test subset",
        schema_ids=("nfs4.1/test",), directions=("C2S",),
        message_types=("call",), target_kinds=("field",),
        parts=("value",), mutation_kinds=("replace",),
        transforms=("literal",), structure_policies=("preserve",),
        value_sources=("target",), predicate_ops=("gt",))
    promoted = PromotedSemanticCapabilityRegistry(
        proxy_sha256=build.proxy_sha256,
        registry_digest=build.registry_digest, registry=registry,
        subsets=(PromotedSubset(
            subset=subset,
            validation_items=(ValidationItem.REQUEST_MUTATION,),
            evidence_refs=(sha("evidence"),)),))
    return build, promoted


def test_unconfigured_stage2_is_reported_without_creating_state(tmp_path):
    config = _config(tmp_path)
    path = tmp_path / "stage1.json"
    path.write_text(config.model_dump_json(indent=2))
    report = preflight(path, kvm_path=tmp_path / "absent-kvm")
    assert not report.ready
    assert [(item.name, item.status) for item in report.checks] == [
        ("stage1_config", "pass"), ("stage2_config", "error")]
    assert not config.state_dir.exists()
    assert not config.artifact_root.exists()


def test_job_preflight_uses_read_only_lookup_without_creating_state(tmp_path):
    config = _config(tmp_path)
    path = tmp_path / "stage1.json"
    path.write_text(config.model_dump_json(indent=2))
    report = preflight(path, job_id="job-missing",
                       kvm_path=tmp_path / "absent-kvm")
    assert not report.ready
    assert [(item.name, item.status) for item in report.checks] == [
        ("stage1_config", "pass"), ("stage2_job", "error"),
        ("stage2_config", "error")]
    assert not config.state_dir.exists()
    assert not config.artifact_root.exists()


def test_host_command_requires_input_and_output_placeholders(tmp_path):
    executable = tmp_path / "stage2-step"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    good = SimpleNamespace(argv=(str(executable), "{input}", "{output}"),
                           cwd=tmp_path)
    assert str(executable) in _check_command(good, which=lambda _: None)
    bad = SimpleNamespace(argv=(str(executable), "{input}"), cwd=tmp_path)
    with pytest.raises(PreflightError, match=r"\{output\}"):
        _check_command(bad, which=lambda _: None)


def test_stage2_supervisor_covers_slowdown_scaled_step_budgets(tmp_path):
    collector = CollectorConfig(
        artifact_root=tmp_path, files={}, ssh_key=tmp_path / "id",
        exec_timeout_s=600)
    argv = ("/bin/true", "--campaign-timeout", "1800",
            "--manager-stop-timeout=45", "--exec-slowdown", "10",
            "{input}", "{output}")
    policies = (policy(gate_repetitions=3),)
    budget = stage2_timeout_budget(
        collector, exec_slowdown=10, gate_repetitions=3,
        campaign_timeout_s=1800, manager_stop_timeout_s=45)
    boundary = SimpleNamespace(argv=argv, timeout_s=budget.required_s)
    with pytest.raises(PreflightError, match="supervisor stop reserve"):
        _check_stage2_timeout(boundary, collector, policies)
    reserve = ProcessLimits().stop_reserve_s
    exact = SimpleNamespace(
        argv=argv, timeout_s=budget.required_s + reserve)
    assert "stop reserve" in _check_stage2_timeout(
        exact, collector, policies)
    short = SimpleNamespace(argv=argv, timeout_s=3600)
    with pytest.raises(PreflightError, match="configured lease budget"):
        _check_stage2_timeout(short, collector, policies)
    enough = SimpleNamespace(argv=argv, timeout_s=86_400)
    detail = _check_stage2_timeout(enough, collector, policies)
    assert all(value in detail for value in (
        "gate=", "replay=", "campaign=", "slowdown=10",
        "gate_repetitions=3"))


@pytest.mark.parametrize("argv, message", [
    (("/bin/true", "--exec-slowdown", "0"), "slowdown"),
    (("/bin/true", "--campaign-timeout", "nan"), "finite"),
    (("/bin/true", "--exec-slowdown", "2", "--exec-slowdown=3"),
     "repeats"),
])
def test_stage2_timeout_rejects_invalid_command_options(tmp_path, argv, message):
    collector = CollectorConfig(
        artifact_root=tmp_path, files={}, ssh_key=tmp_path / "id")
    command = SimpleNamespace(argv=argv, timeout_s=86_400)
    with pytest.raises(PreflightError, match=message):
        _check_stage2_timeout(command, collector, (policy(),))


def test_kvm_device_is_opened_and_reports_the_supported_api():
    closed = []
    detail = _check_kvm(
        Path("/dev/null"), opener=lambda path, flags: 17,
        ioctl=lambda fd, request: KVM_API_VERSION,
        closer=closed.append)
    assert "KVM API 12" in detail
    assert closed == [17]
    closed.clear()
    with pytest.raises(PreflightError, match="reported KVM API 11"):
        _check_kvm(
            Path("/dev/null"), opener=lambda path, flags: 18,
            ioctl=lambda fd, request: 11, closer=closed.append)
    assert closed == [18]


def test_kernel_check_does_not_create_an_absent_artifact_root(
        tmp_path, monkeypatch):
    config = _config(tmp_path)
    config.kernel_repo.mkdir()
    monkeypatch.setattr(stage2_host.subprocess, "run", lambda *args, **kwargs:
                        SimpleNamespace(returncode=0,
                                        stdout="a" * 40 + "\n"))
    with pytest.raises(PreflightError, match="artifact root is absent"):
        _check_kernel_repo(config)
    assert not config.artifact_root.exists()


def test_pin_verification_does_not_update_the_collector_cache(
        tmp_path, monkeypatch):
    cache = tmp_path / "pins.json"
    collector = CollectorConfig(
        artifact_root=tmp_path, files={}, ssh_key=tmp_path / "id",
        pin_cache=cache)
    seen = []
    monkeypatch.setattr(stage2_host, "verify_pins",
                        lambda config, descriptor: seen.append(config.pin_cache))
    _verify_pins_read_only(collector, object())
    assert seen == [None]
    assert not cache.exists()


def _manager_config(tmp_path: Path):
    path = tmp_path / "manager.json"
    template = tmp_path / "template"
    template.mkdir()
    lane = template / "lane.sh"
    lane.write_bytes(b"#!/bin/sh\n")
    lane_digest = hashlib.sha256(lane.read_bytes()).hexdigest()

    kernel_obj = tmp_path / "kernel-obj"
    kernel_obj.mkdir()
    syzkaller = tmp_path / "syzkaller"
    syz_bin = syzkaller / "bin/linux_amd64"
    syz_bin.mkdir(parents=True)
    assets = {
        "bzimage": tmp_path / "bzImage",
        "kernel": kernel_obj / "vmlinux",
        "lane-script": lane,
        "vm-image": tmp_path / "guest.qcow2",
        "syz-execprog": syz_bin / "syz-execprog",
        "syz-executor": syz_bin / "syz-executor",
        "syz-manager": syzkaller / "bin/syz-manager",
    }
    for name, asset in assets.items():
        if name == "lane-script":
            continue
        asset.write_bytes((name + "\n").encode())
    assets["syz-manager"].chmod(0o755)
    ssh_key = tmp_path / "id"
    ssh_key.write_text("key\n")
    collector = CollectorConfig(
        artifact_root=tmp_path, files=assets, ssh_key=ssh_key,
        qemu="/bin/true")
    harness = _ApprovedHarness(
        harness_id="a" * 64,
        command_line=("root=/dev/sda", "console=ttyS0", "nokaslr",
                      "nfs.localio_enabled=N"),
        pins=tuple((name, pin_file(name, asset))
                   for name, asset in assets.items()))
    manager = {
        "type": "qemu", "target": "linux/amd64", "procs": 1,
        "workdir_template": str(template),
        "kernel_obj": str(kernel_obj), "syzkaller": str(syzkaller),
        "image": str(assets["vm-image"]), "sshkey": str(ssh_key),
        "experimental": {"remote_cover": True, "nfs_proxy_window": 8},
        "vm": {"count": 1, "kernel": str(assets["bzimage"]),
               "cmdline": ("root=/dev/sda console=ttyS0 nokaslr "
                           "nfs.localio_enabled=N "
                           "koov.nfs_version=4.1 koov.nfs_target=1 "
                           f"koov.lane_sha256={lane_digest}"),
               "qemu_args": ("-enable-kvm "
                             "-device virtserialport,name=nfsp-journal-0")},
    }
    path.write_text(json.dumps(manager))
    command = SimpleNamespace(
        argv=("/bin/true", "--manager", str(path), "{input}", "{output}"),
        cwd=tmp_path)
    return path, manager, lane, collector, (harness,), command


def _manager_check(path, collector, harnesses, command):
    return _check_manager(
        path, 4, command=command, collector=collector,
        harnesses=harnesses, expected_target="linux/amd64",
        which=lambda _: None)


def test_manager_config_binds_approved_assets_and_command(tmp_path):
    path, manager, lane, collector, harnesses, command = \
        _manager_config(tmp_path)
    assert "approved assets" in _manager_check(
        path, collector, harnesses, command)
    image = Path(manager["image"])
    image.write_bytes(b"wrong image\n")
    with pytest.raises(RuntimeError, match="does not match its pin"):
        _manager_check(path, collector, harnesses, command)
    image.write_bytes(b"vm-image\n")
    unbound = SimpleNamespace(argv=("/bin/true", "{input}", "{output}"),
                              cwd=tmp_path)
    with pytest.raises(PreflightError, match="explicit Stage 2 command"):
        _manager_check(path, collector, harnesses, unbound)
    manager["target"] = "linux/arm64"
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="approved linux/amd64"):
        _manager_check(path, collector, harnesses, command)
    manager["target"] = "linux/amd64"
    approved_cmdline = manager["vm"]["cmdline"]
    manager["vm"]["cmdline"] += " sunrpc.lane_attribution=0"
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="approved command line"):
        _manager_check(path, collector, harnesses, command)
    manager["vm"]["cmdline"] = approved_cmdline
    manager["vm"]["cmdline"] = manager["vm"]["cmdline"].replace(
        "nokaslr ", "")
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="approved command line"):
        _manager_check(path, collector, harnesses, command)


def test_manager_rejects_stage1_only_nlm_fixture(tmp_path):
    path, manager, _, collector, harnesses, command = _manager_config(tmp_path)
    manager["vm"]["cmdline"] = manager["vm"]["cmdline"].replace(
        "koov.nfs_version=4.1", "koov.nfs_fixture=nlm-knfsd")
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="unapproved dynamic argument"):
        _manager_check(path, collector, harnesses, command)


def _job_readiness(fixture="nlm-knfsd", stage2_hcap=False):
    binding = SimpleNamespace(execution_harness_id="a" * 64,
                              hcap_revision="b" * 64)
    materialized = SimpleNamespace(
        harness_ref="c" * 64, execution_harness_id=binding.execution_harness_id,
        hcap_revision=binding.hcap_revision, authority_hcap_revision=None)
    job = SimpleNamespace(
        job_id="job-test", state=JobState.S1_REACHED, binding=binding,
        harness=materialized,
        stage2_input=SimpleNamespace(harness_ref=materialized.harness_ref,
                                     execution_harness_id=binding.execution_harness_id,
                                     plan_ref="d" * 64))
    harness = SimpleNamespace(
        execution_harness_id=binding.execution_harness_id,
        hcap_revision=binding.hcap_revision,
        plan_ref=job.stage2_input.plan_ref,
        required_capability_ids=("HCAP-13",) if fixture == "nlm-knfsd" else (),
        selected_capability_ids=("HCAP-13",) if fixture == "nlm-knfsd" else (),
        runtime_selection=SimpleNamespace(fixture_mode=fixture,
                                          nfs_version="3" if fixture == "nlm-knfsd" else "4.1"))
    hcap = SimpleNamespace(capabilities=(SimpleNamespace(
        id="HCAP-13", usable_stage=("stage1", "stage2") if stage2_hcap else ("stage1",),
        usable_by=("agent_stage1", "agent_stage2") if stage2_hcap else ("agent_stage1",)),))
    manager = {"vm": {"cmdline": "root=/dev/sda " + (
        "koov.nfs_fixture=nlm-knfsd" if fixture == "nlm-knfsd" else
        "koov.nfs_version=4.1")}}
    return job, harness, hcap, manager, (binding,)


def test_job_readiness_rejects_nlm_even_if_hcap_is_promoted():
    arguments = _job_readiness()
    with pytest.raises(PreflightError, match="HCAP-13 is approved for Stage 1 only"):
        _check_stage2_job(*arguments)
    arguments = _job_readiness(stage2_hcap=True)
    with pytest.raises(PreflightError, match="promoted NLM Proxy"):
        _check_stage2_job(*arguments)


def test_job_authority_checks_reached_identity_before_manager_config():
    job, harness, hcap, _, _ = _job_readiness()
    with pytest.raises(PreflightError, match="Stage 1 only"):
        _check_job_authority(job, harness, hcap)
    job.state = JobState.S1_RUNNING
    with pytest.raises(PreflightError, match="reached Stage 2 basis"):
        _check_job_authority(job, harness, hcap)


def test_job_authority_accepts_revalidated_hcap_without_changing_harness():
    job, harness, hcap, manager, _ = _job_readiness("single")
    original = job.harness.hcap_revision
    job.binding.hcap_revision = "e" * 64
    job.harness.authority_hcap_revision = job.binding.hcap_revision
    assert "approved single fixture" in _check_stage2_job(
        job, harness, hcap, manager, (job.binding,))
    assert harness.hcap_revision == original
    job.harness.authority_hcap_revision = None
    with pytest.raises(PreflightError, match="approved harness"):
        _check_job_authority(job, harness, hcap)


def test_job_authority_rejects_wrong_plan_and_unbound_hcap13():
    job, harness, hcap, _, _ = _job_readiness("single")
    harness.plan_ref = "f" * 64
    with pytest.raises(PreflightError, match="approved harness"):
        _check_job_authority(job, harness, hcap)
    harness.plan_ref = job.stage2_input.plan_ref
    harness.selected_capability_ids = ("HCAP-13",)
    with pytest.raises(PreflightError, match="non-NLM runtime selection"):
        _check_job_authority(job, harness, hcap)


def test_job_readiness_binds_manager_fixture_and_preserves_nfs4_path():
    job, harness, hcap, manager, bindings = _job_readiness("single")
    assert "approved single fixture" in _check_stage2_job(
        job, harness, hcap, manager, bindings)
    manager["vm"]["cmdline"] = "koov.nfs_fixture=broad-knfsd"
    with pytest.raises(PreflightError, match="manager fixture differs"):
        _check_stage2_job(job, harness, hcap, manager, bindings)


def test_job_lookup_does_not_create_a_missing_controller_database(tmp_path):
    with pytest.raises(FileNotFoundError):
        _load_job_read_only(tmp_path, "job-missing")
    assert not (tmp_path / "controller.sqlite").exists()


def test_job_lookup_reads_existing_database_without_mutating_it(tmp_path):
    job = Job(
        job_id="job-test", job_policy_id="test-policy",
        submission=CandidateSubmission(
            kernel_commit="a" * 40,
            location=LocationRequest(
                kind=LocationKind.FUNCTION, path="test.c", symbol="test")))
    database = tmp_path / "controller.sqlite"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE jobs (job_id TEXT PRIMARY KEY, body TEXT)")
        db.execute("INSERT INTO jobs VALUES (?, ?)",
                   (job.job_id, job.model_dump_json()))
    original = database.read_bytes()
    assert _load_job_read_only(tmp_path, job.job_id) == job
    with pytest.raises(PreflightError, match="job is absent"):
        _load_job_read_only(tmp_path, "job-other")
    assert database.read_bytes() == original


def test_manager_config_binds_window_lane_script_and_all_proc_journals(
        tmp_path):
    path, manager, lane, collector, harnesses, command = \
        _manager_config(tmp_path)
    assert "window=8" in _manager_check(path, collector, harnesses, command)
    manager["snapshot"] = True
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="snapshot mode must be false"):
        _manager_check(path, collector, harnesses, command)
    del manager["snapshot"]
    path.write_text(json.dumps(manager))
    lane.write_bytes(b"changed\n")
    with pytest.raises(PreflightError, match="differs from koov.lane_sha256"):
        _manager_check(path, collector, harnesses, command)
    old_digest = hashlib.sha256(b"#!/bin/sh\n").hexdigest()
    new_digest = hashlib.sha256(b"changed\n").hexdigest()
    manager["vm"]["cmdline"] = manager["vm"]["cmdline"].replace(
        old_digest, new_digest)
    path.write_text(json.dumps(manager))
    with pytest.raises(RuntimeError, match="lane-script.*does not match its pin"):
        _manager_check(path, collector, harnesses, command)
    lane.write_bytes(b"#!/bin/sh\n")
    manager["vm"]["cmdline"] = manager["vm"]["cmdline"].replace(
        new_digest, old_digest)
    manager["procs"] = 2
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="lanes: 1"):
        _manager_check(path, collector, harnesses, command)
    manager["procs"] = 1
    manager["experimental"]["nfs_proxy_window"] = 3
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="at least 4"):
        _manager_check(path, collector, harnesses, command)


def test_promoted_runtime_must_match_every_harness():
    build, promoted = _build()
    assert _check_runtime(Path("/proxy"), (promoted,),
                          reader=lambda _: build) == build
    other, _ = _build("other")
    with pytest.raises(PreflightError, match="not the promoted"):
        _check_runtime(Path("/proxy"), (promoted,), reader=lambda _: other)


def test_operator_start_and_placeholder_thresholds_are_warnings():
    checks = _Checks()
    _check_policies((policy(),), checks)
    assert [(item.name, item.status) for item in checks.items] == [
        ("stage2_policy", "warning"), ("campaign_policy", "warning")]
    checks = _Checks()
    changed = policy(run_stage2=True, fuzz_budget_executions=1234)
    _check_policies((changed,), checks)
    assert all(item.status == "pass" for item in checks.items)
