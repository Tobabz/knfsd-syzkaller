"""Read-only Stage 2 KVM readiness checks."""

from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_pipeline.stage2.host as stage2_host
from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import put_record
from agent_pipeline.hcap import HcapCatalog
from agent_pipeline.contracts import JudgeVersions
from agent_pipeline.runner.process_supervisor import ProcessLimits
from agent_pipeline.semantic_promotion import (
    BuildRegistry, CapabilityRegistry, PromotedSemanticCapabilityRegistry,
    PromotedSubset, RegistryLimits, RegistrySchema, SemanticSubset,
    ValidationItem, with_semantic_capability,
)
from agent_pipeline.stage1.config import EngineConfig, Stage1Config
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage1.host.pins import pin_file
from agent_pipeline.stage2.host import (
    KVM_API_VERSION, PreflightError, _ApprovedHarness, _Checks,
    _check_accel, _check_command, _check_kernel_repo, _check_kvm,
    _check_manager, _check_policies, _check_runtime, _check_stage2_timeout,
    _shared_registry, _verify_pins_read_only, preflight,
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
                   for name, asset in assets.items()),
        fixtures=frozenset({("koov.nfs_version=4.1", "0"),
                            ("koov.nfs_fixture=broad-knfsd", "0")}))
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
    manager["sandbox"] = "namespace"
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="sandbox must be none"):
        _manager_check(path, collector, harnesses, command)
    del manager["sandbox"]
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


def test_manager_accelerator_matches_the_collector(tmp_path):
    path, manager, lane, collector, harnesses, command = \
        _manager_config(tmp_path)
    tcg = collector.model_copy(update={"accel": "tcg", "exec_slowdown": 10})
    with pytest.raises(PreflightError, match="collector's tcg"):
        _manager_check(path, tcg, harnesses, command)
    manager["vm"]["qemu_args"] = manager["vm"]["qemu_args"].replace(
        "-enable-kvm", "-accel tcg,thread=multi -cpu max")
    path.write_text(json.dumps(manager))
    assert "approved assets" in _manager_check(path, tcg, harnesses, command)
    with pytest.raises(PreflightError, match="collector's kvm"):
        _manager_check(path, collector, harnesses, command)
    assert "TCG" in _check_accel(tcg, tmp_path / "absent-kvm")
    with pytest.raises(PreflightError, match="unavailable"):
        _check_accel(collector, tmp_path / "absent-kvm")


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


def test_manager_fixture_is_an_approved_stage2_runtime_selection(tmp_path):
    # #81 D17: the allowed fixtures are the descriptor's runtime selections.
    path, manager, lane, collector, harnesses, command = \
        _manager_config(tmp_path)
    approved_cmdline = manager["vm"]["cmdline"]

    def check(old, new):
        manager["vm"]["cmdline"] = approved_cmdline.replace(old, new)
        path.write_text(json.dumps(manager))
        return _manager_check(path, collector, harnesses, command)
    assert "approved assets" in check(
        "koov.nfs_version=4.1", "koov.nfs_fixture=broad-knfsd")
    assert "approved assets" in check(
        "koov.nfs_target=1", "koov.nfs_target=1 koov.nfs_trace=0")
    with pytest.raises(PreflightError, match="koov.nfs_trace=1"):
        check("koov.nfs_target=1", "koov.nfs_target=1 koov.nfs_trace=1")
    with pytest.raises(PreflightError, match="no Stage 2 runtime selection"):
        check("koov.nfs_version=4.1", "koov.nfs_version=4.2")
    with pytest.raises(PreflightError, match="unapproved dynamic argument"):
        check("koov.nfs_target=1", "koov.nfs_target=0")
    with pytest.raises(PreflightError, match="one approved NFS fixture"):
        check("koov.nfs_version=4.1",
              "koov.nfs_version=4.1 koov.nfs_fixture=broad-knfsd")


def test_nlm_fixture_stays_a_stage1_selection():
    from agent_pipeline.stage2.host import _stage2_fixtures
    from .test_materializer import runtime
    assert _stage2_fixtures((
        runtime(), runtime(trace_mode="on"),
        runtime(fixture_mode="broad-knfsd"),
        runtime(fixture_mode="nlm-knfsd", nfs_version="3",
                profile="knfsd-v3"))) == {
        ("koov.nfs_version=4.1", "0"), ("koov.nfs_version=4.1", "1"),
        ("koov.nfs_fixture=broad-knfsd", "0")}


def test_manager_runs_the_variant_whose_kernel_it_boots(tmp_path):
    # #81 D10: sanitizer variants differ in their kernel only.
    path, manager, lane, collector, harnesses, command = \
        _manager_config(tmp_path)
    (kasan,) = harnesses
    other = tmp_path / "kcsan"
    other.mkdir()
    pins = dict(kasan.pins)
    for name in ("bzimage", "kernel"):
        (other / name).write_bytes(f"kcsan {name}\n".encode())
        pins[name] = pin_file(name, other / name)
    kcsan = dataclasses.replace(kasan, harness_id="b" * 64,
                                pins=tuple(pins.items()))
    assert "approved assets" in _manager_check(
        path, collector, (kasan, kcsan), command)
    manager["vm"]["kernel"] = str(other / "bzimage")
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="no approved harness's"):
        _manager_check(path, collector, (kasan, kcsan), command)


def test_promoted_runtime_must_match_every_harness():
    build, promoted = _build()
    assert _check_runtime(Path("/proxy"), (promoted,),
                          reader=lambda _: build) == build
    other, _ = _build("other")
    with pytest.raises(PreflightError, match="not the promoted"):
        _check_runtime(Path("/proxy"), (promoted,), reader=lambda _: other)


def test_a_shared_binding_takes_no_pending_subset(tmp_path):
    # 03-nfs-proxy/06 §30: a staged pin is only a staged revision's.
    store = ArtifactStore(tmp_path / "cas")
    _, promoted = _build()

    def hcap(registry):
        return with_semantic_capability(
            HcapCatalog(capabilities=(), missing_capability_ids=()), put_record(store, registry), registry)

    assert _shared_registry(store, hcap(promoted), "a" * 64) == promoted
    pending = promoted.model_copy(update={"subsets": tuple(
        s.model_copy(update={"crash_survival": "pending"})
        for s in promoted.subsets)})
    with pytest.raises(PreflightError, match="crash survival pending"):
        _shared_registry(store, hcap(pending), "a" * 64)
    with pytest.raises(PreflightError, match="no promoted semantic subset"):
        _shared_registry(store, HcapCatalog(capabilities=(), missing_capability_ids=()), "a" * 64)


def test_a_shared_binding_takes_a_subset_promoted_on_the_durability_check(
        tmp_path):
    # #142: not_observed is promoted, unlike a staged pin: the preflight's
    # authority check passes and the HCAP-10 entry says no crash was seen.
    store = ArtifactStore(tmp_path / "cas")
    _, promoted = _build()
    unobserved = promoted.model_copy(update={"subsets": tuple(
        s.model_copy(update={"natural_crash_reproduction": "not_observed",
                             "durability_ref": "d" * 64})
        for s in promoted.subsets)})
    catalog = with_semantic_capability(
        HcapCatalog(capabilities=(), missing_capability_ids=()),
        put_record(store, unobserved), unobserved)
    assert _shared_registry(store, catalog, "a" * 64) == unobserved
    entry = next(c for c in catalog.capabilities if c.id == "HCAP-10")
    assert any("not observed" in c for c in entry.constraints)


def test_operator_start_and_placeholder_thresholds_are_warnings():
    checks = _Checks()
    _check_policies((policy(),), checks)
    assert [(item.name, item.status) for item in checks.items] == [
        ("stage2_policy", "warning"), ("campaign_policy", "warning")]
    checks = _Checks()
    changed = policy(run_stage2=True, fuzz_budget_executions=1234)
    _check_policies((changed,), checks)
    assert all(item.status == "pass" for item in checks.items)


def test_manager_stays_inside_the_validated_layouts(tmp_path):
    # #99: procs above a capability's validated layout refuse its calls
    # and its runtime features; the manager's other checks still run.
    from dataclasses import replace

    from agent_pipeline.hcap import HcapCatalog
    path, manager, _, collector, harnesses, command = \
        _manager_config(tmp_path)
    catalog = HcapCatalog.model_validate({
        "capabilities": (
            {"id": "CAP-lane", "name": "lane", "purpose": "lane",
             "usable_stage": ("stage2",), "usable_by": ("agent_stage2",),
             "interface": {"syz_calls": ("openat$lane",)},
             "status": "validated", "scope": ("lane",),
             "validated_layout": {"procs": 2, "lanes": (0, 1)}},
            {"id": "CAP-observe", "name": "kcov", "purpose": "kcov",
             "usable_stage": ("stage2",), "usable_by": ("agent_stage2",),
             "interface": {"runtime_features": ("remote_cover",)},
             "status": "validated", "scope": ("generation",),
             "validated_layout": {"procs": 2, "lanes": (0, 1)}},
            {"id": "CAP-one", "name": "one lane", "purpose": "lane 0",
             "usable_stage": ("stage2",), "usable_by": ("agent_stage2",),
             "interface": {"syz_calls": ("syz_lane0_only",)},
             "status": "validated", "scope": ("lane0",)}),
        "missing_capability_ids": ()}, strict=False)
    profile = SimpleNamespace(entries=(
        SimpleNamespace(call="openat$lane", capability_ids=("CAP-lane",)),
        SimpleNamespace(call="syz_lane0_only", capability_ids=("CAP-one",))))
    harnesses = tuple(replace(item, authorities=((catalog, profile),))
                      for item in harnesses)
    manager["procs"] = 2
    manager["vm"]["qemu_args"] += \
        " -device virtserialport,name=nfsp-journal-1"
    manager["enable_syscalls"] = ["openat$lane", "close"]
    path.write_text(json.dumps(manager))
    assert "2 proc(s)" in _manager_check(path, collector, harnesses, command)
    manager["enable_syscalls"] = ["openat$lane", "syz_lane0_only"]
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match=r"call_outside_validated_layout:"
                       r"syz_lane0_only"):
        _manager_check(path, collector, harnesses, command)
    # Without enable_syscalls syz-manager enables every call.
    del manager["enable_syscalls"]
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="syz_lane0_only"):
        _manager_check(path, collector, harnesses, command)
    manager["enable_syscalls"] = ["openat$lane"]
    manager["procs"] = 3
    manager["vm"]["qemu_args"] += \
        " -device virtserialport,name=nfsp-journal-2"
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match=r"openat\$lane"):
        _manager_check(path, collector, harnesses, command)
    manager["enable_syscalls"] = []
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="runtime_feature_outside_"
                       "validated_layout:remote_cover"):
        _manager_check(path, collector, harnesses, command)
