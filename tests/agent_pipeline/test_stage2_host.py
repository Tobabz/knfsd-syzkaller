"""Read-only Stage 2 KVM readiness checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import agent_pipeline.stage2.host as stage2_host
from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.contracts import JudgeVersions
from agent_pipeline.semantic_promotion import (
    BuildRegistry, CapabilityRegistry, PromotedSemanticCapabilityRegistry,
    PromotedSubset, RegistryLimits, RegistrySchema, SemanticSubset,
    ValidationItem,
)
from agent_pipeline.stage1.config import EngineConfig, Stage1Config
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage2.host import (
    PreflightError, _Checks, _check_command, _check_kernel_repo,
    _check_manager, _check_policies, _check_runtime,
    _verify_pins_read_only, preflight,
)

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


def test_manager_config_binds_window_target_mode_and_journal(tmp_path):
    path = tmp_path / "manager.json"
    template = tmp_path / "template"
    template.mkdir()
    lane = template / "lane.sh"
    lane.write_bytes(b"#!/bin/sh\n")
    lane_digest = hashlib.sha256(lane.read_bytes()).hexdigest()
    manager = {
        "type": "qemu", "workdir_template": str(template),
        "experimental": {"remote_cover": True, "nfs_proxy_window": 8},
        "vm": {"count": 1,
               "cmdline": ("nokaslr nfs.localio_enabled=N "
                           f"koov.nfs_target=1 koov.lane_sha256={lane_digest}"),
               "qemu_args": ("-enable-kvm "
                             "-device virtserialport,name=nfsp-journal-0")},
    }
    path.write_text(json.dumps(manager))
    assert "window=8" in _check_manager(path, 4)
    lane.write_bytes(b"changed\n")
    with pytest.raises(PreflightError, match="differs from koov.lane_sha256"):
        _check_manager(path, 4)
    lane.write_bytes(b"#!/bin/sh\n")
    manager["experimental"]["nfs_proxy_window"] = 3
    path.write_text(json.dumps(manager))
    with pytest.raises(PreflightError, match="at least 4"):
        _check_manager(path, 4)


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
