"""Identity and failure-evidence checks for the NFS lifecycle campaign."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import Sanitizer
from agent_pipeline.data import put_record
from agent_pipeline.hcap import RuntimeSelection
from agent_pipeline.materializer import (
    ExecutionHarnessDescriptor,
    HarnessBuildArtifact,
    descriptor_id,
)
from agent_pipeline.q1 import CandidateTarget, KernelIdentity, TargetPcMapping
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage1.host.pins import pin_file


REPO = Path(__file__).resolve().parents[2]
RUNNER = REPO / "tools/nfs-lifecycle/run.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("nfs_lifecycle_run", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_identity_inputs(tmp_path):
    runner = load_runner()
    store = ArtifactStore(tmp_path / "cas")
    file_names = (
        "bzimage", "kernel", "lane-script", "syz-execprog",
        "syz-executor", "vm-image",
    )
    files = {}
    artifacts = []
    lane_dir = tmp_path / "lane"
    lane_dir.mkdir()
    for name in file_names:
        path = (lane_dir / "lane.sh" if name == "lane-script"
                else tmp_path / name)
        path.write_bytes((name + " pinned bytes\n").encode())
        files[name] = path
        artifacts.append(HarnessBuildArtifact(
            name=name, artifact_ref=put_record(store, pin_file(name, path))))
    instrumentation_ref = store.put(b"instrumentation manifest")
    artifacts.append(HarnessBuildArtifact(
        name="instrumentation", artifact_ref=instrumentation_ref))
    artifacts.sort(key=lambda item: item.name)

    identity = SyzkallerTargetIdentity(
        syzkaller_commit="b" * 40,
        patch_series_sha256="1" * 64,
        build_manifest_sha256="2" * 64,
        call_table_sha256="3" * 64,
        target="linux/amd64")
    selection = RuntimeSelection(
        profile="knfsd-v41", nfs_version="4.1", fixture_mode="single",
        route="direct", topology="one-lane",
        enabled_interfaces=tuple(sorted(runner.ADMIN_REQUIRED_INTERFACES)),
        trace_mode="off")
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit="a" * 40, sanitizer=Sanitizer.KASAN,
        syzkaller_identity=identity, build_artifacts=tuple(artifacts),
        guest_kernel_command_line=(
            "root=/dev/sda console=ttyS0 nokaslr nfs.localio_enabled=N"),
        allowed_runtime_selections=(selection,))
    descriptor_path = tmp_path / "descriptor.json"
    descriptor_path.write_text(descriptor.model_dump_json(indent=2))

    ssh_key = tmp_path / "ssh-key"
    ssh_key.write_text("private test key\n")
    config = CollectorConfig(
        artifact_root=store.root, files=files, ssh_key=ssh_key)
    config_path = tmp_path / "collector.json"
    config_path.write_text(config.model_dump_json(indent=2))

    builds = {item.name: item.artifact_ref
              for item in descriptor.build_artifacts}
    mapping_identity = KernelIdentity(
        execution_harness_id=descriptor_id(descriptor),
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds["instrumentation"],
        vmlinux_sha256=builds["kernel"],
        kaslr_enabled=False, kaslr_offset=0)
    mapping = TargetPcMapping(
        mapping_method="synthetic verified fixture", verified=True,
        target=CandidateTarget(
            candidate_id="private-candidate", kernel_commit="a" * 40,
            kind="function", path="fs/nfsd/private.c",
            symbol="private_symbol", start_line=10, end_line=20),
        identity=mapping_identity,
        target_pcs=(0xffffffff81001234,))
    mapping_path = tmp_path / "mapping.json"
    mapping_path.write_text(mapping.model_dump_json(indent=2))
    return runner, config_path, descriptor_path, mapping_path, mapping


def test_admin_context_binds_mapping_to_verified_harness_without_leaking_target(
        tmp_path):
    runner, config, descriptor, mapping_path, _ = write_identity_inputs(
        tmp_path)
    context = runner.load_admin_context(config, descriptor, mapping_path)
    assert context.target_pcs == frozenset((0xffffffff81001234,))
    shareable = json.dumps(context.evidence_identity, sort_keys=True)
    for private in (
            "private-candidate", "fs/nfsd/private.c", "private_symbol",
            "0xffffffff81001234"):
        assert private not in shareable


def test_admin_context_refuses_mapping_from_another_harness(tmp_path):
    runner, config, descriptor, mapping_path, mapping = write_identity_inputs(
        tmp_path)
    bad = mapping.model_copy(update={
        "identity": mapping.identity.model_copy(update={
            "execution_harness_id": "e" * 64})})
    mapping_path.write_text(bad.model_dump_json(indent=2))
    with pytest.raises(RuntimeError, match="exact execution harness"):
        runner.load_admin_context(config, descriptor, mapping_path)


class FailedExecGuest:
    def __init__(self, runner):
        self.runner = runner
        self.released = False

    def guest(self, command, timeout=60):
        if command.startswith("if test -f "):
            return "exited\n" if self.released else "ready\n"
        if command == self.runner.STATE_COMMAND:
            return ("owner 1 state COMMITTED outstanding_tokens 0 "
                    "active_roots 0\n")
        if command == self.runner.STATS_COMMAND:
            return "raw generation counters\n"
        if command.startswith("wc -l < "):
            return "4\n"
        if command == "touch %s.go" % self.runner.ADMIN_GATE:
            self.released = True
            return ""
        if command == "cat %s" % self.runner.ADMIN_RC:
            return "7\n"
        if command == "cat %s" % self.runner.ADMIN_LOG:
            return "executor failed after gate\n"
        if command.startswith("cat ") and command.endswith("/trace"):
            return "trace retained\n"
        if command.startswith("tail -n +"):
            return "lifecycle retained\n"
        if command.startswith("find /tmp/cov "):
            return "cover.0\ncover.extra\ncover.meta\n"
        if command == "cat /tmp/cov/cover.extra":
            return "0xffffffff81001234\n"
        if command == "cat /tmp/cov/cover.meta":
            return "completed_unix_nano 1\n"
        if command == "cat /tmp/cov/cover.0":
            return "0x1\n"
        return ""


def test_admin_exec_failure_retains_all_available_raw_artifacts(tmp_path):
    runner = load_runner()
    guest = FailedExecGuest(runner)
    with pytest.raises(RuntimeError, match="rc=7"):
        runner.run_admin_program(
            guest, tmp_path, "stimulus", 1, "/sys/kernel/tracing",
            {0xffffffff81001234})
    stem = "stimulus-001."
    expected = (
        "executor.log", "stats-before.txt", "stats-after.txt",
        "state-before.txt", "state-after.txt", "trace.txt",
        "lifecycle.log", "coverage-files.txt", "coverage.extra",
        "coverage.meta", "coverage.raw.cover.0",
        "coverage.raw.cover.extra", "coverage.raw.cover.meta",
    )
    for suffix in expected:
        assert (tmp_path / (stem + suffix)).is_file(), suffix
    assert "executor failed" in (
        tmp_path / (stem + "executor.log")).read_text()
