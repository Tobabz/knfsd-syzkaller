"""Host-only tests for the real Stage 2 KVM step command."""

from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import put_record
from agent_pipeline.journal_sink import CHANNEL_CLOSE_TIMEOUT_S
from agent_pipeline.stage1.host.collector import (EVIDENCE_COMMAND_TIMEOUT_S,
                                                  EXECPROG_EXIT_GRACE_S, POLL_S,
                                                  CollectorConfig, execprog_argv,
                                                  execprog_timeout)
from agent_pipeline.stage1.host.pins import PinError, pin_file
from agent_pipeline.stage1.host.vm import (GUEST_COMMAND_TIMEOUT_S,
                                           GUEST_TRANSFER_TIMEOUT_S,
                                           VM_STOP_TIMEOUT_S, QemuGuest,
                                           VmConfig)
from agent_pipeline.stage2.kvm import (
    EVIDENCE_SEAL_RESERVE_S, MANAGER_SIGNAL_TIMEOUT_S, MAX_JOURNAL_CHANNELS,
    NfsProxyExecution, Stage2StepError, _Artifact,
    _barrier_generation, _campaign_records, _corpus, _correlated,
    _journal_artifacts, _journal_lane_count, _lane_template,
    _manager_assets, _manager_cmdline, _manager_qemu_args,
    _seal_segment, _spool, _stop_manager, StepOptions, stage2_timeout_budget,
)

from .stage2_host import rules_bytes


def execution_record(**updates) -> dict:
    value = {
        "schema_version": "knfsd-nfs-proxy-execution.v2",
        "vm": 0, "lane": 0, "execution_id": 7,
        "campaign": True,
        "program_sha256": "a" * 64, "generation": 11,
        "program_digest": "b" * 64,
        "activation": "Acked", "activation_status": 0,
        "deactivation": "Acked", "deactivation_status": 0,
        "executed": True, "lease_cleared": True,
        "hanged": False, "error": "", "pcs": [3, 9],
    }
    value.update(updates)
    return value


def test_direct_execprog_slowdown_is_explicit_and_bounded(tmp_path):
    assert "-slowdown=1" in execprog_argv(60)
    assert "-slowdown=10" in execprog_argv(60, 10)
    assert "timeout --kill-after=60 600 " in execprog_argv(60, 10)
    assert execprog_timeout(60, 10) == 600
    with pytest.raises(ValueError, match="slowdown"):
        execprog_argv(60, 0)
    assert StepOptions(
        manager=tmp_path / "manager.json",
        collector=tmp_path / "collector.json",
        exec_slowdown=10,
    ).exec_slowdown == 10
    with pytest.raises(ValueError, match="exec_slowdown"):
        StepOptions(
            manager=tmp_path / "manager.json",
            collector=tmp_path / "collector.json",
            exec_slowdown=0,
        )


def test_stage2_timeout_budget_accounts_for_every_bounded_operation(tmp_path):
    collector = CollectorConfig(
        artifact_root=tmp_path, files={}, ssh_key=tmp_path / "id",
        boot_timeout_s=2, fixture_timeout_s=3, grace_s=4, drain_s=5,
        exec_timeout_s=6)
    budget = stage2_timeout_budget(
        collector, exec_slowdown=10, gate_repetitions=3,
        campaign_timeout_s=7, manager_stop_timeout_s=8)
    direct = execprog_timeout(collector.exec_timeout_s, 10)
    direct_gate = direct + EXECPROG_EXIT_GRACE_S + POLL_S
    close = (2 * VM_STOP_TIMEOUT_S
             + MAX_JOURNAL_CHANNELS * CHANNEL_CLOSE_TIMEOUT_S
             + EVIDENCE_SEAL_RESERVE_S)
    scenario = (
        collector.boot_timeout_s + collector.fixture_timeout_s
        + collector.grace_s + collector.drain_s + direct_gate
        + 10 * GUEST_COMMAND_TIMEOUT_S
        + 3 * EVIDENCE_COMMAND_TIMEOUT_S
        + 4 * GUEST_TRANSFER_TIMEOUT_S)
    neutral = (
        collector.drain_s + direct_gate
        + 2 * GUEST_COMMAND_TIMEOUT_S
        + 2 * EVIDENCE_COMMAND_TIMEOUT_S
        + 2 * GUEST_TRANSFER_TIMEOUT_S)
    assert budget.gate_repetition_s == scenario + neutral + close
    assert budget.gate_s == 3 * budget.gate_repetition_s
    assert budget.replay_s == (
        collector.boot_timeout_s + collector.fixture_timeout_s + direct
        + 5 * GUEST_COMMAND_TIMEOUT_S
        + 3 * GUEST_TRANSFER_TIMEOUT_S + close)
    assert budget.campaign_s == (
        7 + 2 * (8 + 2 * MANAGER_SIGNAL_TIMEOUT_S)
        + MAX_JOURNAL_CHANNELS * CHANNEL_CLOSE_TIMEOUT_S
        + EVIDENCE_SEAL_RESERVE_S)
    assert budget.required_s == budget.gate_s


def test_spool_records_are_strict_and_ordered(tmp_path):
    (tmp_path / "00000000000000000001.json").write_text(
        json.dumps(execution_record(execution_id=2)))
    (tmp_path / "00000000000000000000.json").write_text(
        json.dumps(execution_record(execution_id=1)))
    records = _spool(tmp_path)
    assert [item.execution_id for item in records] == [1, 2]
    assert records[0].pcs == (3, 9)
    with pytest.raises(ValueError):
        NfsProxyExecution.model_validate_json(
            json.dumps(execution_record(pcs=[-1])))


def test_only_generation_attributed_target_execution_counts_as_campaign_work():
    def record(**updates):
        return NfsProxyExecution.model_validate_json(
            json.dumps(execution_record(**updates)))

    assert _correlated(record())
    assert not _correlated(record(
        generation=0, program_digest="", activation="", executed=False))
    assert not _correlated(record(activation="Refused"))

    setup = record(campaign=False, generation=1, program_sha256="c" * 64)
    seed = record(generation=2, program_sha256="a" * 64)
    fuzz = record(generation=3, program_sha256="d" * 64)
    uncorrelated = record(
        generation=0, program_digest="", activation="", executed=False)
    span, campaign = _campaign_records(
        [setup, uncorrelated, seed, uncorrelated, fuzz])
    assert span == [uncorrelated, seed, uncorrelated, fuzz]
    assert campaign == [seed, fuzz]


def test_one_program_corpus_is_syzkaller_db_v2_corpus_v5(tmp_path):
    program = b"getpid()\n"
    path = tmp_path / "corpus.db"
    _corpus(path, program)
    raw = path.read_bytes()
    magic, version, corpus_version = struct.unpack_from("<IIQ", raw)
    assert (magic, version, corpus_version) == (0xBADDB, 2, 5)
    record_magic, key_length = struct.unpack_from("<II", raw, 16)
    assert record_magic == 0xFEE1BAD
    offset = 24 + key_length
    sequence, compressed_length = struct.unpack_from("<QI", raw, offset)
    compressed = raw[offset + 12:offset + 12 + compressed_length]
    assert sequence == 0
    assert zlib.decompress(compressed, wbits=-15) == program


def test_lane_template_replaces_frozen_target_inputs(tmp_path):
    source = tmp_path / "source"
    target = source / "target"
    target.mkdir(parents=True)
    (source / "lane.sh").write_text("#!/bin/sh\n")
    old_rule = target / "lane0.nfsprul1"
    old_session = target / "lane0.session"
    old_rule.write_bytes(b"old")
    old_session.write_text("old\n")
    old_rule.chmod(0o444)
    old_session.chmod(0o444)
    rules = rules_bytes("candidate")
    result = _lane_template(source, tmp_path / "copy", rules, ("prefix",))
    assert (result / "target/lane0.nfsprul1").read_bytes() == rules
    assert (result / "target/lane0.session").read_text() == "prefix\n"


def test_journal_lane_count_uses_complete_fixture_topology():
    vm = {"qemu_args": "-enable-kvm " + " ".join(
        f"-device virtserialport,name=nfsp-journal-{lane}"
        for lane in range(4))}
    assert _journal_lane_count(vm, procs=1) == 4
    with pytest.raises(Stage2StepError, match="not contiguous"):
        _journal_lane_count(
            {"qemu_args": ("-enable-kvm -device "
                           "virtserialport,name=nfsp-journal-1")}, 1)
    with pytest.raises(Stage2StepError, match="duplicate"):
        _journal_lane_count(
            {"qemu_args": ("-enable-kvm "
                           "-device virtserialport,name=nfsp-journal-0 "
                           "-device virtserialport,name=nfsp-journal-0")}, 1)
    with pytest.raises(Stage2StepError, match="enable KVM"):
        _journal_lane_count(
            {"qemu_args": "-device virtserialport,name=nfsp-journal-0"}, 1)


def test_manager_cmdline_is_bound_to_harness_selection():
    descriptor = SimpleNamespace(
        guest_kernel_command_line="root=/dev/sda console=ttyS0 nokaslr")
    harness = SimpleNamespace(runtime_selection=SimpleNamespace(
        fixture_mode="single", nfs_version="4.1", trace_mode="off"))
    lane = "a" * 64
    value = ("root=/dev/sda console=ttyS0 nokaslr koov.nfs_version=4.1 "
             f"koov.nfs_target=1 koov.lane_sha256={lane}")
    assert _manager_cmdline(
        {"cmdline": value}, descriptor, harness, lane) == value
    with pytest.raises(Stage2StepError, match="base command line"):
        _manager_cmdline(
            {"cmdline": value.replace("console=ttyS0 ", "")},
            descriptor, harness, lane)
    with pytest.raises(Stage2StepError, match="unapproved koov.nfs_version"):
        _manager_cmdline(
            {"cmdline": value.replace("koov.nfs_version=4.1",
                                      "koov.nfs_version=3")},
            descriptor, harness, lane)


def test_manager_runtime_assets_are_bound_to_harness_pins(tmp_path):
    syzkaller = tmp_path / "syzkaller"
    target_bin = syzkaller / "bin/linux_amd64"
    target_bin.mkdir(parents=True)
    kernel_obj = tmp_path / "kernel"
    kernel_obj.mkdir()
    template = tmp_path / "template"
    template.mkdir()
    assets = {
        "bzimage": tmp_path / "bzImage",
        "kernel": kernel_obj / "vmlinux",
        "lane-script": template / "lane.sh",
        "vm-image": tmp_path / "image.qcow2",
        "syz-execprog": target_bin / "syz-execprog",
        "syz-executor": target_bin / "syz-executor",
        "syz-manager": syzkaller / "bin/syz-manager",
    }
    for name, path in assets.items():
        path.write_bytes((name + "\n").encode())
    assets["syz-manager"].chmod(0o755)
    key = tmp_path / "id"
    key.write_text("key\n")
    store = ArtifactStore(tmp_path / "cas")
    builds = {
        name: put_record(store, pin_file(name, path))
        for name, path in assets.items()
    }
    collector = CollectorConfig(
        artifact_root=store.root, files=assets, ssh_key=key,
        qemu="/bin/true", pin_cache=tmp_path / "pins.json")
    descriptor = SimpleNamespace(syzkaller_identity=SyzkallerTargetIdentity(
        syzkaller_commit="a" * 40,
        patch_series_sha256="b" * 64,
        build_manifest_sha256="c" * 64,
        call_table_sha256="d" * 64,
        target="linux/amd64"))
    manager = {
        "target": "linux/amd64", "syzkaller": str(syzkaller),
        "kernel_obj": str(kernel_obj), "workdir_template": str(template),
        "image": str(assets["vm-image"]), "sshkey": str(key),
    }
    vm = {"kernel": str(assets["bzimage"]), "qemu": "/bin/true"}
    assert _manager_assets(manager, vm, collector, descriptor, builds).name == \
        "lane-script"
    wrong = tmp_path / "wrong-image"
    wrong.write_bytes(b"wrong\n")
    manager["image"] = str(wrong)
    with pytest.raises(PinError, match="does not match its pin"):
        _manager_assets(manager, vm, collector, descriptor, builds)


def test_malformed_barrier_log_keeps_a_safe_capture_generation():
    malformed = ("nfs proxy barrier: generation=1 program_digest=zz "
                 "activation=Acked/0 deactivation=Acked/0 "
                 "executed=true lease_cleared=true\n")
    assert _barrier_generation(malformed, fallback=9) == 9


def test_manager_qemu_args_replace_only_journal_channels(tmp_path):
    socket = tmp_path / "lane0.sock"
    channels = SimpleNamespace(
        sockets=[socket], qemu_args=lambda **_: (
            "-chardev", f"socket,id=nfspj0,path={socket},server=off",
            "-device", "virtserialport,bus=nfspser.0,chardev=nfspj0,"
                       "name=nfsp-journal-0"))
    old = ("-enable-kvm -cpu host -device virtio-serial-pci,id=nfspser "
           "-chardev socket,id=nfspj0,path=/old/lane0.sock "
           "-device virtserialport,bus=nfspser.0,chardev=nfspj0,"
           "name=nfsp-journal-0")
    result = _manager_qemu_args(old, channels)
    assert "-enable-kvm -cpu host" in result
    assert "/old/lane0.sock" not in result
    assert str(socket) in result
    assert result.count("name=nfsp-journal-0") == 1


def test_manager_exit_race_is_a_complete_stop(monkeypatch):
    process = SimpleNamespace(pid=17, poll=lambda: None, waits=[])
    process.wait = lambda timeout: process.waits.append(timeout)

    def gone(_pid, _signal):
        raise ProcessLookupError

    monkeypatch.setattr("agent_pipeline.stage2.kvm.os.killpg", gone)
    assert _stop_manager(process, 4)
    assert process.waits == [10]


def test_segment_is_published_only_at_final_name(tmp_path):
    output = tmp_path / "output"
    (output / "segments").mkdir(parents=True)
    final = _seal_segment(
        output, 0, vm="vm-1", lane=0, generation=3,
        host={"journal_name": "gate"},
        artifacts=[_Artifact("execprog.scenario", "text/plain", b"run\n")])
    assert final == output / "segments/000000"
    assert not (output / "segments/.000000.tmp").exists()
    capture = json.loads((final / "capture.json").read_text())
    assert capture["vm_instance_id"] == "vm-1"
    assert capture["generation_id"] == 3
    assert (final / capture["artifacts"][0]["path"]).read_bytes() == b"run\n"


def test_empty_journal_cannot_be_sealed(tmp_path):
    channels = SimpleNamespace(paths=lambda: [])
    with pytest.raises(Stage2StepError, match="no host journal"):
        _journal_artifacts(channels)


def test_direct_qemu_appends_trusted_journal_arguments(tmp_path):
    config = VmConfig(
        qemu="qemu", bzimage=tmp_path / "bzImage",
        image=tmp_path / "image", lane_dir=tmp_path / "lane",
        ssh_key=tmp_path / "key", cmdline="console=ttyS0",
        console_log=tmp_path / "console", extra_args=("-device", "test-device"))
    guest = QemuGuest.__new__(QemuGuest)
    guest.config = config
    guest.port = 2222
    argv = guest.qemu_argv()
    assert argv[-2:] == ["-device", "test-device"]
