"""Host-only tests for the real Stage 2 KVM step command."""

from __future__ import annotations

import json
import sqlite3
import signal
import struct
import time
import zlib
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent_pipeline.admission import SyzkallerTargetIdentity
from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import Sanitizer
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.journal_sink import CHANNEL_CLOSE_TIMEOUT_S
from agent_pipeline.stage1.host.collector import (EVIDENCE_COMMAND_TIMEOUT_S,
                                                  EXECPROG_EXIT_GRACE_S, POLL_S,
                                                  CollectorConfig, execprog_argv,
                                                  execprog_timeout, pinned_path,
                                                  staged_path)
from agent_pipeline.stage1.host.pins import PinError, pin_file
from agent_pipeline.stage1.host.vm import (GUEST_COMMAND_TIMEOUT_S,
                                           GUEST_TRANSFER_TIMEOUT_S,
                                           VM_STOP_TIMEOUT_S, QemuGuest,
                                           VmConfig)
from agent_pipeline.stage2.kvm import (
    ARTIFACT_SEAL_RESERVE_S, EVIDENCE_SEAL_RESERVE_S,
    MANAGER_SIGNAL_TIMEOUT_S, MAX_JOURNAL_CHANNELS, NfsProxyExecution,
    Stage2StepError, _Artifact, _check_program_calls,
    _barrier_generation, _campaign_records, _corpus, _correlated,
    _crash_attribution,
    _closed_evidence_channels, _JournalChannels, _journal_artifacts,
    _journal_lane_count, _lane_template,
    _campaign_manager, _campaign_report_state, _CRASH, _KCSAN_REPORT,
    _foreign_campaign_execution, _manager_command,
    _manager_assets, _manager_cmdline, _manager_path, _manager_qemu_args,
    _seedless_syzkaller,
    _staged_manager, _evidence_seal_window, _seal_segment, _spool,
    _stop_manager, _validate_runtime_authority, StepOptions,
    stage2_timeout_budget,
)
from agent_pipeline.materializer import ReachabilityHarness
from .stage2_host import rules_bytes
from .fakes import COMMIT, World


@pytest.mark.parametrize("sanitizer", [Sanitizer.KASAN, Sanitizer.KCSAN])
def test_campaign_selects_policy_from_job_candidate(tmp_path, sanitizer, monkeypatch):
    state = tmp_path / "state"
    state.mkdir()
    world = World(state, bound=False, sanitizer=sanitizer)
    job_id = world.submit()
    candidate_id = world.job(job_id).candidate.candidate_id
    payload = state / "kcsan-policies" / f"{candidate_id}_policy.payload"
    assert not payload.exists()
    with sqlite3.connect(state / "controller.sqlite") as database:
        world.store.db.backup(database)
    inputs = SimpleNamespace(
        manager={"name": "campaign"},
        execution=SimpleNamespace(job_id=job_id, state_dir=str(state)),
        harness=SimpleNamespace(candidate_id=candidate_id),
        descriptor=SimpleNamespace(sanitizer=sanitizer, kernel_commit=COMMIT))

    if sanitizer is Sanitizer.KASAN:
        def unexpected_kcsan_pipeline(*args, **kwargs):
            pytest.fail("KASAN campaign invoked the KCSAN pipeline")

        monkeypatch.setattr("agent_pipeline.stage2.kvm.ProgramPolicyPipeline",
                            unexpected_kcsan_pipeline)
        inputs.execution.state_dir = str(state / "missing")
    selected = _campaign_manager(inputs)
    if sanitizer is Sanitizer.KASAN:
        assert selected == {"name": "campaign"}
        assert not (state / "kcsan-policies").exists()
        for key in ("kcsan_policy_file", "kcsan_policy"):
            inputs.manager = {key: ""}
            with pytest.raises(Stage2StepError, match="non-KCSAN campaign"):
                _campaign_manager(inputs)
    else:
        assert selected == {"name": "campaign", "kcsan_policy_file": str(payload)}
        contents = payload.read_bytes()
        assert contents.startswith(f"policy {candidate_id} 5 ".encode())
        assert _campaign_manager(inputs) == selected
        assert payload.read_bytes() == contents
        payload.unlink()
        assert _campaign_manager(inputs) == selected
        assert payload.read_bytes() == contents
        inputs.harness.candidate_id = "different-candidate"
        with pytest.raises(Stage2StepError, match="different candidates"):
            _campaign_manager(inputs)


def test_kcsan_campaign_requires_controller_state():
    inputs = SimpleNamespace(
        manager={}, execution=SimpleNamespace(job_id="job", state_dir=None),
        descriptor=SimpleNamespace(sanitizer=Sanitizer.KCSAN))
    with pytest.raises(Stage2StepError, match="lacks Controller state"):
        _campaign_manager(inputs)


def test_kcsan_report_is_not_misclassified_as_guest_termination():
    console = b"[  5.0] BUG: KCSAN: data-race in nfsd_svc / nfsd_svc\n"
    assert _KCSAN_REPORT.search(console)
    assert not _CRASH.search(console)
    assert _campaign_report_state([], None, console) == (True, False)


def test_fatal_console_is_distinct_from_nonfatal_manager_report(tmp_path):
    report = tmp_path / "report0"
    report.write_text("WARNING: recoverable warning\n")
    log = tmp_path / "log0"
    log.write_text("last executing program\n")
    assert _campaign_report_state([report], log, b"") == (True, False)
    assert _campaign_report_state([], None, b"BUG: KASAN: slab-use-after-free\n") \
        == (True, True)


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


def runtime_authority(tmp_path):
    from tests.agent_pipeline.test_materializer import materializer_world

    world = materializer_world(tmp_path)
    result = world.materializer.materialize(world.plan_ref, world.binding)
    harness = load_record(world.store, result.harness_ref, ReachabilityHarness)
    root = tmp_path / "input"
    root.mkdir()
    (root / "hcap.json").write_bytes(canonical_json(world.hcap))
    (root / "admission.json").write_bytes(canonical_json(world.profile))
    manager = {
        "procs": 1,
        "enable_syscalls": ["close", "openat$lane"],
        "experimental": {"remote_cover": True},
    }
    return world, harness, root, manager


def test_runtime_rejects_manager_outside_harness_validated_layout(tmp_path):
    world, harness, root, manager = runtime_authority(tmp_path)
    _validate_runtime_authority(root, harness, world.descriptor, manager)
    manager["procs"] = 2
    with pytest.raises(Stage2StepError, match="validated layout"):
        _validate_runtime_authority(root, harness, world.descriptor, manager)


def test_every_candidate_program_call_is_enabled():
    """syz-manager drops a disabled call from the seed without a word
    (#99): the step refuses instead."""
    program = (b"r0 = openat$lane(0xffffffffffffff9c, 0x0, 0x0, 0x0)\n"
               b"# a comment\n"
               b"read$extra(r0, 0x0, 0x0)\n"
               b"close(r0)\n")
    _check_program_calls(program, {"enable_syscalls": [
        "close", "openat$lane", "read$extra"]})
    _check_program_calls(program, {})       # every call enabled
    with pytest.raises(Stage2StepError,
                       match="leaves out candidate program calls: read\\$extra$"):
        _check_program_calls(program, {"enable_syscalls": [
            "close", "openat$lane"]})


@pytest.mark.parametrize("name", ["hcap.json", "admission.json"])
def test_runtime_rejects_altered_authority_bytes(tmp_path, name):
    world, harness, root, manager = runtime_authority(tmp_path)
    path = root / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(Stage2StepError, match=f"{name} differs"):
        _validate_runtime_authority(root, harness, world.descriptor, manager)


def test_direct_execprog_slowdown_is_explicit_and_bounded(tmp_path):
    assert "-slowdown=1" in execprog_argv(60)
    assert "-slowdown=10" in execprog_argv(60, 10)
    assert "timeout --kill-after=60 600 " in execprog_argv(60, 10)
    assert execprog_timeout(60, 10) == 600
    assert "timeout --kill-after=60 1 " in execprog_argv(0.25, 3)
    assert execprog_timeout(0.25, 3) == 1
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
    assert StepOptions(
        manager=tmp_path / "manager.json",
        collector=tmp_path / "collector.json",
    ).campaign_executions == 96
    with pytest.raises(ValueError, match="campaign_executions"):
        StepOptions(
            manager=tmp_path / "manager.json",
            collector=tmp_path / "collector.json",
            campaign_executions=97,
        )


def test_campaign_mode_defaults_to_fuzz_and_runs_the_manager_to_match(tmp_path):
    from agent_pipeline.stage2.kvm import _manager_command
    options = StepOptions(
        manager=tmp_path / "manager.json",
        collector=tmp_path / "collector.json")
    assert options.campaign_mode == "fuzz"
    binary, config = Path("/bin/syz-manager"), Path("/m.json")
    assert _manager_command(binary, config) == [
        str(binary), "-config", str(config), "-debug"]
    assert _manager_command(binary, config, "proxy_only") == [
        str(binary), "-config", str(config), "-mode", "corpus-run",
        "-debug"]
    with pytest.raises(ValueError, match="campaign_mode"):
        StepOptions(
            manager=tmp_path / "manager.json",
            collector=tmp_path / "collector.json",
            campaign_mode="corpus",
        )


def test_a_lease_runs_the_manager_of_its_variant(tmp_path):
    # #81 D10: a host with several variants names one manager each.
    kasan, kcsan = tmp_path / "kasan.json", tmp_path / "kcsan.json"
    options = StepOptions(
        manager=None, collector=tmp_path / "collector.json",
        variant_managers=((Sanitizer.KASAN, kasan),
                          (Sanitizer.KCSAN, kcsan)))
    assert _manager_path(options, SimpleNamespace(
        sanitizer=Sanitizer.KCSAN)) == kcsan
    only = replace(options, variant_managers=((Sanitizer.KASAN, kasan),))
    with pytest.raises(Stage2StepError, match="no variant manager for the "
                                              "kcsan harness"):
        _manager_path(only, SimpleNamespace(sanitizer=Sanitizer.KCSAN))
    with pytest.raises(ValueError, match="one manager or variant"):
        StepOptions(manager=None, collector=tmp_path / "c.json")
    with pytest.raises(ValueError, match="one manager or variant"):
        replace(options, manager=kasan)
    with pytest.raises(ValueError, match="two variant managers"):
        replace(options, variant_managers=((Sanitizer.KASAN, kasan),) * 2)


def test_step_cli_parses_variant_managers(tmp_path, monkeypatch):
    from agent_pipeline.stage2 import host, kvm
    seen = []
    monkeypatch.setattr(kvm, "run_step", lambda *args: seen.append(args))
    assert host.main(["step", "--variant-manager", "kasan=/m/a.json",
                      "--variant-manager", "kcsan=/m/c.json",
                      "--collector", "/c.json", "in", "out"]) == 0
    assert seen[0][0].variant_managers == (
        (Sanitizer.KASAN, Path("/m/a.json")),
        (Sanitizer.KCSAN, Path("/m/c.json")))
    assert seen[0][0].manager is None
    for bad in (["--variant-manager", "kmsan=/m.json"],
                ["--variant-manager", "kasan="],
                ["--manager", "/m.json", "--variant-manager", "kasan=/m"]):
        with pytest.raises(SystemExit):
            host.main(["step", *bad, "--collector", "/c.json", "i", "o"])


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
    assert EVIDENCE_SEAL_RESERVE_S == (
        MAX_JOURNAL_CHANNELS * CHANNEL_CLOSE_TIMEOUT_S
        + ARTIFACT_SEAL_RESERVE_S)
    close = 2 * VM_STOP_TIMEOUT_S + EVIDENCE_SEAL_RESERVE_S
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


def test_crash_attribution_is_campaign_without_a_completion_record():
    quality, warnings = _crash_attribution(
        report_seen=True, crash_log=None, vm="vm", procs=1,
        campaign=[], correlated=[], foreign=None)
    assert quality == "campaign"
    assert warnings == ("exact_generation_unavailable",)


def test_crash_attribution_is_ambiguous_with_competing_lanes():
    quality, warnings = _crash_attribution(
        report_seen=True, crash_log=None, vm="vm", procs=2,
        campaign=[], correlated=[], foreign=None)
    assert quality == "ambiguous"
    assert "multiple_active_lanes:2" in warnings


def test_crash_attribution_is_exact_when_barrier_matches_spool():
    record = NfsProxyExecution.model_validate_json(json.dumps(
        execution_record(execution_id=19, generation=2,
                         program_digest="a" * 64)))
    log = """last executing test programs:

0s ago: executing program 0 (id=19):
nfs-proxy: lane=0 generation=2 program_digest={digest} activation=Acked/0 deactivation=Acked/0 executed=true lease_cleared=true
getpid()

kernel console output (not intermixed with test programs):
""".format(digest="a" * 64)
    quality, warnings = _crash_attribution(
        report_seen=True, crash_log=log, vm="vm", procs=1,
        campaign=[record], correlated=[record], foreign=None)
    assert quality == "exact"
    assert warnings == ()


def test_proxy_only_campaign_manager_runs_only_the_approved_corpus(tmp_path):
    source = tmp_path / "syzkaller"
    (source / "bin").mkdir(parents=True)
    (source / "sys/linux/test").mkdir(parents=True)
    (source / "sys/linux/test/upstream.prog").write_text("getpid()\n")
    view = _seedless_syzkaller(source, tmp_path / "work")
    assert (view / "bin").resolve() == (source / "bin").resolve()
    assert list((view / "sys/linux/test").iterdir()) == []
    assert _manager_command(tmp_path / "syz-manager",
                            tmp_path / "manager.json", "proxy_only") == [
        str(tmp_path / "syz-manager"), "-config",
        str(tmp_path / "manager.json"), "-mode", "corpus-run", "-debug"]


def test_foreign_campaign_program_is_detected_immediately():
    def record(**updates):
        return NfsProxyExecution.model_validate_json(
            json.dumps(execution_record(**updates)))

    approved = record(execution_id=1, program_sha256="a" * 64)
    foreign = record(execution_id=2, program_sha256="d" * 64)
    setup = record(execution_id=3, campaign=False,
                   program_sha256="e" * 64)
    assert _foreign_campaign_execution([setup, approved], "a" * 64) is None
    assert _foreign_campaign_execution(
        [setup, approved, foreign], "a" * 64) is foreign


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
    with pytest.raises(Stage2StepError, match="collector's kvm"):
        _journal_lane_count(
            {"qemu_args": "-device virtserialport,name=nfsp-journal-0"}, 1)
    tcg = {"qemu_args": ("-accel tcg,thread=multi -cpu max "
                         "-device virtserialport,name=nfsp-journal-0")}
    assert _journal_lane_count(tcg, 1, accel="tcg") == 1
    with pytest.raises(Stage2StepError, match="collector's kvm"):
        _journal_lane_count(tcg, 1)


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


def test_a_staged_harness_runs_the_manager_on_its_staged_files(tmp_path):
    # 07 §5.2: the validation staged a new bzImage and syz-executor under
    # the collector's staged_files; the configured files stay the base's.
    syzkaller = tmp_path / "syzkaller"
    target_bin = syzkaller / "bin/linux_amd64"
    target_bin.mkdir(parents=True)
    (tmp_path / "kernel").mkdir()
    (tmp_path / "template").mkdir()
    assets = {
        "bzimage": tmp_path / "bzImage",
        "kernel": tmp_path / "kernel/vmlinux",
        "lane-script": tmp_path / "template/lane.sh",
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
    staged_root = tmp_path / "staged"
    collector = CollectorConfig(
        artifact_root=store.root, files=assets, ssh_key=key,
        qemu="/bin/true", staged_files=staged_root)
    pins = {name: pin_file(name, path) for name, path in assets.items()}
    for name in ("bzimage", "syz-executor"):
        new = tmp_path / f"new-{name}"
        new.write_bytes(f"staged {name}\n".encode())
        pins[name] = pin_file(name, new)
        dest = staged_path(staged_root, pins[name], assets[name])
        dest.parent.mkdir(parents=True)
        dest.write_bytes(new.read_bytes())
    builds = {name: put_record(store, pin) for name, pin in pins.items()}
    files = {name: pinned_path(collector, pins[name], path)
             for name, path in assets.items()}
    assert files["bzimage"].is_relative_to(staged_root)
    manager = {
        "type": "qemu", "target": "linux/amd64", "syzkaller": str(syzkaller),
        "kernel_obj": str(tmp_path / "kernel"),
        "workdir_template": str(tmp_path / "template"),
        "image": str(assets["vm-image"]), "sshkey": str(key),
        "vm": {"kernel": str(assets["bzimage"]), "qemu": "/bin/true"},
    }
    descriptor = SimpleNamespace(syzkaller_identity=SyzkallerTargetIdentity(
        syzkaller_commit="a" * 40, patch_series_sha256="b" * 64,
        build_manifest_sha256="c" * 64, call_table_sha256="d" * 64,
        target="linux/amd64"))
    with pytest.raises(PinError, match="does not match its pin"):
        _manager_assets(manager, manager["vm"], collector, descriptor, builds)

    staged = _staged_manager(manager, collector, files)
    assert staged["vm"]["kernel"] == str(files["bzimage"])
    assert staged["image"] == manager["image"]          # not staged
    links = Path(staged["syzkaller"])
    assert links.parent == staged_root
    assert (links / "bin/linux_amd64/syz-executor").resolve() == \
        files["syz-executor"].resolve()
    assert _manager_assets(staged, staged["vm"], collector, descriptor,
                           builds).name == "lane-script"
    # The same files name the same directory; the base harness is untouched.
    assert _staged_manager(manager, collector, files)["syzkaller"] == \
        staged["syzkaller"]
    assert _staged_manager(manager, collector, assets) == manager


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
        artifacts=[_Artifact("execprog.scenario", "text/plain", b"run\n")],
        deadline=time.monotonic() + 5)
    assert final == output / "segments/000000"
    assert not (output / "segments/.000000.tmp").exists()
    capture = json.loads((final / "capture.json").read_text())
    assert capture["vm_instance_id"] == "vm-1"
    assert capture["generation_id"] == 3
    assert (final / capture["artifacts"][0]["path"]).read_bytes() == b"run\n"


def test_expired_seal_deadline_publishes_no_segment(tmp_path):
    output = tmp_path / "output"
    (output / "segments").mkdir(parents=True)
    with pytest.raises(Stage2StepError, match="sealing deadline expired"):
        _seal_segment(
            output, 0, vm="vm-1", lane=0, generation=3,
            host={"journal_name": "gate"},
            artifacts=[_Artifact("execprog.scenario", "text/plain",
                                 b"run\n")],
            deadline=time.monotonic() - 1)
    assert not any((output / "segments").iterdir())


def test_seal_deadline_after_rename_keeps_segment_and_fails(tmp_path, monkeypatch):
    output = tmp_path / "output"
    segments = output / "segments"
    segments.mkdir(parents=True)
    real_rename = __import__("os").rename

    def rename_then_cross_deadline(source, target):
        real_rename(source, target)
        time.sleep(0.05)

    monkeypatch.setattr(
        "agent_pipeline.stage2.kvm.os.rename", rename_then_cross_deadline)
    monkeypatch.setattr("agent_pipeline.stage2.kvm.os.fsync", lambda fd: None)
    start = time.monotonic()
    with pytest.raises(Stage2StepError, match="sealing deadline expired"):
        with _evidence_seal_window(output, 0, reserve_s=0.02) as deadline:
            _seal_segment(
                output, 0, vm="vm-1", lane=0, generation=3,
                host={"journal_name": "gate"}, artifacts=[_Artifact(
                    "execprog.scenario", "text/plain", b"run\n")],
                deadline=deadline)
    assert time.monotonic() - start < 0.5
    assert [path.name for path in segments.iterdir()] == ["000000"]


def test_seal_window_does_not_hide_errors_after_publication(tmp_path):
    output = tmp_path / "output"
    segments = output / "segments"
    segments.mkdir(parents=True)
    with pytest.raises(RuntimeError, match="after commit"):
        with _evidence_seal_window(output, 0, reserve_s=1) as deadline:
            _seal_segment(
                output, 0, vm="vm-1", lane=0, generation=3,
                host={"journal_name": "gate"},
                artifacts=[_Artifact(
                    "execprog.scenario", "text/plain", b"run\n")],
                deadline=deadline)
            raise RuntimeError("after commit")
    assert (segments / "000000").is_dir()


def test_seal_timeout_leaves_partial_segment_unpublished(tmp_path):
    output = tmp_path / "output"
    segments = output / "segments"
    segments.mkdir(parents=True)
    with pytest.raises(Stage2StepError, match="sealing deadline expired"):
        with _evidence_seal_window(output, 0, reserve_s=0.01):
            (segments / ".000000.tmp").mkdir()
            time.sleep(1)
    assert not (segments / "000000").exists()
    assert (segments / ".000000.tmp").is_dir()


def test_seal_window_rejects_an_inherited_blocked_alarm(tmp_path):
    output = tmp_path / "output"
    (output / "segments").mkdir(parents=True)
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        with pytest.raises(Stage2StepError, match="unblocked host alarm"):
            with _evidence_seal_window(output, 0, reserve_s=1):
                pytest.fail("blocked alarm must prevent sealing")
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)


def test_channel_close_is_inside_seal_deadline(tmp_path):
    output = tmp_path / "output"
    (output / "segments").mkdir(parents=True)
    channels = SimpleNamespace(close=lambda: time.sleep(1))
    with pytest.raises(Stage2StepError, match="sealing deadline expired"):
        with _closed_evidence_channels(
                output, 0, channels, reserve_s=0.01):
            pytest.fail("timed-out close must not enter sealing")


def test_channel_close_refuses_to_seal_with_live_writer(tmp_path):
    channels = object.__new__(_JournalChannels)
    channels.servers = [SimpleNamespace(close=lambda: False)]
    channels.journal = SimpleNamespace(close=lambda: pytest.fail(
        "journal must remain open while its writer thread is alive"))
    channels.socket_dir = tmp_path / "socket"
    channels.socket_dir.mkdir()
    with pytest.raises(Stage2StepError, match="journal channel did not stop"):
        channels.close()
    assert channels.socket_dir.is_dir()


def test_channel_init_failure_removes_socket_directory(tmp_path, monkeypatch):
    socket_dir = tmp_path / "socket"

    def make_socket_dir(*, prefix):
        assert prefix == "knfsd-s2-journal-"
        socket_dir.mkdir()
        return str(socket_dir)

    def fail_journal(*args, **kwargs):
        raise OSError("journal init failed")

    monkeypatch.setattr(
        "agent_pipeline.stage2.kvm.tempfile.mkdtemp", make_socket_dir)
    monkeypatch.setattr("agent_pipeline.stage2.kvm.HostJournal", fail_journal)
    with pytest.raises(OSError, match="journal init failed"):
        _JournalChannels(tmp_path / "journal", "gate", "vm-1", 1,
                         rules_bytes("candidate"), ("prefix",))
    assert not socket_dir.exists()


def test_empty_journal_cannot_be_sealed(tmp_path):
    channels = SimpleNamespace(paths=lambda: [])
    with pytest.raises(Stage2StepError, match="no host journal"):
        _journal_artifacts(channels, deadline=time.monotonic() + 5)


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
    assert argv[1:4] == ["-enable-kvm", "-cpu", "host"]
    smp = argv.index("-smp")
    assert argv[smp:smp + 2] == ["-smp", "2"]
    guest.config = replace(config, accel="tcg")
    assert guest.qemu_argv()[1:5] == [
        "-accel", "tcg,thread=multi", "-cpu", "max"]


def test_collector_selects_cpus_by_sanitizer(tmp_path):
    collector = CollectorConfig(
        artifact_root=tmp_path, files={}, ssh_key=tmp_path / "id",
        cpus=2, variant_cpus={Sanitizer.KASAN: 1, Sanitizer.KCSAN: 2})
    assert collector.cpus_for(Sanitizer.KASAN) == 1
    assert collector.cpus_for(Sanitizer.KCSAN) == 2
