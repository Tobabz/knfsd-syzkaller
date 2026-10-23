#!/usr/bin/env python3
"""Run one non-authoritative Stage 2 NLM gate in an isolated KVM snapshot.

This does not use or modify the Stage 1 controller database, HCAP approval,
production Stage 2 config, or original CAS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import struct
import time
import traceback
from pathlib import Path

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, put_record
from agent_pipeline.materializer import (
    ExecutionHarnessDescriptor, HarnessBuildArtifact, ReachabilityHarness,
    descriptor_id,
)
from agent_pipeline.semantic_delta import SealedJournal
from agent_pipeline.stage1.host.collector import CollectorConfig
from agent_pipeline.stage1.host.pins import pin_file
from agent_pipeline.stage1.host.vm import QemuGuest, VmConfig
from agent_pipeline.stage2 import kvm


_PCAP_STATS = re.compile(r"captured=([0-9]+) packets=([0-9]+) drops=([0-9]+)\n?\Z")


def _capture_stats(path: Path) -> dict:
    if not path.is_file():
        return {"status": "unavailable", "drop_count_known": False}
    match = _PCAP_STATS.fullmatch(path.read_text())
    if match is None:
        return {"status": "invalid", "drop_count_known": False}
    captured, packets, drops = map(int, match.groups())
    return {"status": "diagnostic_only", "drop_count_known": True,
            "captured_tcp_packets": captured, "socket_packets": packets,
            "socket_drops": drops, "socket_drop_free": drops == 0,
            "capture_complete": False}


def _rules() -> bytes:
    schema = "nlm4/sha256:9986d9f2be8bc5e36de582c10f89f1124448718cdd89ea266f3e61cb7b5442d4"

    def string(value: str) -> bytes:
        data = value.encode("ascii")
        return struct.pack(">I", len(data)) + data + b"\0" * (-len(data) % 4)

    return (b"NFSPRUL1" + struct.pack(">I", 1) + string(schema)
            + string("nlm-gate-diagnostic") + struct.pack(">I", 0))


def _lock_rules(*, client: int = 1, offset: int = 1) -> bytes:
    from importlib.util import module_from_spec, spec_from_file_location

    path = Path(__file__).with_name("test-nlm-relay-kvm.py")
    spec = spec_from_file_location("nlm_relay_diagnostic", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("NLM diagnostic rule builder is unavailable")
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    mode = "offset_identity_break" if offset else "offset_noop_control"
    return module.diagnostic_rules(mode, client=client)


def _focused_seed_syscalls() -> list[str]:
    # Resource producers keep the seed's fcntl$lock and nanosleep enabled.
    return [
        "syz_open_nfs_lane_profile$client1_knfsd_v3",
        "syz_open_nlm_lane_file", "fcntl$lock", "syz_nlm_lane_fh",
        "syz_socket_connect_nlm$client0", "syz_send_nlm_rpc",
        "recvfrom$inet_nlm_tcp", "nanosleep", "getpid", "clock_gettime",
    ]


def _campaign_image(args: argparse.Namespace, root: Path,
                    descriptor: ExecutionHarnessDescriptor,
                    collector: CollectorConfig) -> Path:
    image = root / "prepared.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(args.image.resolve()), str(image)], check=True,
                   capture_output=True)

    class PersistentGuest(QemuGuest):
        def qemu_argv(self):
            argv = super().qemu_argv()
            argv.remove("-snapshot")
            return argv

    guest = PersistentGuest(VmConfig(
        qemu=collector.qemu, bzimage=collector.files["bzimage"], image=image,
        lane_dir=args.lane.resolve(), ssh_key=collector.ssh_key,
        cmdline=descriptor.guest_kernel_command_line
                + " systemd.mask=frozen-phase9-fixture.service",
        console_log=root / "image-prepare-console.log",
        memory_mb=collector.memory_mb, cpus=collector.cpus,
        boot_timeout_s=collector.boot_timeout_s))
    try:
        guest.start()
        guest.put(args.proxy, "/tmp/nfs-proxy-replacement")
        rc, log = guest.run(
            "install -m 0755 /tmp/nfs-proxy-replacement "
            "/opt/kcov-nfs/deps/usr/sbin/nfs-proxy && sync", timeout=30)
        if rc:
            raise RuntimeError(f"preparing diagnostic image failed: {log[-1000:]}")
    finally:
        guest.stop()
    return image


def _prepare(args: argparse.Namespace) -> tuple[kvm.StepOptions, Path, Path]:
    root = args.output
    root.mkdir(parents=True, exist_ok=False)
    inp = root / "input"
    out = root / "output"
    inp.mkdir()
    (out / "segments").mkdir(parents=True)
    original = args.state / "runs" / f"{args.job}.t3.g1" / "input"
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        (original / "descriptor.json").read_bytes())
    harness = ReachabilityHarness.model_validate_json(
        (original / "harness.json").read_bytes())
    source_config = CollectorConfig.load(args.state / "collector.json")
    files = dict(source_config.files)
    files["vm-image"] = (_campaign_image(args, root, descriptor, source_config)
                         if args.step == "campaign" else args.image)
    files["lane-script"] = args.lane / "lane.sh"
    cas = ArtifactStore(root / "diagnostic-cas")
    original_cas = ArtifactStore(source_config.artifact_root)
    builds = []
    for artifact in descriptor.build_artifacts:
        if artifact.name in files:
            ref = put_record(cas, pin_file(artifact.name, files[artifact.name]))
        else:
            ref = cas.put(original_cas.get(artifact.artifact_ref))
        builds.append(HarnessBuildArtifact(name=artifact.name, artifact_ref=ref))
    descriptor = descriptor.model_copy(update={"build_artifacts": tuple(builds)})
    identity = descriptor_id(descriptor)
    harness = harness.model_copy(update={"execution_harness_id": identity})
    collector = source_config.model_copy(update={
        "artifact_root": cas.root,
        "files": files,
        "pin_cache": root / "pin-cache.json",
        "fixture_timeout_s": source_config.fixture_timeout_s,
        "exec_timeout_s": source_config.exec_timeout_s,
        "grace_s": source_config.grace_s,
        "drain_s": source_config.drain_s,
    })
    collector_path = root / "collector.json"
    collector_path.write_bytes(canonical_json(collector))
    (inp / "descriptor.json").write_bytes(canonical_json(descriptor))
    (inp / "harness.json").write_bytes(canonical_json(harness))
    for name in ("program.syz", "neutral.syz"):
        (inp / name).write_bytes((original / name).read_bytes())
    rules = (_lock_rules(client=0 if args.seed_client0 else 1,
                         offset=args.mutation_offset)
             if args.nlm_lock_rule else _rules())
    (inp / "rules.nfsprul1").write_bytes(rules)
    execution = {
        "job_id": args.job,
        "task_id": f"{args.job}.nlm-diagnostic-gate",
        "step": args.step, "harness_ref": hashlib.sha256(canonical_json(harness)).hexdigest(),
        "execution_harness_id": identity, "lease_generation": 1,
        "compiled_ref": "0" * 64, "rule_set_id": hashlib.sha256(rules).hexdigest(),
        "gate_repetitions": 1 if args.step == "gate" else None,
        "campaign_id": "nlm-diagnostic" if args.step == "campaign" else None,
        "crash_bundle_ref": None,
    }
    (inp / "execution.json").write_bytes(canonical_json(execution))
    lane_sha = pin_file("lane-script", files["lane-script"]).sha256
    base = descriptor.guest_kernel_command_line
    cmdline = (f"{base} koov.nfs_fixture=nlm-knfsd koov.nfs_trace=0 "
               f"koov.nfs_target=1 koov.nlm_relay_experiment=1 "
               f"koov.lane_sha256={lane_sha}"
               + (" systemd.mask=frozen-phase9-fixture.service"
                  if args.step == "gate" else ""))
    syzkaller = files["syz-manager"].parent.parent
    manager = {
        "type": "qemu", "target": "linux/amd64", "procs": 1,
        "syzkaller": str(syzkaller), "kernel_obj": str(files["kernel"].parent),
        "workdir_template": str(args.lane), "image": str(files["vm-image"]),
        "sshkey": str(collector.ssh_key),
        "experimental": {"remote_cover": True}, "snapshot": False,
        "vm": {
            "kernel": str(files["bzimage"]), "count": 1, "cmdline": cmdline,
            "qemu_args": ("-enable-kvm "
                          "-fsdev local,id=koov_lane,path={{TEMPLATE}},"
                          "security_model=none,readonly=on "
                          "-device virtio-9p-pci,fsdev=koov_lane,"
                          "mount_tag=koov-lane "
                          + " ".join(
                              f"-device virtserialport,name=nfsp-journal-{lane}"
                              for lane in range(4))),
        },
    }
    if args.step == "campaign" and args.focused_seed:
        manager["enable_syscalls"] = _focused_seed_syscalls()
    manager_path = root / "manager.json"
    manager_path.write_bytes(canonical_json(manager))
    (root / "identity.json").write_bytes(canonical_json({
        "evidence_class": "unapproved_diagnostic_only", "source_job_id": args.job,
        "diagnostic_execution_harness_id": identity,
        "original_execution_harness_id": descriptor_id(
            ExecutionHarnessDescriptor.model_validate_json(
                (original / "descriptor.json").read_bytes())),
    }))
    return kvm.StepOptions(manager=manager_path, collector=collector_path), inp, out


def _diagnostic_cmdline(vm, descriptor, harness, lane_sha):
    expected = descriptor.guest_kernel_command_line.split() + [
        "koov.nfs_fixture=nlm-knfsd", "koov.nfs_trace=0",
        "koov.nfs_target=1", "koov.nlm_relay_experiment=1",
        f"koov.lane_sha256={lane_sha}",
    ]
    if "systemd.mask=frozen-phase9-fixture.service" in vm.get("cmdline", "").split():
        expected.append("systemd.mask=frozen-phase9-fixture.service")
    if (vm.get("cmdline", "").split() != expected
            or harness.runtime_selection.fixture_mode != "nlm-knfsd"):
        raise kvm.Stage2StepError("diagnostic NLM command line differs from isolated fixture")
    return vm["cmdline"]


def _campaign_summary(output: Path, capture: dict) -> dict:
    journal = SealedJournal(output / "work" / "journal", "campaign")
    records = kvm._spool(output / "work" / "executions")
    campaign, correlated = kvm._campaign_records(records)
    generations = [generation for session in journal.sessions.values()
                   for generation in session.generations.values()]
    exposures = [exposure for generation in generations
                 for exposure in generation.exposures]
    matched_exposures = 0
    matched_forward_complete = 0
    vm_ids = {session.binding.vm_instance_id for session in journal.sessions.values()}
    if len(vm_ids) != 1:
        raise ValueError("diagnostic campaign journal has ambiguous VM identity")
    vm_id = next(iter(vm_ids))
    for record in correlated:
        match = journal.find(
            vm_instance_id=vm_id,
            lane_id=record.lane, kcov_generation=record.generation,
            program_digest=record.program_digest)
        if match is None:
            continue
        relevant = match[1].exposures
        matched_exposures += bool(relevant)
        matched_forward_complete += bool(relevant) and all(
            exposure.terminal == "complete" for exposure in relevant)
    return {
        "executions": capture["host"]["executions"],
        "vm_termination": capture["host"]["vm_termination"],
        "console_log_completeness": capture["host"]["console_log_completeness"],
        "generation_coverage_count": sum(
            item["identity"].startswith("generation-coverage/")
            for item in capture["artifacts"]),
        "crash_log_present": any(item["identity"] == "crash-log"
                                 for item in capture["artifacts"]),
        "campaign_records": len(campaign),
        "correlated_records": len(correlated),
        "journal_clean": not journal.torn_tail and not journal.rejections,
        "mutation_exposures": len(exposures),
        "matched_mutation_executions": matched_exposures,
        "matched_forward_complete_executions": matched_forward_complete,
        "forward_complete": sum(exposure.terminal == "complete"
                                for exposure in exposures),
        "forward_failed": sum(exposure.terminal == "failed"
                              for exposure in exposures),
        "apply_refusals": sum(len(generation.refusals)
                              for generation in generations),
    }


def _campaign_status(summary: dict) -> str:
    if (summary["executions"] > 0
            and summary["matched_forward_complete_executions"] ==
            summary["executions"]
            and summary["journal_clean"] and not summary["apply_refusals"]
            and not summary["forward_failed"]):
        return "host_campaign_mutation_forwarded_diagnostic_only"
    if summary["mutation_exposures"]:
        return "host_campaign_exposure_unconfirmed_diagnostic_only"
    if summary["executions"]:
        return "host_campaign_executed_no_exposure_diagnostic_only"
    return "host_campaign_inconclusive_diagnostic_only"


def _campaign_failure_phase(output: Path, error: Exception) -> str:
    log = output / "work" / "manager-debug.log"
    if log.is_file():
        console = log.read_bytes()
        if (b"no channels available for device koov-lane" in console
                or b"Failed to start Frozen NFS KCOV" in console):
            return "fixture_preparation"
        if (b"NFS fuzz lane bound" not in console
                and b"NFS proxy target mode" not in console):
            return "fixture_or_executor_preparation"
    if "no generation-attributed campaign execution" in str(error):
        return "campaign_attribution"
    return "campaign_execution"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--job", required=True)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--lane", required=True, type=Path)
    parser.add_argument("--proxy", required=True, type=Path)
    parser.add_argument("--packet-capture", type=Path)
    parser.add_argument("--nlm-lock-rule", action="store_true",
                        help="Use the diagnostic NLM LOCK offset mutation rule")
    parser.add_argument("--mutation-offset", type=int, choices=(0, 1), default=1,
                        help="Diagnostic LOCK offset replacement (0 preserves contention)")
    parser.add_argument("--step", choices=("gate", "campaign"), default="gate")
    parser.add_argument("--campaign-executions", type=int, default=4)
    parser.add_argument("--campaign-timeout", type=float, default=480)
    parser.add_argument("--focused-seed", action="store_true",
                        help="Limit diagnostic campaign syscalls to the NLM seed")
    parser.add_argument("--seed-client0", action="store_true",
                        help="Match the seed's direct client0 NLM LOCK")
    parser.add_argument("--corpus-run", action="store_true",
                        help="Replay the diagnostic seed without fuzzer mutation")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--exec-slowdown", type=int, default=1)
    args = parser.parse_args()
    if args.step == "campaign" and not args.nlm_lock_rule:
        parser.error("diagnostic campaign requires --nlm-lock-rule")
    if args.corpus_run and args.step != "campaign":
        parser.error("--corpus-run requires --step campaign")
    options, inp, out = _prepare(args)
    options = kvm.StepOptions(manager=options.manager, collector=options.collector,
                              exec_slowdown=args.exec_slowdown,
                              campaign_executions=args.campaign_executions,
                              campaign_timeout_s=args.campaign_timeout)
    result = {"evidence_class": "unapproved_diagnostic_only"}
    try:
        kvm._load_inputs(options, inp)
    except Exception as exc:
        result["production_guard"] = f"{type(exc).__name__}: {exc}"
    else:
        raise RuntimeError("NLM production guard unexpectedly accepted diagnostic input")

    original_cmdline = kvm._manager_cmdline
    original_guest = kvm._direct_guest

    def diagnostic_guest(inputs, lane_dir, console, extra_args):
        guest = original_guest(inputs, lane_dir, console, extra_args)
        start = guest.start
        run = guest.run
        stop = guest.stop
        fixture_started = False
        capture_started = False
        gate_opened = False
        live_snapshot_done = False

        def prepared_start():
            nonlocal fixture_started, capture_started
            start()
            guest.put(args.proxy, "/tmp/nfs-proxy-replacement")
            rc, log = run(
                "install -m 0755 /tmp/nfs-proxy-replacement "
                "/opt/kcov-nfs/deps/usr/sbin/nfs-proxy && "
                "sh -x /opt/frozen-phase9/boot-fixture.sh",
                timeout=240)
            (out / "fixture-start.log").write_text(log)
            if rc:
                checks = {
                    "fixture-processes": "ps -eo pid,ppid,stat,wchan:24,comm",
                    "fixture-daemon-logs": "for f in /tmp/frozen-phase9.manager/lane*/client*.nlm.log /tmp/frozen-phase9.manager/lane*/server.log; do echo ==== $f; tail -n 40 $f; done",
                    "fixture-rpcbind": "for ns in /run/netns/f9l*c* /run/netns/f9l*s*; do echo ==== $ns; ip netns exec $(basename $ns) rpcinfo -p 127.0.0.1; done",
                }
                for name, check in checks.items():
                    try:
                        probe_rc, probe_log = run(check, timeout=20)
                        (out / f"{name}.log").write_text(
                            f"rc={probe_rc}\n{probe_log}")
                    except Exception as exc:
                        (out / f"{name}.log").write_text(
                            f"diagnostic command failed: {type(exc).__name__}: {exc}\n")
                raise RuntimeError(f"diagnostic fixture start failed: rc={rc}")
            rc, digest = run("sha256sum /opt/kcov-nfs/deps/usr/sbin/nfs-proxy")
            if rc or digest.split()[0] != hashlib.sha256(args.proxy.read_bytes()).hexdigest():
                raise RuntimeError("diagnostic guest proxy differs from requested build")
            fixture_started = True
            if args.packet_capture is not None:
                guest.put(args.packet_capture, "/tmp/nlm-stage2-pcap")
                rc, log = run(
                    "chmod 0700 /tmp/nlm-stage2-pcap; "
                    "nsenter -t $(cat /tmp/frozen-phase9.manager/lane0/server.pid) "
                    "-n -- /tmp/nlm-stage2-pcap /tmp/nlm-stage2-gate.pcap "
                    "/tmp/nlm-stage2-gate.stats "
                    ">/tmp/nlm-stage2-pcap.log 2>&1 < /dev/null & "
                    "sleep 1; pgrep -f '^/tmp/nlm-stage2-pcap '", timeout=15)
                if rc:
                    raise RuntimeError(f"diagnostic packet capture failed: {log}")
                capture_started = True

        def prepared_run(command, *, timeout=60):
            nonlocal gate_opened, live_snapshot_done
            if command == "systemctl is-active frozen-phase9-fixture.service":
                rc, _ = run("test -x /run/frozen-phase9/lane.sh", timeout=timeout)
                return (0, "active\n") if fixture_started and rc == 0 else (3, "inactive\n")
            if command == "touch /tmp/stage1/gate.go":
                gate_opened = True
            elif (gate_opened and not live_snapshot_done
                  and command.startswith("if [ -e /tmp/stage1/exec.rc ]")):
                live_snapshot_done = True
                time.sleep(1)
                probes = {
                    "processes": "ps -eo pid,ppid,stat,wchan:28,comm | grep -E 'syz-executor|nfs|rpc|proxy'",
                    "stacks": "for p in $(ps -eo pid,comm | awk '$2 ~ /^syz-executor$|^syz[.]0[.]/ {print $1}'); do echo PID=$p; cat /proc/$p/wchan /proc/$p/stack 2>&1; done",
                    "proxy-snapshot": "kill -USR1 $(cat /tmp/frozen-phase9.manager/lane0/server/proxy.pid); sleep 1; tail -n 75 /tmp/frozen-phase9.manager/lane0/server/proxy.log",
                    "client1-tcp": "ip netns exec f9l0c1 ss -tnpi",
                    "server-tcp": "ip netns exec f9l0s ss -tnpi",
                    "client1-nfs": "cat /proc/net/rpc/nfs; cat /proc/net/rpc/nfsd",
                }
                for name, probe in probes.items():
                    try:
                        rc, log = run(probe, timeout=10)
                        (out / f"live-{name}.log").write_text(f"rc={rc}\n{log}")
                    except Exception as exc:
                        (out / f"live-{name}.log").write_text(
                            f"diagnostic command failed: {type(exc).__name__}: {exc}\n")
            return run(command, timeout=timeout)

        def prepared_stop():
            if capture_started:
                try:
                    run("pkill -TERM -x nlm-stage2-pcap; sleep 1", timeout=10)
                    guest.get("/tmp/nlm-stage2-gate.pcap", out / "server.pcap")
                    guest.get("/tmp/nlm-stage2-gate.stats", out / "server-pcap.stats")
                except Exception as exc:
                    (out / "packet-capture-error.log").write_text(
                        f"{type(exc).__name__}: {exc}\n")
            if fixture_started:
                commands = {
                    "proxy": "tail -n 120 /tmp/frozen-phase9.manager/lane0/server/proxy.log",
                    "server": "tail -n 80 /tmp/frozen-phase9.manager/lane0/server.log",
                    "sockets": "ip netns exec f9l0s ss -tnp",
                    "mounts": "timeout 4 stat /syz-nfs-lanes/proc-0/client1-knfsd-v3",
                }
                for name, command in commands.items():
                    try:
                        rc, log = run(command, timeout=10)
                        (out / f"guest-{name}.log").write_text(f"rc={rc}\n{log}")
                    except Exception as exc:
                        (out / f"guest-{name}.log").write_text(
                            f"diagnostic command failed: {type(exc).__name__}: {exc}\n")
            stop()

        guest.start = prepared_start
        guest.run = prepared_run
        guest.stop = prepared_stop
        return guest

    kvm._manager_cmdline = _diagnostic_cmdline
    if args.step == "gate":
        kvm._direct_guest = diagnostic_guest
    try:
        if args.corpus_run:
            from unittest.mock import patch
            original_popen = kvm.subprocess.Popen

            def corpus_popen(argv, *popen_args, **popen_kwargs):
                if (len(argv) == 4 and argv[1] == "-config"
                        and argv[3] == "-debug"):
                    argv = [*argv, "-mode", "corpus-run"]
                return original_popen(argv, *popen_args, **popen_kwargs)

            with patch.object(kvm.subprocess, "Popen", side_effect=corpus_popen):
                kvm.run_step(options, inp, out)
        else:
            kvm.run_step(options, inp, out)
        segment = out / "segments" / "000000"
        capture = json.loads((segment / "capture.json").read_bytes())
        if args.step == "gate":
            reachability = next(item for item in capture["artifacts"]
                                if item["identity"] == "reachability")
            observation = json.loads((segment / reachability["path"]).read_bytes())
            result["gate"] = {
                "boot_ok": observation["boot_ok"],
                "fixture_ok": observation["fixture_ok"],
                "lane_ok": observation["lane_ok"],
                "runner_completed": observation["runner_completed"],
                "generation_attributed": observation["generation_attributed"],
                "generation_aborted": observation["generation"]["generation_aborted"],
                "published_pc_count": len(observation["published_pcs"]),
                "runtime_errors": observation["runtime_errors"],
            }
            result["status"] = ("host_gate_attributed_diagnostic_only"
                                if result["gate"]["generation_attributed"]
                                else "host_gate_inconclusive_diagnostic_only")
        else:
            result["campaign"] = _campaign_summary(out, capture)
            result["status"] = _campaign_status(result["campaign"])
    except Exception as exc:
        result["status"] = ("host_gate_failed" if args.step == "gate"
                            else "host_campaign_failed")
        if args.step == "campaign":
            result["failure_phase"] = _campaign_failure_phase(out, exc)
        result["error"] = f"{type(exc).__name__}: {exc}"
        (args.output / "traceback.log").write_text(traceback.format_exc())
    finally:
        kvm._manager_cmdline = original_cmdline
        kvm._direct_guest = original_guest
    if args.packet_capture is not None:
        result["packet_capture"] = _capture_stats(out / "server-pcap.stats")
    (args.output / "result.json").write_bytes(canonical_json(result))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in (
        "host_gate_attributed_diagnostic_only",
        "host_campaign_mutation_forwarded_diagnostic_only",
        "host_campaign_executed_no_exposure_diagnostic_only") else 2


if __name__ == "__main__":
    raise SystemExit(main())
