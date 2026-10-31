#!/usr/bin/env python3
"""Run versioned NFS lifecycle scenarios in a disposable fixture VM."""

import argparse
import hashlib
import importlib.util
import json
import re
import shlex
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.data import canonical_json, load_record
from agent_pipeline.hcap import RuntimeSelection
from agent_pipeline.materializer import (ExecutionHarnessDescriptor,
                                         descriptor_id)
from agent_pipeline.qemu_accel import from_env as resolve_accel
from agent_pipeline.q1 import KernelIdentity, TargetPcMapping
from agent_pipeline.stage1.host.generate import HCAP11_RECOVERY_ORDER
from agent_pipeline.stage1.host.collector import (CollectorConfig,
                                                  guest_cmdline,
                                                  program_timeout_s,
                                                  verify_pins)
from agent_pipeline.stage1.host.pins import HostFilePin
from agent_pipeline.stage1.host.target_pcs import (iter_addr2line,
                                                   path_matches,
                                                   vmlinux_callsites)
from agent_pipeline.stage1.host.vm import QemuGuest, VmConfig


CRASH_PATTERNS = (
    "BUG: KASAN:", "Kernel panic", "Oops:",
    "general protection fault", "kernel BUG at",
)
SCENARIOS = {
    "v40-lease-expiry": {"version": "4.0", "kind": "lease"},
    "v41-courtesy-expiry": {"version": "4.1", "kind": "courtesy"},
    "v41-control-restart": {"version": "4.1", "kind": "control"},
    "v42-control-restart": {"version": "4.2", "kind": "control"},
    "v3-nlm-lock": {"version": "3", "kind": "nlm", "fixture": "nlm-knfsd"},
}
LEASE_EVENTS = (
    "nfsd/nfsd_clid_confirmed",
    "nfsd/nfsd_mark_client_expired",
    "nfsd/nfsd_clid_purged",
)
LEASE_ORDER = (
    "nfsd_clid_confirmed",
    "nfsd_mark_client_expired",
    "nfsd_clid_purged",
)
CONTROL_EVENTS = (
    "nfsd/nfsd_ctl_threads",
    "nfsd/nfsd_ctl_ports_addxprt",
    "nfsd/nfsd_grace_start",
    "nfsd/nfsd_grace_complete",
    "nfsd/nfsd_compound",
    "nfsd/nfsd_compound_status",
)
CONTROL_ORDER = (
    "nfsd_ctl_threads: newthreads=0",
    "nfsd_ctl_ports_addxprt: transport=tcp port=20490",
    "nfsd_ctl_threads: newthreads=4",
)
ADMIN_EVENTS = (
    "nfsd/nfsd_cb_recall",
    "nfsd/nfsd_mark_client_expired",
    "nfsd/nfsd_clid_purged",
    "nfsd/nfsd_clid_fresh",
    "nfsd/nfsd_clid_confirmed",
    "nfsd/nfsd_slot_seqid_unconf",
    "nfsd/nfsd_compound_status",
)
# "control" is neutral client0 lane I/O.  "stimulus" creates lock0 read-write
# from client0, which gets it a write delegation, makes client0's link drop
# everything past the lease (syzkaller patch 0032), opens lock0 from client1,
# heals the link and does client0 I/O: the courteous server expires client0
# to grant client1's open, and client0 recovers with a new clientid.  It ends
# by unlinking lock0: knfsd gives no delegation on a file it recalled one
# from in the last 30 to 60 s, so the next run must create a new lock0.
COURTESY_PROGRAMS = {
    "control": ROOT / "tools/nfs-lifecycle/programs/v41-client-io-control.prog",
    "stimulus": ROOT / "tools/nfs-lifecycle/programs/v41-courtesy-expiry.prog",
}
ADMIN_GUEST = "/tmp/nfs-lifecycle-admin"
ADMIN_GATE = ADMIN_GUEST + "/gate"
ADMIN_RC = ADMIN_GUEST + "/exec.rc"
ADMIN_LOG = ADMIN_GUEST + "/exec.log"
STATUS_STDERR = ADMIN_GUEST + "/lane-status.err"
STATS_COMMAND = ("for f in /sys/kernel/debug/sunrpc_fuzz/*_stats; do "
                 "echo \"== $f\"; cat \"$f\"; done")
STATE_COMMAND = "cat /sys/kernel/debug/sunrpc_fuzz/phase4_state"
CLIENT_RE = re.compile(r"\bclient ([0-9a-fA-F]{8}:[0-9a-fA-F]{8})\b")
EVENT_RE = re.compile(r"\s(?P<timestamp>\d+\.\d+): (?P<name>[A-Za-z0-9_]+): ")
SECTION_RE = re.compile(r"^== .*/([A-Za-z0-9_]+)$")
COUNTER_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*) (-?[0-9]+)$")
LIFECYCLE_RE = re.compile(
    r"^lifecycle request lane=0 op=1 client=0 status=0 "
    r"clientid=0x([0-9a-fA-F]{16}) minor=1 sessions=([1-9][0-9]*)$",
    re.MULTILINE)
SHAREABLE_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
#: Every campaign runs syz-execprog -procs=1 (start_admin_exec): one proc,
#: lane 0.  The evidence records it (#99).
EXECPROG_LAYOUT = {"procs": 1, "lanes": [0]}
COURTESY_REQUIRED_INTERFACES = frozenset((
    "remote_cover",
    "syz_nfs_lane_link$heal_client0",
    "syz_nfs_lane_link$partition_client0",
    "syz_open_nfs_lane_profile$client0_knfsd_v41",
    "syz_open_nfs_lane_profile$client1_knfsd_v41",
    "syz_open_nlm_lane_file",
))
NLM_REQUIRED_INTERFACES = frozenset((
    "remote_cover",
    "syz_nlm_lane_fh",
    "syz_open_nfs_lane_profile$client0_knfsd_v3",
    "syz_open_nfs_lane_profile$client1_knfsd_v3",
    "syz_open_nlm_lane_file",
    "syz_send_nlm_rpc",
    "syz_socket_connect_nlm$client0",
))
NLM_FIXTURE = "nlm-knfsd"
# "control" is the neutral lane I/O program, "lock" locks through the kernel
# NFS client, "rpc" sends raw NLM calls and "blocked" queues a raw blocking
# LOCK behind a client1 lock so its release grants it by callback.
NLM_PROGRAMS = {
    phase: ROOT / ("tools/nfs-lifecycle/programs/v3-nlm-%s.prog" % phase)
    for phase in ("control", "lock", "rpc", "blocked")
}
# Public lockd probes: (kernel file, function, part), where "function" is
# the whole function.  Only PCs whose inline frame is that function and
# line are kept.  svc_lock, svc_unlock,
# svc_testlock and svc_share run in the server lane lockd while it serves a
# request; clnt_grant in the client0 lockd while it serves the server's
# GRANTED_MSG callback.  svc_grant_blocked runs in the server lockd thread
# outside any request and svc_grant_callback in rpciod; kernel patch 0006
# attributes both to the program whose LOCK created the block.
NLM_PROBES = {
    "clnt_grant": (("fs/lockd/clntlock.c", "nlmclnt_grant", "function"),),
    "svc_grant_blocked": (
        ("fs/lockd/svclock.c", "nlmsvc_grant_blocked", "function"),),
    "svc_grant_callback": (
        ("fs/lockd/svclock.c", "nlmsvc_grant_callback", "function"),),
    "svc_lock": (("fs/lockd/svclock.c", "nlmsvc_lock", "function"),),
    "svc_share": (("fs/lockd/svcshare.c", "nlmsvc_share_file", "function"),),
    "svc_testlock": (("fs/lockd/svclock.c", "nlmsvc_testlock", "function"),),
    "svc_unlock": (("fs/lockd/svclock.c", "nlmsvc_unlock", "function"),),
}
# Diagnostic only: the GRANTED_RES the server receives back depends on the
# client's rpciod timing.  It never decides reach.
NLM_DIAGNOSTIC_PROBES = {
    "svc_grant_reply": (
        ("fs/lockd/svclock.c", "nlmsvc_grant_reply", "function"),),
}
# Public nfsd probes of the courtesy-expiry campaign, in the NLM_PROBES
# form.  nfsd_break_deleg_cb runs in the nfsd thread serving client1's
# conflicting OPEN; nfsd4_exchange_id and nfsd4_create_session in the
# threads serving client0's recovery.  All three are program requests.
COURTESY_PROBES = {
    "break_deleg": (
        ("fs/nfsd/nfs4state.c", "nfsd_break_deleg_cb", "function"),),
    "create_session": (
        ("fs/nfsd/nfs4state.c", "nfsd4_create_session", "function"),),
    "exchange_id": (
        ("fs/nfsd/nfs4state.c", "nfsd4_exchange_id", "function"),),
}
#: The stimulus trace chain validate_courtesy_trace checks, in order.
COURTESY_ORDER = HCAP11_RECOVERY_ORDER
RECLAIM_COMPLETE_RE = re.compile(
    r"nfsd_compound_status: .* OP_RECLAIM_COMPLETE status=0(?:\s|$)",
    re.MULTILINE)


class CheckedGuest:
    """Compatibility adapter for the lifecycle helpers' checked guest API.

    ``scale`` multiplies every command timeout: the helpers' timeouts are
    KVM-speed budgets, and a TCG guest is ``exec_slowdown`` times slower.
    """

    def __init__(self, guest, scale=1):
        self._guest = guest
        self._scale = scale

    def start(self):
        self._guest.start()

    def guest(self, command, timeout=60):
        rc, output = self._guest.run(command, timeout=timeout * self._scale)
        if rc != 0:
            raise RuntimeError("guest rc=%d: %s: %s" %
                               (rc, command, output[-1500:]))
        return output

    def put(self, source, destination):
        self._guest.put(Path(source), destination)

    def stop(self):
        self._guest.stop()


@dataclass(frozen=True)
class AdminContext:
    config: CollectorConfig
    descriptor: ExecutionHarnessDescriptor
    files: dict[str, Path]
    target_pcs: frozenset[int]
    selection: RuntimeSelection
    lane_sha256: str
    evidence_identity: dict
    identity: KernelIdentity | None = None


def load_admin_context(collector_path, descriptor_path, mapping_path, *,
                       required=COURTESY_REQUIRED_INTERFACES,
                       profile="knfsd-v41", nfs_version="4.1",
                       fixture_mode="single"):
    """Load one exact Stage1 harness and bind the target mapping to it.

    ``required`` picks the runtime selection: the courtesy-expiry campaign
    uses the HCAP-11 selection, the NLM campaign the nlm-knfsd NFSv3
    selection.  Both map public probes themselves and pass no target
    mapping.
    """
    config_bytes = Path(collector_path).read_bytes()
    descriptor_bytes = Path(descriptor_path).read_bytes()
    config = CollectorConfig.model_validate_json(config_bytes)
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        descriptor_bytes)
    mapping = None
    if mapping_path is not None:
        mapping = TargetPcMapping.model_validate_json(
            Path(mapping_path).read_bytes())
        if not mapping.verified or not mapping.target_pcs:
            raise RuntimeError("target PC mapping is empty or unverified")
    files = verify_pins(config, descriptor)
    builds = {item.name: item.artifact_ref
              for item in descriptor.build_artifacts}
    for name in (config.instrumentation_artifact_name,
                 config.vmlinux_artifact_name):
        if name not in builds:
            raise RuntimeError("descriptor lacks mapping artifact %s" % name)
    harness_id = descriptor_id(descriptor)
    expected_identity = KernelIdentity(
        execution_harness_id=harness_id,
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds[
            config.instrumentation_artifact_name],
        vmlinux_sha256=builds[config.vmlinux_artifact_name],
        kaslr_enabled=False, kaslr_offset=0)
    if "nokaslr" not in descriptor.guest_kernel_command_line.split():
        raise RuntimeError("execution descriptor does not disable KASLR")
    if mapping is not None:
        if mapping.target.kernel_commit != descriptor.kernel_commit:
            raise RuntimeError("target mapping names another kernel commit")
        if mapping.identity != expected_identity:
            raise RuntimeError("target mapping identity does not match the "
                               "exact execution harness")

    selections = [
        item for item in descriptor.allowed_runtime_selections
        if (item.profile == profile and item.nfs_version == nfs_version
            and item.fixture_mode == fixture_mode and item.route == "direct"
            and item.topology == "one-lane" and item.trace_mode == "off"
            and required <= set(item.enabled_interfaces))
    ]
    if len(selections) != 1:
        raise RuntimeError("execution descriptor must expose one exact "
                           "%s %s lifecycle runtime selection" %
                           (profile, fixture_mode))

    store = ArtifactStore(config.artifact_root)
    lane_pin = load_record(store, builds["lane-script"], HostFilePin)
    if lane_pin.name != "lane-script":
        raise RuntimeError("lane-script build artifact has the wrong pin")
    evidence = {
        "schema_version": "nfs-lifecycle-evidence-identity.v1",
        "collector_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "execution_harness_id": harness_id,
        "kernel_commit": descriptor.kernel_commit,
        "instrumentation_sha256": expected_identity.instrumentation_sha256,
        "vmlinux_sha256": expected_identity.vmlinux_sha256,
        "build_artifact_refs": dict(sorted(builds.items())),
    }
    if mapping is not None:
        evidence["target_mapping_sha256"] = hashlib.sha256(
            canonical_json(mapping)).hexdigest()
    return AdminContext(
        config=config, descriptor=descriptor, files=files,
        target_pcs=frozenset(mapping.target_pcs if mapping else ()),
        selection=selections[0], lane_sha256=lane_pin.sha256,
        evidence_identity=evidence, identity=expected_identity)


def make_admin_vm(context, output):
    config = context.config
    command_line = guest_cmdline(
        context.descriptor, context.selection, context.lane_sha256)
    guest = QemuGuest(VmConfig(
        qemu=config.qemu, bzimage=context.files["bzimage"],
        image=context.files["vm-image"],
        lane_dir=context.files["lane-script"].parent,
        ssh_key=config.ssh_key, cmdline=command_line,
        console_log=output / "console.log", memory_mb=config.memory_mb,
        cpus=config.cpus_for(context.descriptor.sanitizer),
        boot_timeout_s=config.boot_timeout_s,
        accel=config.accel))
    return CheckedGuest(guest, scale=config.exec_slowdown)


def verify_admin_guest(vm, context):
    lane = vm.guest("sha256sum /run/frozen-phase9/lane.sh").split()[0]
    if lane != context.lane_sha256:
        raise RuntimeError("guest lane script differs from the pinned file")
    proxy_line = vm.guest(
        "for p in /opt/kcov-nfs/deps/usr/sbin/nfs-proxy "
        "/usr/sbin/nfs-proxy /usr/local/bin/nfs-proxy; do "
        "test ! -x \"$p\" || { sha256sum -- \"$p\"; exit 0; }; "
        "done; exit 1")
    proxy = proxy_line.split()[0] if proxy_line.split() else ""
    if re.fullmatch(r"[0-9a-f]{64}", proxy) is None:
        raise RuntimeError("could not identify the guest nfs-proxy binary")
    return {"guest_lane_script_sha256": lane,
            "guest_nfs_proxy_sha256": proxy}


def load_legacy_vm_class():
    """Bootstrap VM used by lifecycle scenarios without target mappings."""
    path = ROOT / "tools/bootstrap-kcov-env.py"
    spec = importlib.util.spec_from_file_location("knfsd_bootstrap", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.VM


def trace_root(vm, events):
    tests = " && ".join(
        "test -e $d/events/%s/enable" % event for event in events)
    return vm.guest(
        "for d in /sys/kernel/tracing /sys/kernel/debug/tracing; do "
        + tests + " && { echo $d; exit 0; }; done; exit 1").strip()


def set_tracing(vm, tracing, events, enabled, clear=False):
    controls = " ".join(
        "%s/events/%s/enable" % (tracing, event) for event in events)
    commands = ["echo 0 > %s/tracing_on" % tracing]
    if clear:
        commands.append("echo > %s/trace" % tracing)
    commands.extend(("for e in %s; do echo %d > $e; done" %
                     (controls, 1 if enabled else 0),
                     "echo %d > %s/tracing_on" %
                     (1 if enabled else 0, tracing)))
    vm.guest("; ".join(commands))


def parse_stats(text):
    stats = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        section = SECTION_RE.match(line)
        if section:
            current = stats.setdefault(section.group(1), {})
            continue
        counter = COUNTER_RE.match(line)
        if current is not None and counter:
            current[counter.group(1)] = int(counter.group(2))
    return stats


def counter_delta(before, after, section, name):
    try:
        old = before[section][name]
        new = after[section][name]
    except KeyError as error:
        raise RuntimeError("missing generation counter %s.%s" %
                           (section, name)) from error
    if new < old:
        raise RuntimeError("generation counter went backwards: %s.%s" %
                           (section, name))
    return new - old


def unsettled_generations(text):
    busy = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        pairs = dict(zip(fields[::2], fields[1::2]))
        if (pairs.get("state") not in ("ABORTED", "COMMITTED", "DEAD") or
                pairs.get("outstanding_tokens") != "0" or
                pairs.get("active_roots") != "0"):
            busy.append(line.strip())
    return busy


def generation_evidence(before_text, after_text):
    before = parse_stats(before_text)
    after = parse_stats(after_text)
    evidence = {
        "generation_begin": counter_delta(
            before, after, "phase4_stats", "generation_begin"),
        "generation_aborted": counter_delta(
            before, after, "phase4_stats", "generation_aborted"),
        "remote_start_ok": counter_delta(
            before, after, "phase5_stats", "remote_start_ok"),
        "aggregate_published": counter_delta(
            before, after, "phase6_stats", "aggregate_published"),
        "scratch_overflow": counter_delta(
            before, after, "phase6_stats", "scratch_overflow"),
        "merge_truncation": counter_delta(
            before, after, "phase6_stats", "aggregate_merge_truncated"),
        "outstanding_tokens": after.get(
            "phase4_stats", {}).get("outstanding_tokens"),
        "remote_refs": after.get("phase6_stats", {}).get("remote_refs"),
    }
    expected = {
        "generation_begin": 1,
        "generation_aborted": 0,
        "aggregate_published": 1,
        "scratch_overflow": 0,
        "merge_truncation": 0,
        "outstanding_tokens": 0,
        "remote_refs": 0,
    }
    for name, value in expected.items():
        if evidence[name] != value:
            raise RuntimeError("invalid generation %s=%r, want %d" %
                               (name, evidence[name], value))
    if evidence["remote_start_ok"] < 1:
        raise RuntimeError("generation has no successful remote KCOV start")
    evidence["attributed"] = True
    return evidence


def parse_cover(text):
    pcs = set()
    for line_number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if not re.fullmatch(r"0x[0-9a-fA-F]+", line):
            raise RuntimeError(
                "malformed remote coverage PC at line %d" % line_number)
        value = int(line, 16)
        if value <= 0 or value >= 2 ** 64:
            raise RuntimeError(
                "remote coverage PC out of range at line %d" % line_number)
        pcs.add(value)
    return pcs


def shareable_error(error):
    """Keep result.json diagnostic without reflecting kernel addresses."""
    message = SHAREABLE_HEX_RE.sub("<redacted-hex>", str(error))
    return "%s: %s" % (type(error).__name__, message)


def exec_watchdog_s(slowdown):
    return 300 * slowdown


def wait_admin_exec(vm, gate, timeout=300):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = vm.guest(
            "if test -f %s; then echo exited; "
            "elif test -f %s.ready; then echo ready; fi" %
            (ADMIN_RC, ADMIN_GATE)).strip()
        if state == "exited" or (gate and state == "ready"):
            return state
        time.sleep(1)
    raise RuntimeError("syz-execprog timed out %s" %
                       ("before gate" if gate else "after gate"))


def start_admin_exec(vm, guest_program, slowdown=1, program_budget_s=None):
    """Start syz-execprog stopped at the gate.

    ``slowdown`` is the collector's execprog slowdown (10 under TCG).
    ``program_budget_s`` is the raised syzkaller program budget of a
    program that partitions (collector.program_timeout_s).
    """
    argv = [ADMIN_GUEST + "/syz-execprog",
            "-executor=" + ADMIN_GUEST + "/syz-executor",
            "-os=linux", "-arch=amd64", "-vmarch=amd64",
            "-sandbox=none", "-procs=1", "-repeat=1", "-threaded=false",
            "-cover=true", "-coverfile=/tmp/cov/cover",
            "-remote-cover=true", "-disable=all", "-debug", "-vv=1",
            "-slowdown=%d" % slowdown, "-gate=" + ADMIN_GATE]
    if program_budget_s is not None:
        argv.append("-program-timeout=%ds" % program_budget_s)
    argv.append(guest_program)
    body = ("timeout %d %s > %s 2>&1; echo $? > %s" %
            (exec_watchdog_s(slowdown), shlex.join(argv), ADMIN_LOG,
             ADMIN_RC))
    command = (
        "rm -rf /tmp/cov %s.ready %s.go %s; mkdir -p /tmp/cov; "
        "setsid nohup sh -c %s < /dev/null > /dev/null 2>&1 &" %
        (ADMIN_GATE, ADMIN_GATE, ADMIN_RC, shlex.quote(body)))
    vm.guest(command)


def one_trace_match(trace, pattern, description):
    matches = list(re.finditer(pattern, trace, re.MULTILINE))
    if len(matches) != 1:
        raise RuntimeError("%s count=%d, want 1" % (description, len(matches)))
    return matches[0]


CLIENT_ID = r"([0-9a-f]{8}:[0-9a-f]{8})"


def validate_courtesy_trace(trace, lifecycle_log):
    """Check one stimulus run's server trace.

    client1's OPEN recalls client0's write delegation
    (``nfsd_cb_recall``), which makes the courteous server expire client0
    (``nfsd_mark_client_expired``) and purge it in the laundromat; client1's
    OPEN is then granted.  client0, healed, recovers with a new clientid:
    EXCHANGE_ID, an unconfirmed CREATE_SESSION slot, and the confirmed
    client.
    """
    if lifecycle_log.strip():
        raise RuntimeError("courtesy stimulus invoked the lifecycle broker")
    expired = one_trace_match(
        trace, r"nfsd_mark_client_expired: .* client " + CLIENT_ID,
        "courtesy client expiry")
    old_client = expired.group(1)
    recall = one_trace_match(
        trace, r"nfsd_cb_recall: .* client " + re.escape(old_client) +
        r"(?:\s|$)", "delegation recall of the expired client")
    purged = one_trace_match(
        trace, r"nfsd_clid_purged: client " + re.escape(old_client) +
        r"(?:\s|$)", "purge of the expired client")
    fresh = one_trace_match(
        trace, r"nfsd_clid_fresh: .* client=" + CLIENT_ID,
        "fresh client trace")
    new_client = fresh.group(1)
    exchange = one_trace_match(
        trace, r"nfsd_compound_status: .* OP_EXCHANGE_ID status=0(?:\s|$)",
        "successful EXCHANGE_ID")
    slot = one_trace_match(
        trace, r"nfsd_slot_seqid_unconf: .* client " + re.escape(new_client) +
        r"(?:\s|$)", "unconfirmed CREATE_SESSION slot")
    confirmed = one_trace_match(
        trace, r"nfsd_clid_confirmed: client " + re.escape(new_client) +
        r"(?:\s|$)", "confirmed recovered client")
    create = one_trace_match(
        trace, r"nfsd_compound_status: .* OP_CREATE_SESSION status=0(?:\s|$)",
        "successful CREATE_SESSION")
    granted = [item for item in re.finditer(
        r"nfsd_compound_status: .* OP_OPEN status=0(?:\s|$)", trace,
        re.MULTILINE) if purged.start() < item.start() < fresh.start()]
    if len(granted) != 1:
        raise RuntimeError("granted conflicting OPEN count=%d, want 1" %
                           len(granted))
    chain = (recall, expired, purged, granted[0], fresh, exchange, slot,
             confirmed, create)
    positions = [item.start() for item in chain]
    if positions != sorted(positions):
        raise RuntimeError("lifecycle trace events are out of order")
    if old_client == new_client:
        raise RuntimeError("recovery reused the expired clientid")
    return {
        "expired_clientid": old_client,
        "recovered_clientid": new_client,
        "ordered_events": list(COURTESY_ORDER),
        # The fresh client's boot verifier is a hex value the shareable
        # result must not carry.
        "selected_trace_lines": [
            SHAREABLE_HEX_RE.sub("(redacted)", item.group(0).strip())
            for item in chain],
    }


def validate_admin_control(trace, lifecycle_log):
    forbidden = ("nfsd_mark_client_expired:", "nfsd_clid_fresh:",
                 "OP_EXCHANGE_ID", "OP_CREATE_SESSION")
    present = [marker for marker in forbidden if marker in trace]
    if lifecycle_log.strip():
        raise RuntimeError("neutral control invoked lifecycle broker")
    if present:
        raise RuntimeError("neutral control entered recovery: %s" % present)
    return {"forbidden_recovery_events": present}


def _optional_guest(vm, command, errors, *, timeout=60):
    try:
        return vm.guest(command, timeout=timeout)
    except Exception as error:
        errors.append("%s: %s" % (command.split()[0], error))
        return None


def _capture_admin_raw(vm, tracing, lifecycle_lines, artifacts, errors,
                       *, execution_started):
    """Best-effort raw capture used on success and every failure path."""
    if not execution_started:
        return []
    commands = (
        ("executor.log", "cat %s" % ADMIN_LOG, 120),
        ("stats-after.txt", STATS_COMMAND, 60),
        ("state-after.txt", STATE_COMMAND, 60),
        ("trace.txt", "cat %s/trace" % tracing, 60),
    )
    for suffix, command, timeout in commands:
        if suffix not in artifacts:
            value = _optional_guest(
                vm, command, errors, timeout=timeout)
            if value is not None:
                artifacts[suffix] = value
    if "lifecycle.log" not in artifacts:
        command = ("cat /tmp/frozen-phase9.manager/lane0/server/lifecycle.log"
                   if lifecycle_lines is None else
                   "tail -n +%d "
                   "/tmp/frozen-phase9.manager/lane0/server/lifecycle.log" %
                   (lifecycle_lines + 1))
        value = _optional_guest(vm, command, errors)
        if value is not None:
            artifacts["lifecycle.log"] = value

    listing = _optional_guest(
        vm, "find /tmp/cov -maxdepth 1 -type f -printf '%f\\n' | sort",
        errors)
    if listing is None:
        return artifacts.get("coverage-files.txt", "").splitlines()
    cover_files = listing.splitlines()
    artifacts.setdefault("coverage-files.txt", "".join(
        name + "\n" for name in cover_files))
    safe_files = [name for name in cover_files
                  if re.fullmatch(r"[A-Za-z0-9_.-]+", name)]
    for name in safe_files:
        suffix = "coverage.raw." + name
        if suffix not in artifacts:
            value = _optional_guest(
                vm, "cat /tmp/cov/" + name, errors, timeout=120)
            if value is not None:
                artifacts[suffix] = value
    extra_files = [name for name in safe_files if name.endswith(".extra")]
    meta_files = [name for name in safe_files if name.endswith(".meta")]
    if len(extra_files) == 1:
        value = artifacts.get("coverage.raw." + extra_files[0])
        if value is not None:
            artifacts["coverage.extra"] = value
    if len(meta_files) == 1:
        value = artifacts.get("coverage.raw." + meta_files[0])
        if value is not None:
            artifacts["coverage.meta"] = value
    return cover_files


def _write_admin_raw(output, stem, artifacts, errors):
    if errors:
        artifacts["artifact-errors.txt"] = "\n".join(errors) + "\n"
    for suffix, contents in sorted(artifacts.items()):
        (output / (stem + "." + suffix)).write_text(contents)


def unpublished_generation_error(meta):
    """Name why a program exported .meta without remote coverage.

    The executor publishes a program's remote coverage only when its KCOV
    generation finishes; a program stopped at its budget aborts it.  Either
    way there is no .extra to export, and the run cannot be evidence.
    """
    match = re.search(r"^unfinished_calls ([0-9]+)$", meta, re.MULTILINE)
    if match is None:
        return RuntimeError(
            "execution: coverage .meta without unfinished_calls; "
            "syz-execprog predates 0029")
    unfinished = int(match.group(1))
    if unfinished:
        return RuntimeError(
            "execution: program stopped at its budget with %d unfinished "
            "calls; remote-KCOV generation not published" % unfinished)
    return RuntimeError(
        "execution: remote-KCOV generation not published")


def run_program(vm, output, phase, iteration, tracing, evaluate, *,
                slowdown=1, program_budget_s=None):
    """Run one gated lifecycle program and evaluate its raw artifacts.

    Raw artifacts are retained for every outcome; ``evaluate`` receives
    them with the parsed remote-KCOV PCs once capture is complete.
    """
    guest_program = "%s/%s.prog" % (ADMIN_GUEST, phase)
    stem = "%s-%03d" % (phase, iteration)
    artifacts = {}
    errors = []
    execution_started = False
    lifecycle_lines = None
    cover_files = []
    try:
        set_tracing(vm, tracing, ADMIN_EVENTS, False, clear=True)
        start_admin_exec(vm, guest_program, slowdown, program_budget_s)
        execution_started = True
        watchdog = exec_watchdog_s(slowdown)
        if wait_admin_exec(vm, True, watchdog) != "ready":
            raise RuntimeError("syz-execprog exited before the program gate")
        state_before = vm.guest(STATE_COMMAND)
        artifacts["state-before.txt"] = state_before
        busy = unsettled_generations(state_before)
        if busy:
            raise RuntimeError("unsettled generation at window start: %s" %
                               busy[0])
        stats_before = vm.guest(STATS_COMMAND)
        artifacts["stats-before.txt"] = stats_before
        lifecycle_lines = int(vm.guest(
            "wc -l < "
            "/tmp/frozen-phase9.manager/lane0/server/lifecycle.log").strip())
        set_tracing(vm, tracing, ADMIN_EVENTS, True, clear=True)
        vm.guest("touch %s.go" % ADMIN_GATE)
        if wait_admin_exec(vm, False, watchdog) != "exited":
            raise RuntimeError("syz-execprog did not exit")
        rc = vm.guest("cat %s" % ADMIN_RC).strip()
        executor_log = vm.guest("cat %s" % ADMIN_LOG, timeout=120)
        artifacts["executor.log"] = executor_log
        if rc == "0":
            time.sleep(10)
        cover_files = _capture_admin_raw(
            vm, tracing, lifecycle_lines, artifacts, errors,
            execution_started=execution_started)
        if rc != "0":
            raise RuntimeError("syz-execprog rc=%s; see retained executor log" %
                               rc)

        if "coverage.meta" in artifacts and "coverage.extra" not in artifacts:
            raise unpublished_generation_error(artifacts["coverage.meta"])
        required = ("stats-before.txt", "stats-after.txt", "trace.txt",
                    "lifecycle.log", "coverage.extra", "coverage.meta")
        missing = [name for name in required if name not in artifacts]
        if missing:
            raise RuntimeError("raw artifact capture incomplete: %s" %
                               ", ".join(missing))
        extra_files = [name for name in cover_files
                       if name.endswith(".extra")]
        meta_files = [name for name in cover_files if name.endswith(".meta")]
        if len(extra_files) != 1 or len(meta_files) != 1:
            raise RuntimeError("coverage file cardinality extra=%d meta=%d" %
                               (len(extra_files), len(meta_files)))

        pcs = parse_cover(artifacts["coverage.extra"])
        return {
            "phase": phase,
            "iteration": iteration,
            **evaluate(artifacts, pcs),
            "coverage_pc_count": len(pcs),
            "coverage_files": cover_files,
        }
    finally:
        _capture_admin_raw(
            vm, tracing, lifecycle_lines, artifacts, errors,
            execution_started=execution_started)
        try:
            set_tracing(vm, tracing, ADMIN_EVENTS, False)
        except Exception as error:
            errors.append("disable-tracing: %s" % error)
        _write_admin_raw(output, stem, artifacts, errors)


def probe_range(source, function, part):
    """1-based inclusive line range of one public probe in kernel source."""
    lines = source.splitlines()
    # A definition starts in column 0, optionally after its return type on
    # the same line; a prototype ends with ";".
    starts = [index for index, line in enumerate(lines)
              if re.match(r"(?:[A-Za-z_][A-Za-z0-9_ *]*[ *])?" +
                          re.escape(function) + r"\(", line)
              and not line.rstrip().endswith(";")]
    if len(starts) != 1:
        raise RuntimeError("probe function %s definitions=%d, want 1" %
                           (function, len(starts)))
    start = starts[0]
    end = next((index for index in range(start, len(lines))
                if lines[index] == "}"), None)
    if end is None:
        raise RuntimeError("probe function %s has no end" % function)
    if part == "function":
        return start + 1, end + 1
    raise ValueError("unknown probe part %s" % part)


def probe_ranges(read_source, table):
    """Resolve a probe table (NLM_PROBES) against the exact kernel source."""
    sources = {}
    ranges = {}
    for name, parts in sorted(table.items()):
        ranges[name] = []
        for path, function, part in parts:
            if path not in sources:
                sources[path] = read_source(path)
            start, end = probe_range(sources[path], function, part)
            ranges[name].append({"path": path, "function": function,
                                 "start_line": start, "end_line": end})
    return ranges


def select_probe_pcs(frames, ranges):
    """Callsites whose inline frame is a probe function within its range."""
    selected = {name: set() for name in ranges}
    for pc, chain in frames:
        for name, items in ranges.items():
            if any(frame.function == item["function"]
                   and frame.line is not None
                   and path_matches(frame.path, item["path"])
                   and item["start_line"] <= frame.line <= item["end_line"]
                   for frame in chain for item in items):
                selected[name].add(pc)
    return selected


def build_probes(context, kernel_source, cache, output, table, kind):
    """Map public probes to coverage callsites of the pinned vmlinux.

    Returns probe PCs and the digest of each probe record.  The records
    name public kernel functions only and are kept beside the raw run
    artifacts for audit.  ``table`` and ``kind`` name the probe set
    (NLM_PROBES, "nlm").
    """
    import subprocess
    import tempfile

    commit = context.descriptor.kernel_commit

    def read_source(path):
        return subprocess.run(
            ["git", "-C", str(kernel_source), "show",
             "%s:%s" % (commit, path)],
            check=True, capture_output=True, text=True).stdout

    ranges = probe_ranges(read_source, table)
    vmlinux = context.files["kernel"]
    found = vmlinux_callsites(
        vmlinux, cache, context.identity.vmlinux_sha256)
    if found.tail_jumps or not found.callsites:
        raise RuntimeError("vmlinux coverage callsites are not in call form")
    with tempfile.TemporaryFile("w+") as addresses:
        addresses.write("".join("%#x\n" % pc for pc in found.callsites))
        addresses.seek(0)
        process = subprocess.Popen(
            ["addr2line", "-a", "-f", "-i", "-e", str(vmlinux)],
            stdin=addresses, stdout=subprocess.PIPE, text=True,
            bufsize=1 << 20)
        with process.stdout:
            selected = select_probe_pcs(iter_addr2line(process.stdout),
                                        ranges)
        if process.wait() != 0:
            raise RuntimeError("addr2line failed on the pinned vmlinux")
    probes = {}
    digests = {}
    for name in sorted(ranges):
        if not selected[name]:
            raise RuntimeError("%s probe %s maps to no callsite" %
                               (kind.upper(), name))
        record = {
            "schema_version": "%s-probe-mapping.v1" % kind,
            "probe": name,
            "identity": context.identity.model_dump(mode="json"),
            "ranges": ranges[name],
            "pcs": ["%#x" % pc for pc in sorted(selected[name])],
        }
        encoded = canonical_json(record)
        (output / ("probe-%s.json" % name)).write_bytes(encoded)
        probes[name] = frozenset(selected[name])
        digests[name] = hashlib.sha256(encoded).hexdigest()
    return probes, digests


def run_nlm_program(vm, output, phase, iteration, tracing, probes,
                    diagnostics, slowdown=1):
    def evaluate(artifacts, pcs):
        lineage = validate_admin_control(
            artifacts["trace.txt"], artifacts["lifecycle.log"])
        return {
            "generation": generation_evidence(
                artifacts["stats-before.txt"], artifacts["stats-after.txt"]),
            "probe_hits": {name: len(pcs & probe)
                           for name, probe in probes.items()},
            "lineage": lineage,
            "diagnostics": {name: len(pcs & probe)
                            for name, probe in diagnostics.items()},
        }

    result = run_program(vm, output, phase, iteration, tracing, evaluate,
                         slowdown=slowdown)
    check_fixture_after(vm, output, phase, iteration, NLM_FIXTURE)
    result["status_check"] = "pass"
    return result


def check_fixture_after(vm, output, phase, iteration, fixture_mode):
    """Require a healthy lane fixture and a clean dmesg after one run."""
    stem = "%s-%03d" % (phase, iteration)
    # The guest API returns stdout and stderr together; keep them apart so
    # the status JSON parses and anything on stderr is retained.
    try:
        raw = vm.guest(
            "/run/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager "
            "2>%s" % STATUS_STDERR)
        (output / (stem + ".lane-status.txt")).write_text(raw)
        stderr = vm.guest("cat %s" % STATUS_STDERR)
        (output / (stem + ".lane-status.stderr.txt")).write_text(stderr)
        status = json.loads(raw)
    except Exception as error:
        raise RuntimeError("fixture: lane status failed after %s: %s" %
                           (phase, error)) from error
    if stderr.strip():
        raise RuntimeError("fixture: lane status wrote to stderr after %s: %s"
                           % (phase, stderr.strip().splitlines()[0][:200]))
    if status.get("fixture_mode") != fixture_mode:
        raise RuntimeError("fixture: lane status changed fixture mode")
    dmesg = vm.guest("dmesg")
    (output / (stem + ".dmesg.txt")).write_text(dmesg)
    crashes = [pattern for pattern in CRASH_PATTERNS if pattern in dmesg]
    if crashes:
        raise RuntimeError("kernel crash signatures: %s" % crashes)


def check_nlm_run(phase, run):
    """Fail closed on a run outside the phase's validated lockd reach."""
    from agent_pipeline.stage1.host.generate import (HCAP13_GRANT_PROBES,
                                                     HCAP13_REQUIRED_PROBES)

    hits = run["probe_hits"]
    if phase == "control":
        reached = sorted(name for name, count in hits.items() if count)
        if reached:
            raise RuntimeError("neutral control reached lockd probe %s" %
                               reached[0])
        return
    for name in HCAP13_REQUIRED_PROBES[phase]:
        if not hits[name]:
            raise RuntimeError("%s run missed %s" % (phase, name))
    if phase == "lock" and any(hits[name] for name in HCAP13_GRANT_PROBES):
        raise RuntimeError("lock run reached a grant callback")


def run_nlm(vm, output, repeat, files, probes, diagnostics, slowdown=1):
    tracing = trace_root(vm, ADMIN_EVENTS)
    vm.guest("mkdir -p %s" % ADMIN_GUEST)
    for name in ("syz-executor", "syz-execprog"):
        vm.put(files[name], ADMIN_GUEST + "/" + name)
    for phase, path in NLM_PROGRAMS.items():
        vm.put(path, "%s/%s.prog" % (ADMIN_GUEST, phase))
    vm.guest("chmod 0755 %s/syz-executor %s/syz-execprog" %
             (ADMIN_GUEST, ADMIN_GUEST))
    cycles = {phase: [] for phase in NLM_PROGRAMS}
    for phase in NLM_PROGRAMS:
        for iteration in range(1, repeat + 1):
            run = run_nlm_program(vm, output, phase, iteration, tracing,
                                  probes, diagnostics, slowdown)
            check_nlm_run(phase, run)
            cycles[phase].append(run)
    return tracing, cycles


def hcap13_evidence(context, guest_identity, probe_digests, cycles,
                    result_bytes, crash_count, artifact_errors):
    """Assemble and type-check the HCAP-13 evidence for this campaign."""
    from agent_pipeline.stage1.host.generate import Hcap13KvmEvidence

    runs = {}
    for phase, items in cycles.items():
        runs[phase] = {
            "completed": len(items),
            "probe_hits": {name: [run["probe_hits"][name] for run in items]
                           for name in sorted(NLM_PROBES)},
            "status_checks_passed": sum(
                run["status_check"] == "pass" for run in items),
            "attributed_generations": sum(
                bool(run["generation"]) for run in items),
        }
    generations = [run["generation"] for items in cycles.values()
                   for run in items]
    evidence = {
        "schema_version": "hcap-kvm-evidence.v1",
        "capability_id": "HCAP-13",
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scenario": "v3-nlm-lock",
        "execution_harness_id": context.identity.execution_harness_id,
        "mapping_identity": context.identity.model_dump(mode="json"),
        "probe_mapping_sha256": probe_digests,
        "campaign_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "guest_lane_script_sha256": guest_identity["guest_lane_script_sha256"],
        "guest_nfs_proxy_sha256": guest_identity["guest_nfs_proxy_sha256"],
        "layout": EXECPROG_LAYOUT,
        "runs": runs,
        "generation_contract": {
            "generation_begin_each": 1,
            "aggregate_published_each": 1,
            "generation_aborted_each": 0,
            "scratch_overflow_each": 0,
            "merge_truncation_each": 0,
            "outstanding_tokens_after_each": 0,
            "remote_refs_after_each": 0,
            "minimum_remote_start_ok": min(
                item["remote_start_ok"] for item in generations),
        },
        "crash_signature_count": crash_count,
        "raw_artifact_error_count": artifact_errors,
        "shareable_result_contains_target_metadata_or_addresses":
        bool(SHAREABLE_HEX_RE.search(result_bytes.decode())),
    }
    return Hcap13KvmEvidence.model_validate(evidence)


def run_courtesy_program(vm, output, phase, iteration, tracing, probes,
                         slowdown=1):
    def evaluate(artifacts, pcs):
        trace = artifacts["trace.txt"]
        lifecycle_log = artifacts["lifecycle.log"]
        if phase == "control":
            lineage = validate_admin_control(trace, lifecycle_log)
        else:
            lineage = validate_courtesy_trace(trace, lifecycle_log)
        return {
            "generation": generation_evidence(
                artifacts["stats-before.txt"], artifacts["stats-after.txt"]),
            "probe_hits": {name: len(pcs & probe)
                           for name, probe in probes.items()},
            "lineage": lineage,
        }

    result = run_program(
        vm, output, phase, iteration, tracing, evaluate, slowdown=slowdown,
        program_budget_s=program_timeout_s(
            COURTESY_PROGRAMS[phase].read_bytes(), slowdown))
    check_fixture_after(vm, output, phase, iteration, "single")
    result["status_check"] = "pass"
    return result


def check_courtesy_run(phase, run):
    """Fail closed on a run outside the phase's validated nfsd reach."""
    hits = run["probe_hits"]
    for name in sorted(COURTESY_PROBES):
        if phase == "control" and hits[name]:
            raise RuntimeError("neutral control reached nfsd probe %s" % name)
        if phase == "stimulus" and not hits[name]:
            raise RuntimeError("stimulus run missed %s" % name)


def run_courtesy(vm, output, repeat, files, probes, slowdown=1):
    tracing = trace_root(vm, ADMIN_EVENTS)
    vm.guest("mkdir -p %s; dmesg -c >/dev/null" % ADMIN_GUEST)
    for name in ("syz-executor", "syz-execprog"):
        vm.put(files[name], ADMIN_GUEST + "/" + name)
    for phase, path in COURTESY_PROGRAMS.items():
        vm.put(path, "%s/%s.prog" % (ADMIN_GUEST, phase))
    vm.guest("chmod 0755 %s/syz-executor %s/syz-execprog" %
             (ADMIN_GUEST, ADMIN_GUEST))
    cycles = {phase: [] for phase in COURTESY_PROGRAMS}
    for phase in COURTESY_PROGRAMS:
        for iteration in range(1, repeat + 1):
            run = run_courtesy_program(vm, output, phase, iteration, tracing,
                                       probes, slowdown)
            check_courtesy_run(phase, run)
            cycles[phase].append(run)
    return tracing, cycles


def hcap11_evidence(context, guest_identity, probe_digests, cycles,
                    result_bytes, crash_count, artifact_errors):
    """Assemble and type-check the HCAP-11 evidence for this campaign."""
    from agent_pipeline.stage1.host.generate import (HCAP11_LEASE_TIME_S,
                                                     HCAP11_PARTITION_HOLD_S,
                                                     Hcap11KvmEvidence)

    runs = {}
    for phase, items in cycles.items():
        runs[phase] = {
            "completed": len(items),
            "probe_hits": {name: [run["probe_hits"][name] for run in items]
                           for name in sorted(COURTESY_PROBES)},
            "status_checks_passed": sum(
                run["status_check"] == "pass" for run in items),
            "attributed_generations": sum(
                bool(run["generation"]) for run in items),
        }
    orders = {tuple(run["lineage"]["ordered_events"])
              for run in cycles["stimulus"]}
    if len(orders) != 1:
        raise RuntimeError("stimulus runs disagree on the recovery order")
    generations = [run["generation"] for items in cycles.values()
                   for run in items]
    evidence = {
        "schema_version": "hcap-kvm-evidence.v1",
        "capability_id": "HCAP-11",
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scenario": "v41-courtesy-expiry",
        "execution_harness_id": context.identity.execution_harness_id,
        "mapping_identity": context.identity.model_dump(mode="json"),
        "probe_mapping_sha256": probe_digests,
        "campaign_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "guest_lane_script_sha256": guest_identity["guest_lane_script_sha256"],
        "guest_nfs_proxy_sha256": guest_identity["guest_nfs_proxy_sha256"],
        "layout": EXECPROG_LAYOUT,
        "nfsv4_lease_time_s": HCAP11_LEASE_TIME_S,
        "partition_hold_s": HCAP11_PARTITION_HOLD_S,
        "runs": runs,
        "generation_contract": {
            "generation_begin_each": 1,
            "aggregate_published_each": 1,
            "generation_aborted_each": 0,
            "scratch_overflow_each": 0,
            "merge_truncation_each": 0,
            "outstanding_tokens_after_each": 0,
            "remote_refs_after_each": 0,
            "minimum_remote_start_ok": min(
                item["remote_start_ok"] for item in generations),
        },
        "recovery_order": list(orders.pop()),
        "crash_signature_count": crash_count,
        "raw_artifact_error_count": artifact_errors,
        "shareable_result_contains_target_metadata_or_addresses":
        bool(SHAREABLE_HEX_RE.search(result_bytes.decode())),
    }
    return Hcap11KvmEvidence.model_validate(evidence)


def lease_guest_script(path):
    path.write_text("""#!/bin/sh
set -eu
iteration=$1
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
root=/tmp/frozen-phase9.manager
client_ns=$(printf 'l40c%03d' "$iteration")
server_link=$(printf 'l40s%03d' "$iteration")
client_link=$(printf 'l40c%03d' "$iteration")
mountpoint_dir=$(printf '%s/lifecycle-v40/mnt-%03d' "$root" "$iteration")
mounted=0
cleanup()
{
    set +e
    test "$mounted" -ne 1 || umount "$mountpoint_dir"
    ip netns del "$client_ns" 2>/dev/null || true
    rm -rf "$mountpoint_dir"
}
trap cleanup EXIT
mkdir -p "$mountpoint_dir"
ip netns add "$client_ns"
ip link add "$client_link" type veth peer name "$server_link"
ip link set "$client_link" netns "$client_ns"
ip link set "$server_link" netns f9l0s
ip -n f9l0s addr add 10.250.0.1/30 dev "$server_link"
ip -n f9l0s link set "$server_link" up
ip -n "$client_ns" link set lo up
ip -n "$client_ns" addr add 10.250.0.2/30 dev "$client_link"
ip -n "$client_ns" link set "$client_link" up
ip netns exec "$client_ns" sh -c \
    "printf '%s\\n' lifecycle-v40-client-$iteration > /sys/fs/nfs/net/nfs_client/identifier"
nsenter --net="/run/netns/$client_ns" -- mount.nfs4 \
    -o vers=4.0,minorversion=0,proto=tcp,port=20490,sec=sys,ro,actimeo=0,lookupcache=none,nosharecache \
    10.250.0.1:/ "$mountpoint_dir"
mounted=1
printf 'iteration=%s identifier=lifecycle-v40-client-%s\\n' "$iteration" "$iteration"
cat "$mountpoint_dir/shared/fixture"
stat "$mountpoint_dir/shared/fixture"
umount "$mountpoint_dir"
mounted=0
ip netns del "$client_ns"
rm -rf "$mountpoint_dir"
trap - EXIT
""")


def control_guest_script(path):
    path.write_text("""#!/bin/sh
set -eu
iteration=$1
deps=/opt/kcov-nfs/deps
PATH="$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin"
LD_LIBRARY_PATH="$deps/usr/lib/x86_64-linux-gnu:$deps/lib/x86_64-linux-gnu"
export PATH LD_LIBRARY_PATH
root=/tmp/frozen-phase9.manager
server_pid=$(cat "$root/lane0/server.pid")
client_mount="$root/lane0/client0/mnt"
server() { nsenter -t "$server_pid" -m -n -- "$@"; }
server_sh() { nsenter -t "$server_pid" -m -n -- sh -c "$1"; }
printf 'iteration=%s\\n' "$iteration"
printf 'pre_io='; timeout 30 cat "$client_mount/shared/fixture"
cld_before=$(server pgrep -xo nfsdcld)
printf 'nfsdcld_before=%s\\n' "$cld_before"
server sh -c 'printf "threads_before="; cat /proc/fs/nfsd/threads; cat /proc/fs/nfsd/portlist'
server_sh 'printf "0\\n" > /proc/fs/nfsd/threads'
server_sh 'printf "tcp 20490\\n" > /proc/fs/nfsd/portlist'
server_sh 'printf "4\\n" > /proc/fs/nfsd/threads'
server sh -c 'printf "threads_after="; cat /proc/fs/nfsd/threads; cat /proc/fs/nfsd/portlist'
grace=$(server cat /proc/fs/nfsd/v4_end_grace)
printf 'grace_before_force=%s\\n' "$grace"
test "$grace" = Y || server_sh 'printf "Y\\n" > /proc/fs/nfsd/v4_end_grace'
printf 'grace_after_force='; server cat /proc/fs/nfsd/v4_end_grace
cld_after=$(server pgrep -xo nfsdcld)
printf 'nfsdcld_after=%s\\n' "$cld_after"
test "$cld_before" = "$cld_after"
printf 'post_io='; timeout 60 cat "$client_mount/shared/fixture"
timeout 60 stat "$client_mount/shared/fixture"
""")


def events_for_client(trace, client):
    events = []
    for line in trace.splitlines():
        client_match = CLIENT_RE.search(line)
        event_match = EVENT_RE.search(line)
        if (client_match and event_match and
                client_match.group(1).lower() == client):
            events.append({"name": event_match.group("name"),
                           "timestamp": event_match.group("timestamp"),
                           "line": line})
    return events


def confirmed_clients(trace):
    clients = []
    for match in re.finditer(
            r"nfsd_clid_confirmed: client ([0-9a-fA-F]{8}:[0-9a-fA-F]{8})",
            trace):
        client = match.group(1).lower()
        if client not in clients:
            clients.append(client)
    return clients


def validate_control(iteration, trace, fixture_log):
    positions = []
    for marker in CONTROL_ORDER:
        matches = [match.start() for match in re.finditer(re.escape(marker), trace)]
        if len(matches) != 1:
            raise RuntimeError("iteration %d marker %r count=%d" %
                               (iteration, marker, len(matches)))
        positions.append(matches[0])
    if positions != sorted(positions):
        raise RuntimeError("iteration %d control events are out of order" % iteration)
    starts = len(re.findall(r"\bnfsd_grace_start:", trace))
    completes = len(re.findall(r"\bnfsd_grace_complete:", trace))
    start_pos = trace.find("nfsd_grace_start:")
    complete_pos = trace.find("nfsd_grace_complete:")
    if starts != 1 or completes != 1 or not (
            positions[-1] < start_pos < complete_pos):
        raise RuntimeError("iteration %d invalid grace sequence" % iteration)
    post_restart = trace[positions[-1]:]
    compounds = len(re.findall(r"\bnfsd_compound:", post_restart))
    successes = len(re.findall(
        r"\bnfsd_compound_status: .* status=0(?:\s|$)", post_restart))
    if compounds < 1 or successes < 1:
        raise RuntimeError("iteration %d has no successful post-restart I/O" % iteration)
    pids = re.findall(r"nfsdcld_(?:before|after)=(\d+)", fixture_log)
    if len(pids) != 2 or pids[0] != pids[1]:
        raise RuntimeError("iteration %d changed nfsdcld identity" % iteration)
    for marker in ("pre_io=frozen Phase 9 lane 0 fixture",
                   "post_io=frozen Phase 9 lane 0 fixture"):
        if marker not in fixture_log:
            raise RuntimeError("iteration %d missing %s" % (iteration, marker))
    return {"iteration": iteration, "ordered_control_events": list(CONTROL_ORDER),
            "grace_start_events": starts, "grace_complete_events": completes,
            "post_restart_compounds": compounds,
            "post_restart_success_statuses": successes,
            "nfsdcld_pid_before": int(pids[0]),
            "nfsdcld_pid_after": int(pids[1])}


def run_control(vm, output, repeat):
    tracing = trace_root(vm, CONTROL_EVENTS)
    script = output / "guest-control.sh"
    control_guest_script(script)
    vm.put(script, "/tmp/guest-control.sh")
    vm.guest("chmod 755 /tmp/guest-control.sh; dmesg -c >/dev/null")
    cycles = []
    fixture_logs = []
    traces = []
    for iteration in range(1, repeat + 1):
        set_tracing(vm, tracing, CONTROL_EVENTS, True, clear=True)
        fixture_log = vm.guest(
            "/tmp/guest-control.sh %d" % iteration, timeout=180)
        set_tracing(vm, tracing, CONTROL_EVENTS, False)
        trace = vm.guest("cat %s/trace" % tracing)
        cycles.append(validate_control(iteration, trace, fixture_log))
        fixture_logs.append("=== iteration %d ===\n%s" %
                            (iteration, fixture_log))
        traces.append("# iteration %d\n%s" % (iteration, trace))
        (output / ("control-trace-%03d.txt" % iteration)).write_text(trace)
    (output / "fixture.txt").write_text("\n".join(fixture_logs))
    (output / "control-trace.txt").write_text("\n".join(traces))
    return tracing, cycles


def run_lease(vm, output, repeat):
    tracing = trace_root(vm, LEASE_EVENTS)
    server_pid = vm.guest(
        "cat /tmp/frozen-phase9.manager/lane0/server.pid").strip()
    vm.guest(
        "deps=/opt/kcov-nfs/deps; "
        "PATH=$deps/usr/sbin:$deps/sbin:/usr/sbin:/sbin:/usr/bin:/bin; "
        "LD_LIBRARY_PATH=$deps/usr/lib/x86_64-linux-gnu:"
        "$deps/lib/x86_64-linux-gnu; export PATH LD_LIBRARY_PATH; "
        "nsenter -t %s -m -n -- exportfs -i "
        "-o ro,sync,insecure,no_subtree_check,no_root_squash,fsid=0 "
        "10.250.0.0/30:/tmp/frozen-phase9.manager/lane0/server/export" %
        server_pid)
    set_tracing(vm, tracing, LEASE_EVENTS, True, clear=True)
    vm.guest("dmesg -c >/dev/null")
    script = output / "guest-lease.sh"
    lease_guest_script(script)
    vm.put(script, "/tmp/guest-lease.sh")
    vm.guest("chmod 755 /tmp/guest-lease.sh")
    seen = set()
    cycles = []
    fixture_logs = []
    trace = ""
    for iteration in range(1, repeat + 1):
        fixture_log = vm.guest(
            "/tmp/guest-lease.sh %d" % iteration, timeout=90)
        fixture_logs.append("=== iteration %d ===\n%s" %
                            (iteration, fixture_log))
        deadline = time.monotonic() + 50
        client = None
        while time.monotonic() < deadline:
            trace = vm.guest("cat %s/trace" % tracing)
            new_clients = [item for item in confirmed_clients(trace)
                           if item not in seen]
            if len(new_clients) > 1:
                raise RuntimeError("iteration %d found multiple clients" % iteration)
            if new_clients:
                client = new_clients[0]
                names = [event["name"] for event in
                         events_for_client(trace, client)]
                if "nfsd_clid_purged" in names:
                    break
            time.sleep(1)
        if client is None:
            raise RuntimeError("iteration %d did not confirm a client" % iteration)
        events = events_for_client(trace, client)
        names = [event["name"] for event in events]
        if names != list(LEASE_ORDER):
            raise RuntimeError("iteration %d lifecycle %s != %s" %
                               (iteration, names, list(LEASE_ORDER)))
        if "cl_rpc_users=0" not in events[1]["line"]:
            raise RuntimeError("iteration %d expired with RPC users" % iteration)
        seen.add(client)
        cycles.append({"iteration": iteration, "client": client,
                       "ordered_events": names,
                       "timestamps": {event["name"]: event["timestamp"]
                                      for event in events},
                       "selected_trace_lines": [event["line"]
                                                for event in events]})
    set_tracing(vm, tracing, LEASE_EVENTS, False)
    (output / "fixture.txt").write_text("\n".join(fixture_logs))
    (output / "lease-trace.txt").write_text(trace)
    return tracing, cycles


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=tuple(SCENARIOS), required=True)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", type=Path,
                        default=ROOT / "env/images/bookworm-kcov-fresh.qcow2")
    parser.add_argument("--kernel", type=Path,
                        default=ROOT / "env/images/kasan/bzImage")
    parser.add_argument("--ssh-key", type=Path,
                        default=ROOT / "artifacts/bookworm.id_rsa")
    parser.add_argument("--collector-config", type=Path,
                        help="Stage1 collector.json (required by "
                        "v41-courtesy-expiry and v3-nlm-lock)")
    parser.add_argument("--descriptor", type=Path,
                        help="exact Stage1 descriptor.json (required by "
                        "v41-courtesy-expiry and v3-nlm-lock)")
    parser.add_argument("--target-pcs", type=Path,
                        help="refused: the probe campaigns map public "
                        "probes themselves")
    parser.add_argument("--kernel-source", type=Path,
                        default=ROOT / "env/linux",
                        help="kernel git tree holding the descriptor's "
                        "kernel commit (probe campaigns)")
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args()
    if args.repeat < 1 or args.repeat > 999:
        parser.error("--repeat must be between 1 and 999")
    definition = SCENARIOS[args.scenario]
    admin_context = None
    if definition["kind"] in ("nlm", "courtesy"):
        if args.repeat < 3:
            parser.error("%s evidence needs --repeat >= 3" % args.scenario)
        for option, path in (("--collector-config", args.collector_config),
                             ("--descriptor", args.descriptor)):
            if path is None or not path.resolve().is_file():
                parser.error("%s is required by %s" % (option, args.scenario))
        if args.target_pcs is not None:
            parser.error("%s maps public probes itself; do not pass a "
                         "candidate --target-pcs mapping" % args.scenario)
        if definition["kind"] == "nlm":
            selection = dict(required=NLM_REQUIRED_INTERFACES,
                             profile="knfsd-v3", nfs_version="3",
                             fixture_mode=NLM_FIXTURE)
            programs = NLM_PROGRAMS
        else:
            selection = dict(required=COURTESY_REQUIRED_INTERFACES)
            programs = COURTESY_PROGRAMS
        try:
            admin_context = load_admin_context(
                args.collector_config.resolve(), args.descriptor.resolve(),
                None, **selection)
        except Exception as error:
            parser.error("invalid identity-bound lifecycle inputs: %s" % error)
        for path in programs.values():
            if not path.is_file():
                parser.error("missing lifecycle program: %s" % path)
    else:
        for name in ("image", "kernel", "ssh_key"):
            path = getattr(args, name).resolve()
            if not path.is_file():
                parser.error("missing --%s: %s" %
                             (name.replace("_", "-"), path))
            setattr(args, name, path)
    output = args.output.resolve()
    if output.exists() or output.is_symlink():
        parser.error("output must not already exist: %s" % output)
    # Raw coverage intentionally remains available for private audit even
    # though result.json omits target addresses. Keep the containing
    # directory inaccessible to other local users.
    output.mkdir(parents=True, mode=0o700)

    result = {"scenario": args.scenario, "native_version": definition["version"],
              "iterations": args.repeat, "transport": "TCP", "status": "fail"}
    probes = probe_digests = guest_identity = diagnostics = None
    cycles = None
    if definition["kind"] in ("nlm", "courtesy"):
        # Host-only: map the public probes before booting the guest.
        if definition["kind"] == "nlm":
            table, kind = NLM_PROBES, "nlm"
            extra = NLM_DIAGNOSTIC_PROBES
        else:
            table, kind, extra = COURTESY_PROBES, "nfsd", {}
        try:
            mapped, digests = build_probes(
                admin_context, args.kernel_source.resolve(),
                output / "probe-cache", output, {**table, **extra}, kind)
            probes = {name: mapped[name] for name in table}
            probe_digests = {name: digests[name] for name in table}
            diagnostics = {name: mapped[name] for name in extra}
        except Exception as error:
            result["error"] = shareable_error(error)
            (output / "result.json").write_text(
                json.dumps(result, indent=2, sort_keys=True) + "\n")
            raise
        result["probe_mapping_sha256"] = probe_digests
    if admin_context is not None:
        result["evidence_identity"] = dict(
            admin_context.evidence_identity)
        vm = make_admin_vm(admin_context, output)
    else:
        vm = load_legacy_vm_class()(
            args.image, args.kernel, args.ssh_key,
            args.boot_timeout, definition["version"],
            accel=resolve_accel())
    tracing = None
    try:
        vm.start()
        fixture_state = vm.guest(
            "systemctl is-active frozen-phase9-fixture.service || true").strip()
        if fixture_state != "active":
            raise RuntimeError("fixture service is " + fixture_state)
        status = json.loads(vm.guest(
            "/run/frozen-phase9/lane.sh status /tmp/frozen-phase9.manager"))
        if (status.get("fixture_mode") !=
                definition.get("fixture", "single") or
                status.get("nfs_version") != definition["version"]):
            raise RuntimeError("fixture selected the wrong profile")
        if definition["kind"] == "lease":
            tracing, cycles = run_lease(vm, output, args.repeat)
            result["complete_lifecycle_chains"] = len(cycles)
        elif definition["kind"] == "courtesy":
            guest_identity = verify_admin_guest(vm, admin_context)
            result["evidence_identity"].update(guest_identity)
            tracing, cycles = run_courtesy(
                vm, output, args.repeat, admin_context.files, probes,
                admin_context.config.exec_slowdown)
            result["complete_runs"] = {
                phase: len(items) for phase, items in cycles.items()}
        elif definition["kind"] == "nlm":
            guest_identity = verify_admin_guest(vm, admin_context)
            result["evidence_identity"].update(guest_identity)
            tracing, cycles = run_nlm(
                vm, output, args.repeat, admin_context.files, probes,
                diagnostics, admin_context.config.exec_slowdown)
            result["complete_runs"] = {
                phase: len(items) for phase, items in cycles.items()}
        else:
            tracing, cycles = run_control(vm, output, args.repeat)
            result["complete_control_cycles"] = len(cycles)
        dmesg = vm.guest("dmesg")
        (output / "dmesg.txt").write_text(dmesg)
        crashes = [pattern for pattern in CRASH_PATTERNS if pattern in dmesg]
        if crashes:
            raise RuntimeError("kernel crash signatures: %s" % crashes)
        result.update({"status": "pass", "fixture_service": fixture_state,
                       "trace_root": tracing, "cycles": cycles,
                       "crash_signatures": crashes})
    except Exception as error:
        result["error"] = shareable_error(error)
        if tracing:
            try:
                (output / "failure-trace.txt").write_text(
                    vm.guest("cat %s/trace" % tracing))
                (output / "dmesg.txt").write_text(vm.guest("dmesg"))
            except Exception:
                pass
        raise
    finally:
        vm.stop()
        encoded = (json.dumps(result, indent=2, sort_keys=True) +
                   "\n").encode()
        (output / "result.json").write_bytes(encoded)
        print(encoded.decode(), end="", flush=True)
        if (definition["kind"] in ("nlm", "courtesy")
                and result["status"] == "pass"):
            errors = sum(1 for _ in output.glob("*.artifact-errors.txt"))
            make, name, capability = (
                (hcap13_evidence, "hcap13-kvm.json", "HCAP-13")
                if definition["kind"] == "nlm" else
                (hcap11_evidence, "hcap11-kvm.json", "HCAP-11"))
            evidence = make(
                admin_context, guest_identity, probe_digests, cycles,
                encoded, len(result["crash_signatures"]), errors)
            (output / name).write_text(
                evidence.model_dump_json(indent=2) + "\n")
            print("%s evidence: %s" % (capability, output / name))


if __name__ == "__main__":
    main()
