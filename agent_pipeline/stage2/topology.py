"""HCAP-04 lane-topology campaign: a bounded Stage 2 manager run (#99).

``python -m agent_pipeline.stage2.topology`` runs the generated Stage 2
manager config at ``--procs`` procs (one per NFS lane) with a neutral lane
I/O corpus and an empty NFSPRUL1 rule set, so the NFS proxy activates on
every program and edits nothing.  It stops once every lane has
``--executions`` campaign executions, then checks each lane on its own:

* syz-manager's evidence spool: every execution on the lane has a
  remote-KCOV generation with attributed PCs, a generation no other
  execution reused, an acked NFS proxy activation and deactivation, and it
  ran, cleared its lease, did not hang and reported no error;
* the lane's own journal channel ``nfsp-journal-<lane>``: a GENERATION_OPEN
  for each of those generations, and no event that names another lane or
  belongs to another lane's session series.

A guest crash, a manager crash report or an unexpected manager exit fails
the campaign.  The output directory gets ``result.json`` and, when every
check passed, ``hcap04-kvm.json`` (``LaneTopologyEvidence``), which the host
generator accepts as typed evidence for HCAP-01, HCAP-03 and HCAP-04 with
``validated_layout`` {procs N, lanes 0..N-1}.

The manager owns its VM, so ``lane.sh status`` cannot run inside it; the
per-execution lease and health fields above are the executor's lane check
for each program.  Nothing here acts on the NFS server.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ..data import canonical_json
from ..journal_sink import StoredEvent
from ..materializer import ExecutionHarnessDescriptor, descriptor_id
from ..protocol_schema import load_schemas
from ..q1 import KernelIdentity
from ..rule_compiler import encode_rule_set
from ..stage1.host.collector import CollectorConfig, verify_pins
from ..stage1.host.generate import (LANE_TOPOLOGY_CAPABILITIES,
                                    LANE_TOPOLOGY_MIN_EXECUTIONS,
                                    LANE_TOPOLOGY_PROGRAM_SHA256,
                                    LaneTopologyEvidence)
from .kvm import (_CRASH, NfsProxyExecution, Stage2StepError,
                  _corpus, _crash_files, _JournalChannels, _lane_template,
                  _manager_assets, _manager_cmdline, _manager_qemu_args,
                  _spool, _stop_manager)

CANDIDATE_ID = "hcap04-lane-topology"
DEFAULT_PROGRAM = (Path(__file__).resolve().parents[2] / "tools" /
                   "nfs-lifecycle" / "programs" / "v41-client-io-control.prog")
SHAREABLE_HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
POLL_S = 1.0
MANAGER_STOP_TIMEOUT_S = 45.0


def program_calls(program: bytes) -> list[str]:
    """The calls a syz program names, in order of first use: the manager
    enables exactly these, so the campaign stays lane I/O."""
    calls: list[str] = []
    for line in program.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        call = line.split("(", 1)[0].split("=")[-1].strip()
        if call not in calls:
            calls.append(call)
    return calls


def _selection(descriptor: ExecutionHarnessDescriptor, cmdline: str):
    """The one single-fixture selection the manager's koov arguments boot."""
    tokens = dict(token.partition("=")[::2] for token in cmdline.split()
                  if token.startswith("koov."))
    version = tokens.get("koov.nfs_version")
    matches = [s for s in descriptor.allowed_runtime_selections
               if s.fixture_mode == "single" and s.nfs_version == version
               and s.trace_mode == ("on" if tokens.get("koov.nfs_trace") == "1"
                                    else "off")]
    if len(matches) != 1:
        raise Stage2StepError("the manager boots no single approved "
                              "single-fixture runtime selection")
    return matches[0]


def empty_rule_set(nfs_version: str) -> bytes:
    """An NFSPRUL1 set with no rules for the selection's schema: the proxy
    activates and forwards every message unchanged."""
    family = "nfs3" if nfs_version == "3" else f"nfs{nfs_version}"
    ids = [schema_id for schema_id in load_schemas()
           if schema_id.startswith(family + "/")]
    if len(ids) != 1:
        raise Stage2StepError(f"no single ProtocolSchema for NFS {nfs_version}")
    return encode_rule_set(ids[0], CANDIDATE_ID, [])


def _healthy(record: NfsProxyExecution) -> bool:
    return (record.executed and record.lease_cleared and not record.hanged
            and not record.error)


def _acked(record: NfsProxyExecution) -> bool:
    return (record.activation == "Acked" and record.activation_status == 0
            and record.deactivation == "Acked"
            and record.deactivation_status == 0)


def _attributed(record: NfsProxyExecution) -> bool:
    return bool(record.generation and record.program_digest and record.pcs)


def _event_lane(event: StoredEvent) -> int | None:
    correlation = getattr(event.request.payload, "correlation", None)
    return None if correlation is None else correlation.lane_id


def lane_results(records: list[NfsProxyExecution], events: list[StoredEvent],
                 prefixes: tuple[str, ...]) -> list[dict[str, Any]]:
    """Per-lane counts for LaneTopologyLane, from the manager's spool and the
    host journal.  ``prefixes[lane]`` is the lane's session series."""
    results = []
    for lane, prefix in enumerate(prefixes):
        channel = f"nfsp-journal-{lane}"
        mine = [r for r in records if r.campaign and r.lane == lane]
        attributed = [r for r in mine if _attributed(r)]
        generations = {r.generation for r in attributed}
        on_channel = [e for e in events if e.binding.channel_id == channel]
        opened = {e.request.payload.correlation.kcov_generation
                  for e in on_channel
                  if e.request.event_type == "GENERATION_OPEN"}
        foreign = [e for e in on_channel
                   if not e.binding.proxy_session_id.startswith(prefix)
                   or _event_lane(e) not in (None, lane)]
        # An event of this lane's series on another channel is foreign too.
        foreign += [e for e in events
                    if e.binding.channel_id != channel
                    and e.binding.proxy_session_id.startswith(prefix)]
        results.append({
            "lane": lane,
            "executions": len(mine),
            "attributed_executions": len(attributed),
            "distinct_generations": len(generations),
            "proxy_acked_executions": sum(_acked(r) for r in mine),
            "healthy_executions": sum(_healthy(r) for r in mine),
            "journal_generations": len(opened),
            "generations_missing_from_journal": len(generations - opened),
            "foreign_journal_events": len(foreign),
        })
    return results


def _enough(records: list[NfsProxyExecution], procs: int,
            executions: int) -> bool:
    counts = [0] * procs
    for record in records:
        if record.campaign and record.lane < procs:
            counts[record.lane] += 1
    return min(counts) >= executions


def _validate_manager_mode(manager: dict[str, Any]) -> None:
    if manager.get("snapshot", False) is not False:
        raise Stage2StepError(
            "manager program snapshot mode must be disabled")
    experimental = manager.get("experimental")
    if not isinstance(experimental, dict) or \
            experimental.get("remote_cover") is not True:
        raise Stage2StepError(
            "manager must enable experimental.remote_cover")


def run(*, manager_path: Path, collector_path: Path, descriptor_path: Path,
        output: Path, procs: int, executions: int, timeout_s: float) \
        -> dict[str, Any]:
    """Run the campaign; write ``result.json`` and, on a pass, the typed
    evidence.  Returns the result."""
    if output.exists():
        raise Stage2StepError(f"output exists: {output}")
    output.mkdir(parents=True)
    collector = CollectorConfig.load(collector_path)
    descriptor = ExecutionHarnessDescriptor.model_validate_json(
        descriptor_path.read_bytes())
    files = verify_pins(collector, descriptor)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    manager = json.loads(manager_path.read_text())
    _validate_manager_mode(manager)
    vm = manager.get("vm")
    if manager.get("type") != "qemu" or not isinstance(vm, dict) or \
            vm.get("count", 1) != 1:
        raise Stage2StepError("manager must configure one qemu VM")
    lane_pin = _manager_assets(manager, vm, collector, descriptor, builds)
    selection = _selection(descriptor, str(vm.get("cmdline", "")))
    _manager_cmdline(vm, descriptor, SimpleNamespace(
        runtime_selection=selection), lane_pin.sha256)
    program = DEFAULT_PROGRAM.read_bytes()
    program_sha256 = hashlib.sha256(program).hexdigest()
    if program_sha256 != LANE_TOPOLOGY_PROGRAM_SHA256:
        raise Stage2StepError(
            "default program differs from the trusted lane-topology corpus")
    rules = empty_rule_set(selection.nfs_version)

    work = output / "work"
    workdir, spool = work / "manager-workdir", work / "executions"
    workdir.mkdir(parents=True)
    spool.mkdir()
    _corpus(workdir / "corpus.db", program)
    vm_id = f"hcap04-topology.{uuid.uuid4().hex[:12]}"
    prefixes = tuple(f"tl{lane}-{uuid.uuid4().hex}" for lane in range(procs))
    lane_dir = _lane_template(Path(manager["workdir_template"]), work / "lane",
                              rules, prefixes)
    channels = _JournalChannels(work / "journal", "topology", vm_id, procs,
                                rules, prefixes)
    manager.update({
        "workdir": str(workdir), "workdir_template": str(lane_dir),
        "http": "", "procs": procs, "reproduce": False,
        "enable_syscalls": program_calls(program)})
    manager.setdefault("experimental", {})["nfs_proxy_evidence"] = str(spool)
    manager["vm"]["qemu_args"] = _manager_qemu_args(
        str(manager["vm"].get("qemu_args", "")), channels)
    config = work / "manager.json"
    config.write_text(json.dumps(manager, indent=2, sort_keys=True) + "\n")
    log_path = work / "manager-debug.log"
    binary = Path(str(manager["syzkaller"])) / "bin" / "syz-manager"
    exited = False
    process = None
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [str(binary), "-config", str(config), "-debug"],
                stdin=subprocess.DEVNULL, stdout=log,
                stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                reports, crash_log = _crash_files(workdir)
                if reports or crash_log is not None or \
                        _enough(_spool(spool), procs, executions):
                    break
                if process.poll() is not None:
                    exited = True
                    break
                time.sleep(POLL_S)
    finally:
        if process is not None:
            _stop_manager(process, MANAGER_STOP_TIMEOUT_S)
        channels.close()
    records = _spool(spool)
    events = channels.journal.events()
    reports, crash_log = _crash_files(workdir)
    console = log_path.read_bytes()
    crashes = len(reports) + (crash_log is not None) + \
        len(_CRASH.findall(console))
    result: dict[str, Any] = {
        "schema_version": "hcap04-lane-topology-result.v1",
        "procs": procs, "min_executions_per_lane": executions,
        "program_sha256": program_sha256,
        "rule_set_sha256": hashlib.sha256(rules).hexdigest(),
        "manager_exited_unexpectedly": exited,
        "crash_signature_count": crashes,
        "lanes": lane_results(records, events, prefixes),
    }
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    (output / "result.json").write_bytes(encoded)
    evidence = topology_evidence(descriptor, collector, lane_pin.sha256,
                                 result, encoded)
    (output / "hcap04-kvm.json").write_text(
        evidence.model_dump_json(indent=2) + "\n")
    return result


def topology_evidence(descriptor: ExecutionHarnessDescriptor,
                      collector: CollectorConfig, lane_sha256: str,
                      result: dict[str, Any],
                      result_bytes: bytes) -> LaneTopologyEvidence:
    """Type-check the campaign result as HCAP-04 evidence; a lane or
    campaign that failed a check raises."""
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    harness_id = descriptor_id(descriptor)
    identity = KernelIdentity(
        execution_harness_id=harness_id,
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds[collector.instrumentation_artifact_name],
        vmlinux_sha256=builds[collector.vmlinux_artifact_name],
        kaslr_enabled=False, kaslr_offset=0)
    procs = result["procs"]
    return LaneTopologyEvidence.model_validate_json(canonical_json({
        "schema_version": "hcap-kvm-evidence.v1",
        "capability_id": "HCAP-04",
        "capability_ids": list(LANE_TOPOLOGY_CAPABILITIES),
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scenario": "stage2-lane-topology",
        "execution_harness_id": harness_id,
        "mapping_identity": identity.model_dump(mode="json"),
        "campaign_result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        "program_sha256": result.get("program_sha256"),
        "guest_lane_script_sha256": lane_sha256,
        "layout": {"procs": procs, "lanes": list(range(procs))},
        "min_executions_per_lane": result["min_executions_per_lane"],
        "lanes": result["lanes"],
        "manager_exited_unexpectedly": result["manager_exited_unexpectedly"],
        "crash_signature_count": result["crash_signature_count"],
        "shareable_result_contains_target_metadata_or_addresses":
        bool(SHAREABLE_HEX_RE.search(result_bytes.decode())),
    }))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--manager", type=Path, required=True,
                        help="the generated Stage 2 manager config")
    parser.add_argument("--collector", type=Path, required=True)
    parser.add_argument("--descriptor", type=Path, required=True,
                        help="the execution harness descriptor JSON")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--procs", type=int, default=4)
    parser.add_argument("--executions", type=int,
                        default=LANE_TOPOLOGY_MIN_EXECUTIONS,
                        help="campaign executions each lane must reach")
    parser.add_argument("--timeout", type=float, default=3600,
                        help="campaign seconds before it stops short")
    args = parser.parse_args(argv)
    if not 1 <= args.procs <= 64:
        parser.error("--procs must be in [1, 64]")
    if args.executions < LANE_TOPOLOGY_MIN_EXECUTIONS:
        parser.error(f"--executions must be at least "
                     f"{LANE_TOPOLOGY_MIN_EXECUTIONS}")
    try:
        result = run(manager_path=args.manager, collector_path=args.collector,
                     descriptor_path=args.descriptor, output=args.output,
                     procs=args.procs, executions=args.executions,
                     timeout_s=args.timeout)
    except (Stage2StepError, ValueError, OSError) as error:
        print(f"lane topology campaign failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    print(f"HCAP-04 evidence: {args.output / 'hcap04-kvm.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
