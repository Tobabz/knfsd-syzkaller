"""``python -m agent_pipeline.stage1.host COMMAND``.

``generate SPEC``           write every host record and stage1.json
``collect --config C IN OUT``  the engine's host command (one lease)
``probe --stage1 S --program P --out D``  boot and run one program, no service
``target-pcs --stage1 S --job J --out F``  verified TargetPcMapping for a job
``check-pcs --stage1 S --coverage F``  are published PCs coverage call sites?
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ...artifacts import ArtifactStore
from ...data import load_record
from ...materializer import ExecutionHarnessApproval, ExecutionHarnessDescriptor
from ...q1 import CandidateTarget, KernelIdentity
from ..config import Stage1Config
from .collector import CollectorConfig, CollectorError, collect
from .pins import HostFilePin, PinCache, verify_file


def _collector(args) -> CollectorConfig:
    path = args.collector or Path(Stage1Config.load(args.stage1).state_dir) \
        / "collector.json"
    return CollectorConfig.load(path)


def _descriptor(config: Stage1Config, harness_id: str | None = None,
                variant: str | None = None) -> ExecutionHarnessDescriptor:
    """The descriptor ``harness_id`` names, else the approved one of
    ``variant`` (a sanitizer), else the first approved one."""
    store = ArtifactStore(config.artifact_root)
    if harness_id is not None:
        return load_record(store, harness_id, ExecutionHarnessDescriptor)
    descriptors = [load_record(store, ref, ExecutionHarnessApproval).descriptor
                   for ref in config.execution_harness_approvals]
    if variant is None:
        return descriptors[0]
    found = [d for d in descriptors if d.sanitizer.value == variant]
    if not found:
        raise SystemExit(f"no approved {variant} harness; approved: "
                         + ", ".join(d.sanitizer.value for d in descriptors))
    return found[0]


def _vmlinux(config: Stage1Config, collector: CollectorConfig,
             descriptor: ExecutionHarnessDescriptor) -> tuple[Path, HostFilePin]:
    store = ArtifactStore(config.artifact_root)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    name = config.vmlinux_artifact_name
    pin = load_record(store, builds[name], HostFilePin)
    path = collector.files_for(descriptor.sanitizer)[name]
    verify_file(pin, path, PinCache(collector.pin_cache))
    return path, pin


def cmd_generate(args) -> int:
    from .generate import generate
    result = generate(args.spec)
    print(json.dumps(result.model_dump(mode="json"), indent=2, default=str))
    return 0


def cmd_collect(args) -> int:
    try:
        result = collect(CollectorConfig.load(args.config), args.input,
                         args.output)
    except CollectorError as exc:
        print(f"collector: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({k: result[k] for k in (
        "vm_instance_id", "facts", "published_pc_count", "runtime_errors",
        "crash")}))
    return 0


def cmd_probe(args) -> int:
    """Run one program the way ``collect`` does, without the service: the
    first check on a new host (boot, fixture, counters, coverage)."""
    from ...hcap import RuntimeSelection
    from .collector import (crash_report, guest_cmdline, run_lane,
                            verify_pins)
    from .kcov import counter_deltas, generation_counters
    from .vm import QemuGuest, VmConfig
    config = Stage1Config.load(args.stage1)
    collector = _collector(args)
    descriptor = _descriptor(config, variant=args.variant)
    files = verify_pins(collector, descriptor)
    selection = descriptor.allowed_runtime_selections[args.selection]
    if args.trace:
        selection = RuntimeSelection.model_validate(
            {**selection.model_dump(), "trace_mode": "on"})
    store = ArtifactStore(config.artifact_root)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    lane = load_record(store, builds["lane-script"], HostFilePin)
    args.out.mkdir(parents=True, exist_ok=True)
    guest = QemuGuest(VmConfig(
        qemu=collector.qemu, bzimage=files["bzimage"],
        image=files["vm-image"], lane_dir=files["lane-script"].parent,
        ssh_key=collector.ssh_key,
        cmdline=guest_cmdline(descriptor, selection, lane.sha256),
        console_log=args.out / "console.log",
        memory_mb=collector.memory_mb, cpus=collector.cpus,
        boot_timeout_s=collector.boot_timeout_s))
    result: dict = {"selection": selection.model_dump(mode="json")}
    try:
        run = run_lane(guest, files, args.program, selection, lane.sha256,
                       collector, args.out, result)
    finally:
        guest.stop()
    summary = {k: getattr(run, k) for k in (
        "boot_ok", "fixture_ok", "lane_ok", "runner_completed",
        "collection_started", "collection_completed", "extra_present")}
    summary["runtime_errors"] = run.runtime_errors
    crash = crash_report(args.out, args.out / "console.log", descriptor)
    summary["crash"] = None if crash is None else crash.model_dump(mode="json")
    summary["published_pcs"] = len(run.pcs)
    if run.stats_before is not None and run.stats_after is not None:
        summary["generation"] = generation_counters(
            run.stats_before, run.stats_after).model_dump()
        deltas = counter_deltas(run.stats_before, run.stats_after)
        summary["counter_labels"] = sorted(d.counter for d in deltas)
        summary["nonzero_deltas"] = {d.counter: d.value for d in deltas
                                     if d.value}
    (args.out / "pcs.txt").write_text(
        "".join(f"0x{pc:x}\n" for pc in sorted(run.pcs)))
    (args.out / "probe.json").write_text(
        json.dumps({**result, "summary": summary}, indent=2, default=str))
    print(json.dumps(summary, indent=2))
    return 0 if not run.runtime_errors else 1


def cmd_target_pcs(args) -> int:
    from ...controller.store import Store
    from .target_pcs import build_mapping
    config = Stage1Config.load(args.stage1)
    collector = _collector(args)
    store = Store(Path(config.state_dir) / "controller.sqlite")
    try:
        job = store.job(args.job)
    finally:
        store.close()
    if job.candidate is None or job.binding is None:
        raise SystemExit(f"{args.job} has no accepted candidate or harness "
                         f"binding yet (state {job.state.value})")
    descriptor = _descriptor(config, job.binding.execution_harness_id)
    vmlinux, pin = _vmlinux(config, collector, descriptor)
    builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
    identity = KernelIdentity(
        execution_harness_id=job.binding.execution_harness_id,
        kernel_commit=descriptor.kernel_commit,
        instrumentation_sha256=builds[config.instrumentation_artifact_name],
        vmlinux_sha256=builds[config.vmlinux_artifact_name],
        kaslr_enabled=False, kaslr_offset=0)
    c = job.candidate
    target = CandidateTarget(candidate_id=c.candidate_id,
                             kernel_commit=c.kernel_commit,
                             **c.location.model_dump(mode="json"))
    cache = args.cache or Path(config.state_dir) / "target-pcs-cache"
    mapping = build_mapping(vmlinux, target, identity, pin.sha256,
                            cache=cache)
    args.out.write_text(mapping.model_dump_json(indent=2) + "\n")
    print(f"{len(mapping.target_pcs)} target PCs for {target.path}:"
          f"{target.start_line}-{target.end_line} -> {args.out}")
    print(f"register with: python -m agent_pipeline.stage1 --config "
          f"{args.stage1} add-mapping {args.out}")
    return 0


def cmd_check_pcs(args) -> int:
    from .kcov import parse_cover_pcs
    from .target_pcs import check_pcs, vmlinux_callsites
    config = Stage1Config.load(args.stage1)
    collector = _collector(args)
    vmlinux, pin = _vmlinux(config, collector,
                            _descriptor(config, variant=args.variant))
    text = args.coverage.read_text()
    if text.lstrip().startswith("{"):
        pcs = json.loads(text)["pcs"]
    else:
        pcs = parse_cover_pcs(text)
    cache = args.cache or Path(config.state_dir) / "target-pcs-cache"
    report = check_pcs(pcs, vmlinux_callsites(vmlinux, cache, pin.sha256))
    print(json.dumps(report))
    ok = (report["published"] and not report["callback_tail_jumps"]
          and report["callsites"] == report["published"])
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m agent_pipeline.stage1.host",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    g = sub.add_parser("generate")
    g.add_argument("spec", type=Path)
    c = sub.add_parser("collect")
    c.add_argument("--config", type=Path, required=True)
    c.add_argument("input", type=Path)
    c.add_argument("output", type=Path)
    for name in ("probe", "target-pcs", "check-pcs"):
        p = sub.add_parser(name)
        p.add_argument("--stage1", type=Path, required=True)
        p.add_argument("--collector", type=Path)
        if name != "target-pcs":
            # target-pcs takes the job's own harness.
            p.add_argument("--variant", help="sanitizer of the approved "
                           "harness to use (default: the first)")
        if name == "probe":
            p.add_argument("--program", type=Path, required=True)
            p.add_argument("--out", type=Path, required=True)
            p.add_argument("--selection", type=int, default=0,
                           help="index into allowed_runtime_selections")
            p.add_argument("--trace", action="store_true")
        elif name == "target-pcs":
            p.add_argument("--job", required=True)
            p.add_argument("--out", type=Path, required=True)
            p.add_argument("--cache", type=Path)
        else:
            p.add_argument("--coverage", type=Path, required=True,
                           help="coverage.json or a cover_prog*.extra file")
            p.add_argument("--cache", type=Path)
    args = ap.parse_args(argv)
    return {"generate": cmd_generate, "collect": cmd_collect,
            "probe": cmd_probe, "target-pcs": cmd_target_pcs,
            "check-pcs": cmd_check_pcs}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
