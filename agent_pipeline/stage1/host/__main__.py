"""``python -m agent_pipeline.stage1.host COMMAND``.

``generate SPEC``           write every host record and stage1.json
``collect --config C IN OUT``  the engine's host command (one lease)
``validate --config V IN OUT``  the validation command of a Harness
                            Generation patch set (07 §5.2)
``probe-campaign --config C OUT``  the promotion probe campaign of a
                            capability (07 §5.3)
``probe --stage1 S --program P --out D``  boot and run one program, no service
``target-pcs --stage1 S --job J --out F``  verified TargetPcMapping for a job
``check-pcs --stage1 S --coverage F``  are published PCs coverage call sites?
``check-pins --stage1 S``   does every pinned host file still match its pin?
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ...artifacts import ArtifactStore
from ...data import load_record
from ...materializer import (ExecutionHarnessApproval, ExecutionHarnessDescriptor,
                            descriptor_id)
from ...q1 import CandidateTarget, KernelIdentity
from ..config import Stage1Config
from .collector import CollectorConfig, CollectorError, collect, pinned_path
from .pins import REBUILT_HINT, HostFilePin, PinCache, PinError


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
    path = pinned_path(collector, pin,
                       collector.files_for(descriptor.sanitizer)[name],
                       PinCache(collector.pin_cache))
    return path, pin


def check_pins(config: Stage1Config, collector: CollectorConfig
               ) -> list[tuple[str, str, str, str]]:
    """(harness, file, status, detail) for every file a configured
    approved descriptor pins and the collector has a path for.  ``ok``: the
    configured file matches; ``staged``: a staged copy of the pinned digest
    does; ``stale``: neither does; ``missing``: no file."""
    store = ArtifactStore(config.artifact_root)
    cache = PinCache(collector.pin_cache)
    rows = []
    for ref in config.execution_harness_approvals:
        descriptor = load_record(store, ref, ExecutionHarnessApproval).descriptor
        harness = f"{descriptor.sanitizer.value}:{descriptor_id(descriptor)[:12]}"
        builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
        for name, path in sorted(collector.files_for(descriptor.sanitizer).items()):
            if name not in builds:
                rows.append((harness, name, "stale",
                             "not a build artifact of the descriptor"))
                continue
            pin = load_record(store, builds[name], HostFilePin)
            try:
                used = pinned_path(collector, pin, path, cache)
            except PinError as exc:
                status = "missing" if not Path(path).is_file() else "stale"
                rows.append((harness, name, status, str(exc)))
            else:
                rows.append((harness, name, "ok" if used == path else "staged",
                             str(used)))
    return rows


def cmd_check_pins(args) -> int:
    rows = check_pins(Stage1Config.load(args.stage1), _collector(args))
    for harness, name, status, detail in rows:
        print(f"{status:7} {harness} {name}: {detail}")
    bad = [r for r in rows if r[2] in ("stale", "missing")]
    if bad:
        print(f"{len(bad)} pinned file(s) differ: {REBUILT_HINT}",
              file=sys.stderr)
    return 1 if bad else 0


def cmd_generate(args) -> int:
    from .generate import generate
    gap = None
    if args.gap is not None:
        from ...hcap import GapContract
        gap = GapContract.model_validate_json(args.gap.read_bytes())
    result = generate(args.spec, gap=gap, base_spec=args.base_spec)
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


def cmd_validate(args) -> int:
    from .validate import ValidateConfig, validate
    report = validate(ValidateConfig.load(args.config), args.input,
                      args.output)
    print(json.dumps({k: report.get(k) for k in ("result", "reason")}))
    return 0


def cmd_probe_campaign(args) -> int:
    from .campaign import CampaignConfig, probe_campaign
    report = probe_campaign(CampaignConfig.load(args.config), args.output)
    print(json.dumps({k: report.get(k) for k in ("result", "reason")}))
    # The report says the result; a nonzero exit is an infrastructure end
    # (stage1.campaigns).
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
        memory_mb=collector.memory_mb,
        cpus=collector.cpus_for(descriptor.sanitizer),
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
    g.add_argument("--gap", type=Path,
                   help="the Controller's GapContract for the gap a Harness "
                        "Generation patch set fills (#100)")
    g.add_argument("--base-spec", type=Path,
                   help="with --gap, the host spec the patch set started "
                        "from")
    c = sub.add_parser("collect")
    c.add_argument("--config", type=Path, required=True)
    c.add_argument("input", type=Path)
    c.add_argument("output", type=Path)
    v = sub.add_parser("validate")
    v.add_argument("--config", type=Path, required=True)
    v.add_argument("--resource", help="the KVM slot the validator holds")
    v.add_argument("input", type=Path)
    v.add_argument("output", type=Path)
    pc = sub.add_parser("probe-campaign")
    pc.add_argument("--config", type=Path, required=True,
                    help="a campaign.CampaignConfig")
    pc.add_argument("output", type=Path)
    for name in ("probe", "target-pcs", "check-pcs", "check-pins"):
        p = sub.add_parser(name)
        p.add_argument("--stage1", type=Path, required=True)
        p.add_argument("--collector", type=Path)
        if name not in ("target-pcs", "check-pins"):
            # target-pcs takes the job's own harness; check-pins checks all.
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
        elif name == "check-pcs":
            p.add_argument("--coverage", type=Path, required=True,
                           help="coverage.json or a cover_prog*.extra file")
            p.add_argument("--cache", type=Path)
    args = ap.parse_args(argv)
    return {"generate": cmd_generate, "collect": cmd_collect,
            "validate": cmd_validate, "probe-campaign": cmd_probe_campaign,
            "probe": cmd_probe, "target-pcs": cmd_target_pcs,
            "check-pcs": cmd_check_pcs,
            "check-pins": cmd_check_pins}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
