#!/usr/bin/env python3
"""A/B the same four-route syzkaller RPC program with scoped arms off/on.

Each trial gets a fresh snapshot VM, ASan Ganesha and the same fixture. The
ON group adds only the two ACKed C2S/S2C arm rules and their FD closes. This
measures this relay's treatment, not Ganesha's unavailable remote .extra.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys
from datetime import datetime, timezone


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


def stamp():
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--proxy-binary", type=Path, required=True)
    parser.add_argument("--syz-executor", type=Path, required=True)
    parser.add_argument("--syz-execprog", type=Path, required=True)
    parser.add_argument("--lane-fixture", type=Path, default=ROOT / "tools/ganesha-lane.sh")
    parser.add_argument("--four-mount-script", type=Path,
                        default=HERE / "test/guest-four-mounts.sh")
    parser.add_argument("--off-workload", type=Path,
                        default=HERE / "test/guest-syzkaller-four.prog")
    parser.add_argument("--on-workload", type=Path,
                        default=HERE / "test/guest-syzkaller-mutate.prog")
    parser.add_argument("--asan-options", default="detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=stderr")
    parser.add_argument("--executions", type=int, default=30)
    parser.add_argument("--trials", type=int, default=2)
    args = parser.parse_args()
    if args.executions != 30 or args.trials != 2:
        parser.error("this formal gate requires --executions 30 --trials 2")
    args.output = args.output.resolve()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must be a fresh path")
    names = ("kernel", "image", "ssh_key", "deps_tar", "proxy_binary",
             "syz_executor", "syz_execprog", "lane_fixture",
             "four_mount_script", "off_workload", "on_workload")
    inputs = {}
    for name in names:
        path = getattr(args, name).resolve()
        if not path.is_file() or not path.stat().st_size:
            parser.error("missing --%s: %s" % (name.replace("_", "-"), path))
        setattr(args, name, path)
        inputs[name] = {"path": str(path), "sha256": digest(path)}
    args.output.mkdir(parents=True)
    report = {"schema": 1, "status": "running", "started_at": stamp(),
              "experiment": "ganesha-asan-four-route-arm-off-on",
              "controls": {"executions_per_trial": 30, "trials_per_group": 2,
                           "clients": 2, "backends": 2, "nfs_minor": 1,
                           "ASan": args.asan_options, "remote_cover": True,
                           "only_intended_difference": "two syzkaller arm calls and their FD closes"},
              "inputs": inputs, "trial_order": []}
    path = args.output / "experiment_manifest.json"
    save(path, report)
    # ABBA balances trial order without pretending two trials establish a
    # confidence interval. Both groups have identical RPCs and mount I/O.
    for mode, trial in (("off", 1), ("on", 1), ("on", 2), ("off", 2)):
        relative = "%s/trial_%02d" % (mode, trial)
        print("starting %s" % relative, flush=True)
        command = [sys.executable, str(HERE / "run-ganesha-asan-relay-smoke.py")]
        for name in ("kernel", "image", "ssh_key", "deps_tar", "proxy_binary",
                     "syz_executor", "syz_execprog", "lane_fixture", "four_mount_script"):
            command += ["--" + name.replace("_", "-"), str(getattr(args, name))]
        command += ["--workload", str(args.on_workload if mode == "on" else
                                      args.off_workload),
                    "--output", str(args.output / relative),
                    "--asan-options", args.asan_options,
                    "--executions", str(args.executions)]
        item = {"mode": mode, "trial": trial, "directory": relative,
                "status": "running"}
        report["trial_order"].append(item)
        save(path, report)
        result = subprocess.run(command, check=False)
        trial_path = args.output / relative / "trial_evidence.json"
        if not trial_path.exists():
            item["status"] = "fail"
            report["status"] = "fail"
            save(path, report)
            raise RuntimeError("trial wrote no evidence: " + relative)
        evidence = json.loads(trial_path.read_text(encoding="utf-8"))
        item["status"] = evidence["status"]
        item["duration_seconds"] = evidence.get("executor_four_routes", {}).get(
            "duration_seconds")
        item["evidence_sha256"] = digest(trial_path)
        save(path, report)
        if result.returncode or item["status"] != "pass" or not item["duration_seconds"]:
            report["status"] = "fail"
            save(path, report)
            raise RuntimeError("trial failed: " + relative)
        if mode == "on" and evidence.get("delta_total") != 60:
            report["status"] = "fail"
            save(path, report)
            raise RuntimeError("mutation trial lacks 60 durable deltas: " + relative)
        print("passed %s, executor %.3fs" % (relative, item["duration_seconds"]),
              flush=True)
    rates = {}
    for mode in ("off", "on"):
        rates[mode] = [30 / item["duration_seconds"] for item in
                       report["trial_order"] if item["mode"] == mode]
    off = statistics.median(rates["off"])
    on = statistics.median(rates["on"])
    report["results"] = {"exec_per_second": rates,
                         "median_off": off, "median_on": on,
                         "on_vs_off_percent": (on / off - 1) * 100}
    report["status"] = "pass"
    report["completed_at"] = stamp()
    save(path, report)
    print("PASS: 30 executions × 2 trials/group; arm ON vs OFF %.2f%% exec/s" %
          report["results"]["on_vs_off_percent"])


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("four-route arm A/B failed: %s" % error, file=sys.stderr)
        sys.exit(1)
