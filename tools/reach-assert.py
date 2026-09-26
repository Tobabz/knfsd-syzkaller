#!/usr/bin/env python3
"""Reach-corpus verdict: assert sentinel functions landed in the right
coverage slices, using the corpus manifest's sentinel table.

Attribution model (see manifest): fs/nfsd collects only under ON remote kcov
(on_only == on_union), net/sunrpc is split and the server-side continuation
must land in on_only, fs/nfs (client) collects in both modes so presence is
asserted on the on_union slice.

Usage:
  reach-assert.py --results DIR --vmlinux PATH --manifest PATH [--out PATH]
"""
import argparse
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NotRequired, TypeAlias, TypedDict

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from tools.reach_callback import CallbackVerdict, callback_witness

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
SentinelSpec = TypedDict("SentinelSpec", {
    "rule": str, "required": list[str], "observed": list[str],
    "absent-on-only": NotRequired[list[str]],
})
class CallbackSpec(TypedDict):
    rule: str
    required: list[str]
    trace_file: str
    copies_per_execution: int
    completion_before_seconds: float

class ReachManifest(TypedDict):
    corpus: str
    kind: NotRequired[str]
    prog_sha256: str
    sentinel: dict[str, SentinelSpec]
    ownerless_callback: NotRequired[CallbackSpec]

class Presence(TypedDict):
    on_union: bool
    on_only: bool
    off_union: bool

Assertion = TypedDict("Assertion", {"assert": bool, "on_union": bool, "on_only": bool, "off_union": bool})
ModuleVerdict = TypedDict("ModuleVerdict", {
    "rule": str, "required": dict[str, Assertion], "observed": dict[str, Presence],
    "absent-on-only": dict[str, Assertion], "pcs": dict[str, int],
})
class PhysicalVerdict(TypedDict):
    rule: str
    paired_run: bool
    required: dict[str, dict[str, CallbackVerdict]]

class ReachVerdict(TypedDict):
    corpus: str
    kind: str | None
    prog_sha256: str
    modules: dict[str, ModuleVerdict]
    overall: str
    ownerless_callback: NotRequired[PhysicalVerdict]

class Arguments(argparse.Namespace):
    results: Path | None = None
    vmlinux: Path | None = None
    manifest: Path | None = None
    out: Path | None = None

MODULE_STEM = {
    "fs/nfsd": "fs_nfsd",
    "net/sunrpc": "net_sunrpc",
    "fs/nfs": "fs_nfs",
}


def paired_controls(path: Path, decode: Callable[[str], JsonValue] = json.loads) -> tuple[bool, int, int]:
    """Parse run controls at the JSON boundary; missing/invalid evidence fails."""
    if not path.is_file():
        return False, 0, 0
    document = decode(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        return False, 0, 0
    controls = document.get("controls")
    if not isinstance(controls, dict):
        return False, 0, 0
    trials = controls.get("trials_per_mode")
    executions = controls.get("executions_per_trial")
    if not isinstance(trials, int) or not isinstance(executions, int):
        return False, 0, 0
    paired = (document.get("status") == "collected" and controls.get("selected_mode") == "both"
              and trials > 0 and executions > 0)
    return paired, trials, executions


def symbolize(vmlinux: str, pcs: list[str]) -> set[str]:
    """Map kernel PCs to function names via addr2line (batch)."""
    if not pcs:
        return set()
    out = subprocess.run(
        ["addr2line", "-e", vmlinux, "-f", "-C"] + pcs,
        capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    names: set[str] = set()
    for i in range(0, len(lines), 2):
        name = lines[i].strip()
        if not name or name == "??":
            continue
        # Accept .cold partitions as the same function; never __pfx_ (ftrace
        # prefix has its own symbol and does not constitute body coverage).
        name = re.sub(r"\.cold$", "", name)
        if name.startswith("__pfx_"):
            continue
        names.add(name)
    return names


def load_set(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {line.strip() for line in path.read_text().splitlines() if line.strip()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--vmlinux", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(namespace=Arguments())
    if args.results is None or args.vmlinux is None or args.manifest is None:
        ap.error("results, vmlinux and manifest are required")

    manifest: ReachManifest = json.loads(args.manifest.read_text())
    corpus = manifest["corpus"]
    sentinel = manifest["sentinel"]
    cov = args.results / "coverage_sets"
    if not cov.is_dir():
        print(f"error: no coverage_sets/ under {args.results}", file=sys.stderr)
        return 2

    verdict: ReachVerdict = {
        "corpus": corpus,
        "kind": manifest.get("kind"),
        "prog_sha256": manifest["prog_sha256"],
        "modules": {},
        "overall": "PASS",
    }
    ok = True
    for module, spec in sentinel.items():
        stem = MODULE_STEM.get(module)
        if not stem:
            print(f"error: no coverage stem for module {module}", file=sys.stderr)
            return 2
        on_union = load_set(cov / f"{stem}_on_union.pcs")
        on_only = load_set(cov / f"{stem}_on_only.pcs")
        off_union = load_set(cov / f"{stem}_off_union.pcs")
        synth = {
            "on_union": symbolize(str(args.vmlinux), sorted(on_union)),
            "on_only": symbolize(str(args.vmlinux), sorted(on_only)),
            "off_union": symbolize(str(args.vmlinux), sorted(off_union)),
        }
        rule = spec["rule"]
        pool = {"on-only": "on_only", "on-union": "on_union"}[rule]
        mod: ModuleVerdict = {"rule": rule, "required": {}, "observed": {}, "absent-on-only": {}, "pcs": {
            "on_union": len(on_union), "on_only": len(on_only),
            "off_union": len(off_union)}}
        for name in spec.get("required", []):
            hit = name in synth[pool]
            mod["required"][name] = {
                "assert": hit,
                "on_union": name in synth["on_union"],
                "on_only": name in synth["on_only"],
                "off_union": name in synth["off_union"],
            }
            if not hit:
                ok = False
        for name in spec.get("observed", []):
            mod["observed"][name] = {
                "on_union": name in synth["on_union"],
                "on_only": name in synth["on_only"],
                "off_union": name in synth["off_union"],
            }
        for name in spec.get("absent-on-only", []):
            absent = name not in synth["on_only"]
            mod["absent-on-only"][name] = {
                "assert": absent, "on_union": name in synth["on_union"],
                "on_only": name in synth["on_only"], "off_union": name in synth["off_union"],
            }
            ok = absent and ok
        verdict["modules"][module] = mod
        status = "PASS" if all(
            v["assert"] for v in (*mod["required"].values(), *mod["absent-on-only"].values())) else "FAIL"
        print(f"[{status}] {module} (rule={rule})")
        for name, v in mod["required"].items():
            print(f"    req {name:<40} "
                  f"on_union={v['on_union']} on_only={v['on_only']} "
                  f"off_union={v['off_union']} => asserted={v['assert']}")
        for name, observation in mod["observed"].items():
            print(f"    obs {name:<40} "
                  f"on_union={observation['on_union']} on_only={observation['on_only']} "
                  f"off_union={observation['off_union']}")
        for name, absence in mod["absent-on-only"].items():
            print(f"    absent-on-only {name}: on_only={absence['on_only']} => asserted={absence['assert']}")

    if "ownerless_callback" in manifest:
        callback_spec = manifest["ownerless_callback"]
        if (callback_spec["rule"] != "trace-both"
                or callback_spec["required"] != ["nfsd4_run_cb_work"]):
            print("error: unsupported ownerless callback contract", file=sys.stderr)
            return 2
        paired, trials, executions = paired_controls(args.results / "experiment_manifest.json")
        physical: PhysicalVerdict = {"rule": callback_spec["rule"], "paired_run": paired,
                                    "required": {name: {} for name in callback_spec["required"]}}
        for mode in ("off", "on"):
            for trial in range(1, trials + 1):
                directory = f"remote_{mode}/trial_{trial:02d}"
                result = callback_witness(
                    args.results / directory / callback_spec["trace_file"],
                    executions * callback_spec["copies_per_execution"],
                    callback_spec["completion_before_seconds"])
                physical["required"]["nfsd4_run_cb_work"][directory] = result
                status = "PASS" if result["assert"] else "FAIL"
                print(f"[{status}] ownerless nfsd4_run_cb_work {directory}: {result['matched_copies']}/{result['expected_copies']} delivered")
                ok = result["assert"] and ok
        verdict["ownerless_callback"] = physical
        ok = paired and ok
    verdict["overall"] = "PASS" if ok else "FAIL"
    out = args.out or (args.results / f"reach_verdict_{corpus}.json")
    _ = out.write_text(json.dumps(verdict, indent=2) + "\n")
    print(f"overall: {verdict['overall']}  -> {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
