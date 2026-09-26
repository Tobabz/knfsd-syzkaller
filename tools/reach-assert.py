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
from pathlib import Path

MODULE_STEM = {
    "fs/nfsd": "fs_nfsd",
    "net/sunrpc": "net_sunrpc",
    "fs/nfs": "fs_nfs",
}


def symbolize(vmlinux: str, pcs: list[str]) -> set[str]:
    """Map kernel PCs to function names via addr2line (batch)."""
    if not pcs:
        return set()
    out = subprocess.run(
        ["addr2line", "-e", vmlinux, "-f", "-C"] + pcs,
        capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    names = set()
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
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    corpus = manifest["corpus"]
    sentinel = manifest["sentinel"]
    cov = args.results / "coverage_sets"
    if not cov.is_dir():
        print(f"error: no coverage_sets/ under {args.results}", file=sys.stderr)
        return 2

    verdict = {
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
        mod = {"rule": rule, "required": {}, "observed": {}, "pcs": {
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
        verdict["modules"][module] = mod
        status = "PASS" if all(
            v["assert"] for v in mod["required"].values()) else "FAIL"
        print(f"[{status}] {module} (rule={rule})")
        for name, v in mod["required"].items():
            print(f"    req {name:<40} "
                  f"on_union={v['on_union']} on_only={v['on_only']} "
                  f"off_union={v['off_union']} => asserted={v['assert']}")
        for name, v in mod["observed"].items():
            print(f"    obs {name:<40} "
                  f"on_union={v['on_union']} on_only={v['on_only']} "
                  f"off_union={v['off_union']}")

    verdict["overall"] = "PASS" if ok else "FAIL"
    out = args.out or (args.results / f"reach_verdict_{corpus}.json")
    out.write_text(json.dumps(verdict, indent=2) + "\n")
    print(f"overall: {verdict['overall']}  -> {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())