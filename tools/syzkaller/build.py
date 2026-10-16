#!/usr/bin/env python3
"""Build an independently reviewable bridge bundle from BASE + exact series.

Requires the repository's Python dependencies and the pinned Go toolchain.
The supplied local git source is read-only. Every mutation is in --output.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from agent_pipeline.admission import (  # noqa: E402
    BuildFile, SyzkallerBuildManifest, SyzkallerCallTable, SyzkallerTargetIdentity,
)
from agent_pipeline.admission_generation import (  # noqa: E402
    PinnedSyzkallerInputs, inspect_pinned_syzkaller,
)
from agent_pipeline.data import canonical_json, parse_json  # noqa: E402
from agent_pipeline.syzkaller import PinnedSyzParser  # noqa: E402


def run(args, *, cwd, env=None, capture=False):
    return subprocess.run(args, cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None,
                          timeout=1800).stdout


def git(checkout: Path, *args: str) -> str:
    return run(["git", *args], cwd=checkout, capture=True).decode().strip()


def build(source: Path, output: Path, go: str) -> Path:
    # Refuse reuse rather than trusting old generated code or silently changing
    # an existing authority bundle. A failed build can be inspected in place.
    output.mkdir(parents=True, exist_ok=False)
    source = source.resolve(strict=True)
    base = dict(line.split("=", 1) for line in
                (ROOT / "bundle/patches/BASE").read_text().splitlines()
                if line and not line.startswith("#"))["syzkaller_commit"]
    series = ROOT / "bundle/patches/syzkaller"
    names = [line for line in (series / "series").read_text().splitlines()
             if line and not line.startswith("#")]
    if names != sorted(p.name for p in series.glob("*.patch")):
        raise ValueError("series and patch filename ordering disagree")
    patch_bytes = b"".join(name.encode() + b"\0" + (series / name).read_bytes() + b"\0"
                           for name in names)
    patch_digest = hashlib.sha256(patch_bytes).hexdigest()
    checkout = output / "checkout"
    run(["git", "clone", "--shared", "--no-checkout", str(source), str(checkout)], cwd=output)
    run(["git", "checkout", "--detach", base], cwd=checkout)
    for name in names:
        # Stable committer identity/date: same base+patch bytes yield the same
        # applied commit, independently of the developer's git configuration.
        run(["git", "-c", "user.name=knfsd bridge builder",
             "-c", "user.email=bridge@localhost", "am", "--committer-date-is-author-date",
             str(series / name)], cwd=checkout)
    commit = git(checkout, "rev-parse", "HEAD")
    tree = git(checkout, "rev-parse", "HEAD^{tree}")
    env = {**os.environ, "GOCACHE": str(output / "go-cache"),
           "CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOFLAGS": "",
           "GOWORK": "off", "GOOS": "linux", "GOARCH": "amd64"}
    # Select an explicit go executable. Go 1.23's automatic toolchain download
    # is not silently accepted as build provenance.
    go = shutil.which(go) or go
    version = run([go, "version"], cwd=checkout, env=env, capture=True).decode().strip()
    if " go1.26.0 " not in version:
        raise ValueError("this pin requires Go 1.26.0; supply --go")
    run([go, "run", "./sys/syz-sysgen"], cwd=checkout, env=env)
    bundle = output / "bundle"
    bundle.mkdir()
    files = [ROOT / "tools/syzkaller/bridge.go", ROOT / "tools/syzkaller/facts.go"]
    flags = (f"-s -w -X main.sourceCommit={commit} -X main.patchDigest={patch_digest} "
             f"-X main.sourceTree={tree}")
    run([go, "build", "-trimpath", "-buildvcs=false", "-ldflags", flags,
         "-o", str(bundle / "bridge"), *map(str, files)], cwd=checkout, env=env)
    tests = sorted((ROOT / "tools/syzkaller").glob("*_test.go"))
    run([go, "test", "-count=1", "-ldflags", flags, *map(str, files + tests)], cwd=checkout, env=env)
    shutil.copyfile(checkout / "sys/gen/linux_amd64.gob.flate", bundle / "target.gob.flate")
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(checkout / name, bundle / name)
    provenance = {
        "schema_version": "knfsd-syz-build.v1", "upstream_commit": base,
        "source_commit": commit, "source_tree": tree, "go_version": version,
        "target": "linux/amd64", "patch_series_sha256": patch_digest,
        "bridge_sources": {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in files},
    }
    (bundle / "provenance.json").write_bytes(canonical_json(provenance))
    # Export from this executable, not from descriptions or hand-written names.
    response = parse_json(run([str(bundle / "bridge"), "export"], cwd=bundle, capture=True))
    table = SyzkallerCallTable.model_validate_json(canonical_json(response["call_table"]))
    manifest = SyzkallerBuildManifest(
        syzkaller_commit=commit, patch_series_sha256=patch_digest, target="linux/amd64",
        files=tuple(BuildFile(path=p.name, artifact_ref=hashlib.sha256(p.read_bytes()).hexdigest())
                    for p in sorted(bundle.iterdir())),
    )
    (bundle / "build-manifest.json").write_bytes(canonical_json(manifest))
    (bundle / "call-table.json").write_bytes(canonical_json(table))
    (bundle / "patch-series.bin").write_bytes(patch_bytes)
    identity = SyzkallerTargetIdentity(
        syzkaller_commit=commit, patch_series_sha256=patch_digest,
        build_manifest_sha256=hashlib.sha256(canonical_json(manifest)).hexdigest(),
        call_table_sha256=hashlib.sha256(canonical_json(table)).hexdigest(), target="linux/amd64")
    (bundle / "identity.json").write_bytes(canonical_json(identity))
    inspected = inspect_pinned_syzkaller(PinnedSyzkallerInputs(
        checkout=checkout, expected_commit=commit, patch_series=bundle / "patch-series.bin",
        build_root=bundle, build_manifest=bundle / "build-manifest.json",
        call_table=bundle / "call-table.json", target="linux/amd64"))
    if inspected.identity != identity:
        raise ValueError("admission generator identity disagreement")
    with PinnedSyzParser(bundle, identity=identity) as parser:
        parser.parse(b"getpid()\n", identity=identity)
    return bundle


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="local git repository containing BASE commit")
    parser.add_argument("--output", type=Path, required=True, help="new output directory")
    parser.add_argument("--go", default="go", help="Go 1.26.0 executable")
    args = parser.parse_args()
    print(build(args.source, args.output.absolute(), args.go))


if __name__ == "__main__":
    main()
