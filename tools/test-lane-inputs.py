#!/usr/bin/env python3
"""Check lane dependency assembly and default bake inputs without booting a VM."""
import argparse
import contextlib
import hashlib
import json
import io
import runpy
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
assemble = ROOT / "tools/assemble-guest-deps.py"
bootstrap = runpy.run_path(str(ROOT / "tools/bootstrap-kcov-env.py"))
baker = runpy.run_path(str(ROOT / "bundle/baker/bake_nfs_protocol_image.py"))

with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    deps, proxy, output = (work / name for name in ("deps.tar.gz", "proxy", "lane.tar.gz"))
    proxy.write_bytes(b"\x7fELFtest")
    with tarfile.open(deps, "w:gz") as archive:
        for name in ("./usr/sbin/ganesha.nfsd", "usr/sbin/rpc.nfsd"):
            member = tarfile.TarInfo(name)
            member.size, member.mode = 4, 0o755
            archive.addfile(member, io.BytesIO(b"test"))
        link = tarfile.TarInfo("./usr/lib/libtest.so")
        link.type, link.linkname = tarfile.SYMTYPE, "libtest.so.1"
        archive.addfile(link)

    # Incomplete deps must be rejected before bootstrap starts.
    with contextlib.redirect_stderr(io.StringIO()) as errors:
        try:
            bootstrap["check_lane_deps"](argparse.ArgumentParser(), deps)
        except SystemExit as error:
            assert error.code == 2 and "usr/sbin/nfs-proxy" in errors.getvalue()
        else:
            raise AssertionError("incomplete lane deps accepted")

    command = [sys.executable, str(assemble), "--ganesha-deps", str(deps),
               "--proxy", str(proxy), "--out", str(output)]
    subprocess.run(command, check=True, capture_output=True)
    bootstrap["check_lane_deps"](argparse.ArgumentParser(), output)
    with tarfile.open(output) as archive:
        assert archive.extractfile("./usr/sbin/nfs-proxy").read() == proxy.read_bytes()
        assert archive.getmember("./usr/sbin/nfs-proxy").mode == 0o755
        assert archive.extractfile("usr/sbin/rpc.nfsd").read() == b"test"
        assert archive.getmember("./usr/lib/libtest.so").issym()
        assert archive.getmember("./usr/lib/libtest.so").linkname == "libtest.so.1"
    before = output.read_bytes()
    retry = subprocess.run(command, capture_output=True)
    assert retry.returncode == 2 and b"already exists" in retry.stderr
    assert output.read_bytes() == before

    # Parsing must find all three moved lane files without explicit overrides.
    for version in ("3", "4.0", "4.1", "4.2"):
        args = baker["parse_args"]([
            "--base-image", str(proxy), "--kernel", str(proxy), "--ssh-key", str(proxy),
            "--deps-tar", str(output), "--output", str(work / "image.qcow2"),
            "--version", version])
        assert args.version == version
        assert args.lane_script == ROOT / "bundle/lane/lane.sh"
        assert args.boot_fixture == ROOT / "bundle/lane/boot-fixture.sh"
        assert args.service == ROOT / "bundle/lane/fixture.service"

    manager = work / "manager.cfg"
    live = work / "manager-live.cfg"
    manager.write_text(json.dumps({"type": "qemu", "workdir": str(work / "workdir"),
                                   "vm": {"cmdline": "nfs.localio_enabled=N"}}))
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(live), "--version", "3", "--image", str(proxy)],
                   check=True,
                   capture_output=True)
    prepared = json.loads(live.read_text())
    lane_bytes = (ROOT / "bundle/lane/lane.sh").read_bytes()
    lane_sha = hashlib.sha256(lane_bytes).hexdigest()
    assert (Path(prepared["workdir_template"]) / "lane.sh").read_bytes() == lane_bytes
    assert "path={{TEMPLATE}}" in prepared["vm"]["qemu_args"]
    assert "-snapshot" in prepared["vm"]["qemu_args"].split()
    assert "koov.nfs_version=3" in prepared["vm"]["cmdline"]
    assert "koov.lane_sha256=" + lane_sha in prepared["vm"]["cmdline"]
    assert prepared["image"] == str(proxy.resolve())

    broad = work / "manager-broad.cfg"
    subprocess.run([sys.executable, str(ROOT / "tools/prepare-live-lane-config.py"),
                    str(manager), str(broad), "--broad-knfsd", "--image", str(proxy)],
                   check=True, capture_output=True)
    broad_prepared = json.loads(broad.read_text())
    assert "koov.nfs_fixture=broad-knfsd" in broad_prepared["vm"]["cmdline"]
    assert "koov.nfs_version=" not in broad_prepared["vm"]["cmdline"]
    assert "koov.lane_sha256=" + lane_sha in broad_prepared["vm"]["cmdline"]
    assert "-snapshot" in broad_prepared["vm"]["qemu_args"].split()

# --skip-build must fail before deleting an incomplete existing checkout.
with tempfile.TemporaryDirectory() as directory:
    work = Path(directory)
    for tree in ("linux", "syzkaller"):
        checkout = work / tree
        checkout.mkdir()
        marker = checkout / "keep"
        marker.write_text("existing data")
        args = argparse.Namespace(target=work, kernel_ref=bootstrap["KERNEL_TAG"],
                                  variants=["kasan"], skip_build=True)
        stage = bootstrap["stage_kernel"] if tree == "linux" else bootstrap["stage_syzkaller"]
        try:
            stage(args, {}, True)
        except RuntimeError as error:
            assert "--skip-build" in str(error)
        else:
            raise AssertionError(f"{tree}: incomplete checkout was accepted")
        assert marker.read_text() == "existing data"

manifest = json.loads((ROOT / "bundle/corpus/nfs-normal/manifest.json").read_text())
assert manifest["schema"] == 3
assert manifest["purpose"] == "mutation_seed"
programs = {entry["path"]: entry for entry in manifest["programs"]}
assert len(programs) == len(manifest["programs"]) == 12
for entry in manifest["programs"]:
    source = ROOT / "bundle/corpus/nfs-normal" / entry["path"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["sha256"]
    assert sum(bool(line.strip()) for line in source.read_text().splitlines()) == entry["calls"]
    assert entry["native_profile"] in manifest["profiles"]
    assert entry["backend"] == manifest["profiles"][entry["native_profile"]]["backend"]
    assert entry["native_version"] == manifest["profiles"][entry["native_profile"]]["native_version"]
    if entry["path"] != "nfs3-create-retry-tcp.prog":
        assert "syz_open_nfs_lane_profile$" in source.read_text()

listed = []
for name, profile in manifest["profiles"].items():
    for path in profile["programs"]:
        assert path in programs
        assert programs[path]["native_profile"] == name
        listed.append(path)
assert sorted(listed) == sorted(programs)
broad_profiles = manifest["experimental_fixtures"]["broad-knfsd"]["profiles"]
assert broad_profiles == ["knfsd-v3", "knfsd-v40", "knfsd-v41", "knfsd-v42"]
assert manifest["experimental_fixtures"]["broad-knfsd"]["automatic_promotion"] is False
assert "ganesha-v41" not in broad_profiles

builder = runpy.run_path(str(ROOT / "tools/build-normal-corpus.py"))
selected, description = builder["select_programs"](
    argparse.ArgumentParser(), manifest, programs, None, "broad-knfsd")
assert len(selected) == 11
assert description["profiles"] == broad_profiles
assert "basic-v41-ganesha-tcp.prog" not in selected

print("PASS: lane deps, fixture modes, and profile-aware mutation corpus")
