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
    for minor in ("1", "2"):
        args = baker["parse_args"]([
            "--base-image", str(proxy), "--kernel", str(proxy), "--ssh-key", str(proxy),
            "--deps-tar", str(output), "--output", str(work / "image.qcow2"),
            "--minor", minor])
        assert args.lane_script == ROOT / "bundle/lane/lane.sh"
        assert args.boot_fixture == ROOT / "bundle/lane/boot-fixture.sh"
        assert args.service == ROOT / "bundle/lane/fixture.service"

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
for entry in manifest["programs"]:
    source = ROOT / "bundle/corpus/nfs-normal" / entry["path"]
    assert hashlib.sha256(source.read_bytes()).hexdigest() == entry["sha256"]
    assert (ROOT / entry["fixture_path"]).is_file()

print("PASS: lane deps assembly, preflight, and corpus paths/hashes")
