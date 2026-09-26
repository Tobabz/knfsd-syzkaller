#!/usr/bin/env python3
"""Build the custom KCOV environment from an empty directory.

End-to-end: clone upstream kernel/syzkaller at pinned revisions, apply
the checked-in patch series, build bzImage + syzkaller binaries, bake a
manager-ready protocol image, and verify the lane status.

Only TARGET_DIR is written. Sources (patches, kernel config, seeds)
are read from the repository this script lives in; their revisions are
pinned in the manifest.

Usage (all paths explicit, no host defaults besides REPO auto-detect):
  bootstrap_kcov_env.py TARGET_DIR --kernel-repo URL --syz-repo URL \\
      --base-image FILE --ssh-key FILE --deps-tar FILE --minor 1|2 \\
      [--jobs N] [--skip-build] [--skip-verify]

  For offline handoff, replace the two --*-repo URLs with
  --kernel-tarball/--syz-tarball pristine source archives; the trees
  are extracted, committed locally, and patched the same way (the
  base-hash check becomes a content check). See README-HANDOFF.

  --skip-build rebuilds nothing: verifies prebuilt trees only.
  --skip-verify stops after the bake (no VM run).
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
WORK = TOOLS.parent
BUNDLE = Path(os.environ.get("KOOV_BUNDLE", str(WORK / "bundle" / "patches")))
ABRUN = Path(os.environ.get("KOOV_ABRUNNER", str(WORK / "bundle" / "ab-runner")))
BAKER = Path(os.environ.get("KOOV_BAKER", str(WORK / "bundle" / "baker")))
FPORT_APPLY = TOOLS / "fport-apply.sh"
KCONFIG = BUNDLE / "kernel.config"

KERNEL_URL_DEFAULT = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
SYZ_URL_DEFAULT = "https://github.com/google/syzkaller.git"
KERNEL_TAG = "v7.3-rc4"
KERNEL_COMMIT = "93f51579e7df248780214094418f205253383cc5"
SYZ_COMMIT = "801f0966669a37e048adabf9e5f38ce52825ea82"


def run(command, timeout=3600, check=True, **kwargs):
    print("+ " + shlex.join(str(c) for c in command), flush=True)
    result = subprocess.run(command, timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError("command failed rc=%d: %s" % (
            result.returncode, shlex.join(str(c) for c in command)))
    return result


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--kernel-repo", default=KERNEL_URL_DEFAULT)
    parser.add_argument("--syz-repo", default=SYZ_URL_DEFAULT)
    parser.add_argument("--kernel-tarball", type=Path, default=None,
                        help="offline alternative to --kernel-repo: pristine "
                        "v7.3-rc4 source archive")
    parser.add_argument("--syz-tarball", type=Path, default=None,
                        help="offline alternative to --syz-repo: pristine "
                        "801f09666 source archive")
    parser.add_argument("--base-image", type=Path, required=True,
                        help="clean raw base image (never opened RW)")
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--minor", choices=("1", "2"), required=True)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--update", action="store_true",
                        help="reuse stages whose pins did not change; rebuild "
                        "only what the new pins invalidate")
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args(argv)
    for field in ("base_image", "ssh_key", "deps_tar"):
        path = getattr(args, field).resolve()
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing --%s: %s" % (field.replace("_", "-"), path))
        setattr(args, field, path)
    for path in (FPORT_APPLY, KCONFIG):
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("repo input missing: %s" % path)
    args.target = args.target.absolute()
    if args.target.exists():
        if not args.target.is_dir():
            parser.error("target is not a directory")
        if any(args.target.iterdir()) and not args.update:
            parser.error("target must be a new or empty directory "
                         "(or pass --update)")
    else:
        args.target.mkdir(parents=True)
    return args


def series_shas(bundle):
    bundle = Path(bundle)
    names = (bundle / "series").read_text(encoding="utf-8").split()
    return [sha256(bundle / name) for name in names]


def compute_pins(args):
    return {
        "kernel_base": KERNEL_COMMIT,
        "kernel_series": series_shas(BUNDLE / "kernel"),
        "kconfig": sha256(KCONFIG),
        "syz_base": SYZ_COMMIT,
        "syz_series": series_shas(BUNDLE / "syzkaller"),
        "lane_script": sha256(ABRUN / "frozen_phase9_lane.sh"),
        "service": sha256(ABRUN / "frozen-phase9-fixture.service"),
        "deps": sha256(args.deps_tar),
        "base_image": sha256(args.base_image),
        "minor": args.minor,
    }


def pins_match(old, new, *sections):
    if not isinstance(old, dict):
        return False
    old_pins, new_pins = old.get("pins"), new.get("pins")
    if not isinstance(old_pins, dict) or not isinstance(new_pins, dict):
        return False
    return all(old_pins.get(section) == new_pins.get(section)
               for section in sections)


def git_clean(tree):
    result = subprocess.run(["git", "-C", str(tree), "status", "--porcelain"],
                            capture_output=True, text=True, timeout=60)
    return result.returncode == 0 and result.stdout.strip() == ""


def kernel_sentinel(linux):
    try:
        return "TCP_SUNRPC_FUZZ" in (
            linux / "include" / "uapi" / "linux" / "tcp.h"
        ).read_text(errors="replace")
    except OSError:
        return False


def import_tarball(tarball, dest, kind):
    """Extract a pristine source archive and commit it as a local repo."""
    import tarfile
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:*") as archive:
        archive.extractall(dest)
    run(["git", "-C", str(dest), "init"], timeout=60)
    for key, value in (("user.email", "knfsd-fuzz@localhost"),
                       ("user.name", "knfsd-fuzz")):
        run(["git", "-C", str(dest), "config", key, value], timeout=60)
    if kind == "kernel":
        makefile = (dest / "Makefile").read_text(errors="replace")
        fields = dict(re.findall(r"^(VERSION|PATCHLEVEL|SUBLEVEL|EXTRAVERSION)\s*=\s*(\S+)",
                                 makefile, re.MULTILINE))
        if (fields.get("VERSION"), fields.get("PATCHLEVEL"),
                fields.get("SUBLEVEL"), fields.get("EXTRAVERSION")) != (
                "7", "3", "0", "-rc4"):
            raise RuntimeError("kernel tarball is not v7.3-rc4: %r" % fields)
    run(["git", "-C", str(dest), "add", "-A"], timeout=600)
    run(["git", "-C", str(dest), "commit", "-q", "-m",
         "pristine base import (%s)" % kind], timeout=600)


def stage_kernel(args, manifest, reuse):
    linux = args.target / "linux"
    bzimage = linux / "arch" / "x86" / "boot" / "bzImage"
    vmlinux = linux / "vmlinux"
    rebuilt = True
    if (reuse and bzimage.is_file() and bzimage.stat().st_size > 0
            and kernel_sentinel(linux)):
        print("reusing kernel build", flush=True)
        rebuilt = False
    else:
        if linux.exists():
            shutil.rmtree(linux)
        if args.kernel_tarball is not None:
            import_tarball(args.kernel_tarball, linux, "kernel")
        else:
            run(["git", "clone", "--branch", KERNEL_TAG, "--depth", "1",
                 args.kernel_repo, str(linux)], timeout=1800)
            for key, value in (("user.email", "knfsd-fuzz@localhost"),
                               ("user.name", "knfsd-fuzz")):
                run(["git", "-C", str(linux), "config", key, value],
                    timeout=60)
            head = subprocess.run(
                ["git", "-C", str(linux), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=60,
                check=True).stdout.strip()
            if head != KERNEL_COMMIT:
                raise RuntimeError("kernel base %s != %s"
                                   % (head, KERNEL_COMMIT))
        if not args.skip_build:
            if not git_clean(linux):
                raise RuntimeError("linux tree not clean")
            run([str(FPORT_APPLY), "kernel", str(linux)], timeout=600)
            (linux / ".config").write_bytes(KCONFIG.read_bytes())
            run(["make", "-C", str(linux), "olddefconfig"], timeout=600)
            run(["make", "-C", str(linux), "-j%d" % args.jobs, "bzImage"],
                timeout=5400)
        if not bzimage.is_file() or bzimage.stat().st_size == 0:
            raise RuntimeError("bzImage missing after build")
    manifest["kernel"] = {
        "base": KERNEL_COMMIT,
        "head": subprocess.run(
            ["git", "-C", str(linux), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60,
            check=True).stdout.strip(),
        "bzImage_sha256": sha256(bzimage),
        "vmlinux_sha256": sha256(vmlinux) if vmlinux.is_file() else None,
    }
    return bzimage, vmlinux, rebuilt


def syz_sentinel(syz):
    try:
        text = (syz / "sys" / "linux" / "socket_inet_nfs.txt").read_text(
            errors="replace")
    except OSError:
        return False
    return "syz_send_nfs_fuzz" in text


def syz_binaries_ok(syz):
    for relative in ("bin/syz-manager", "bin/linux_amd64/syz-executor",
                     "bin/linux_amd64/syz-execprog", "bin/syz-db"):
        path = syz / relative
        if not path.is_file() or path.stat().st_size == 0:
            return False
    return True


def stage_syzkaller(args, manifest, reuse):
    syz = args.target / "syzkaller"
    if reuse and syz_binaries_ok(syz) and syz_sentinel(syz):
        print("reusing syzkaller build", flush=True)
    else:
        if syz.exists():
            shutil.rmtree(syz)
        if args.syz_tarball is not None:
            import_tarball(args.syz_tarball, syz, "syzkaller")
        else:
            run(["git", "clone", args.syz_repo, str(syz)], timeout=3600)
            for key, value in (("user.email", "knfsd-fuzz@localhost"),
                               ("user.name", "knfsd-fuzz")):
                run(["git", "-C", str(syz), "config", key, value], timeout=60)
            subprocess.run(["git", "-C", str(syz), "fetch", "origin"],
                           timeout=900, check=True)
            run(["git", "-C", str(syz), "checkout", SYZ_COMMIT], timeout=300)
        if not args.skip_build:
            if not git_clean(syz):
                raise RuntimeError("syzkaller tree not clean")
            run([str(FPORT_APPLY), "syzkaller", str(syz)], timeout=600)
            run(["make", "-C", str(syz), "-j%d" % args.jobs], timeout=3600)
        if not syz_binaries_ok(syz):
            raise RuntimeError("missing build output after build")
    manifest["syzkaller"] = {
        "base": SYZ_COMMIT,
        "head": subprocess.run(
            ["git", "-C", str(syz), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60,
            check=True).stdout.strip(),
    }
    return syz


def stage_bake(args, bzimage, image_out):
    bake = BAKER / "bake_nfs_protocol_image.py"
    run([sys.executable, str(bake), "--base-image", str(args.base_image),
         "--output", str(image_out), "--minor", args.minor,
         "--kernel", str(bzimage), "--ssh-key", str(args.ssh_key),
         "--deps-tar", str(args.deps_tar),
         "--lane-script", str(ABRUN / "frozen_phase9_lane.sh"),
         "--boot-fixture", str(ABRUN / "frozen_phase9_boot_fixture.sh"),
         "--service", str(ABRUN / "frozen-phase9-fixture.service"),
         "--cpus", "4", "--memory", "4096",
         "--boot-timeout", str(args.boot_timeout)], timeout=3600)
    manifest_path = image_out.with_suffix(".json")
    return json.loads(manifest_path.read_text())


class VM:
    def __init__(self, image, kernel, ssh_key, boot_timeout):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.ssh_port = reservation.getsockname()[1]
        common = ["-F", "/dev/null", "-o", "UserKnownHostsFile=/dev/null",
                  "-o", "StrictHostKeyChecking=no", "-o", "IdentitiesOnly=yes",
                  "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                  "-o", "ConnectTimeout=5", "-i", str(ssh_key)]
        self.ssh = ["ssh", *common, "-p", str(self.ssh_port),
                    "root@127.0.0.1"]
        self.scp = ["scp", "-O", *common, "-P", str(self.ssh_port)]
        self.image, self.kernel = image, kernel
        self.boot_timeout = boot_timeout
        self.process = None

    def start(self):
        cmd = ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host",
               "-m", "4096", "-smp", "4", "-display", "none",
               "-serial", "none", "-no-reboot", "-snapshot",
               "-drive", "file=%s,format=qcow2,if=ide" % self.image,
               "-kernel", str(self.kernel),
               "-append", "root=/dev/sda console=ttyS0 nokaslr "
               "nfs.localio_enabled=N",
               "-device", "e1000,netdev=net0",
               "-netdev", "user,id=net0,restrict=on,"
               "hostfwd=tcp:127.0.0.1:%d-:22" % self.ssh_port]
        self.process = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + self.boot_timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("QEMU exited before SSH became ready")
            result = subprocess.run([*self.ssh, "true"], capture_output=True,
                                    text=True, timeout=8)
            if result.returncode == 0:
                return
            time.sleep(3)
        raise RuntimeError("timed out waiting for guest SSH")

    def guest(self, command, timeout=60):
        result = subprocess.run([*self.ssh, command], capture_output=True,
                                text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("guest rc=%d: %s\n%s" % (
                result.returncode, command, result.stderr[-1500:]))
        return result.stdout

    def put(self, source, destination):
        subprocess.run([*self.scp, str(source),
                        "root@127.0.0.1:" + destination],
                       capture_output=True, text=True, timeout=120,
                       check=True)

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)


def _config_option_on(text, name):
    return any(line == name + "=y" for line in text.splitlines())


def detect_mem_sanitizer(vm, config_path):
    """Return the compiled+active memory sanitizer: 'kasan' or 'kcsan'.

    Kconfig makes KCSAN depend on !KASAN, so the two are mutually exclusive:
    a normal build compiles at most one.  Both a build-level signal (.config)
    and a run-time signal from the booted kernel are required; the winner is
    recorded in the manifest.
    """
    cfg = Path(config_path)
    if not cfg.is_file():
        raise RuntimeError("kernel config missing: %s" % cfg)
    text = cfg.read_text()
    cfg_kasan = _config_option_on(text, "CONFIG_KASAN")
    cfg_kcsan = _config_option_on(text, "CONFIG_KCSAN")
    if cfg_kasan == cfg_kcsan:   # both on (impossible per Kconfig) or neither
        raise RuntimeError(
            "mem sanitizer not uniquely compiled in %s: kasan=%s kcsan=%s"
            % (cfg, cfg_kasan, cfg_kcsan))
    if cfg_kasan:
        ok = vm.guest(
            "dmesg 2>/dev/null | grep -q "
            "'KernelAddressSanitizer initialized' && echo yes || echo no",
            timeout=30).strip()
        if ok != "yes":
            raise RuntimeError(
                "KASAN=y in %s but boot log has no init banner" % cfg)
        return "kasan"
    ok = vm.guest(
        "grep -qE '(kcsan_setup_watchpoint|kcsan_report|"
        "kcsan_found_watchpoint|__kcsan_check_access)' "
        "/proc/kallsyms 2>/dev/null && echo yes || echo no",
        timeout=30).strip()
    if ok != "yes":
        raise RuntimeError(
            "KCSAN=y in %s but no KCSAN symbols in /proc/kallsyms" % cfg)
    return "kcsan"


def stage_verify(args, image, bzimage):
    vm = VM(image, bzimage, args.ssh_key, args.boot_timeout)
    try:
        vm.start()
        state = vm.guest("systemctl is-active frozen-phase9-fixture.service",
                         timeout=60).strip()
        if state != "active":
            raise RuntimeError("fixture service not active: %r" % state)
        root = vm.guest("ls -d /tmp/frozen-phase9.manager",
                        timeout=30).strip()
        lanes = vm.guest(
            "NFS_MINOR_VERSION=%s /opt/frozen-phase9/lane.sh status %s"
            % (args.minor, root), timeout=90)
        if int(json.loads(lanes).get("lane_count", 0)) < 1:
            raise RuntimeError("no lanes reported")
        sanitizer = detect_mem_sanitizer(vm,
                                         args.target / "linux" / ".config")
        return {"mode": "base", "fixture_root": root,
                "lane_count": int(json.loads(lanes)["lane_count"]),
                "mem_sanitizer": sanitizer,
                "target_kasan": sanitizer == "kasan",
                "target_kcsan": sanitizer == "kcsan"}
    finally:
        vm.stop()


def main(argv=None):
    args = parse_args(argv)
    pins = compute_pins(args)
    old_manifest = None
    if args.update:
        manifest_path = args.target / "manifest.json"
        if manifest_path.is_file():
            try:
                old_manifest = json.loads(manifest_path.read_text())
            except (OSError, json.JSONDecodeError):
                old_manifest = None
    manifest = {"target": str(args.target), "minor": args.minor,
                "repo": str(BUNDLE.parent), "pins": pins}
    kernel_reuse = (
        old_manifest is not None
        and pins_match(old_manifest, manifest, "kernel_base",
                       "kernel_series", "kconfig"))
    syz_reuse = (
        old_manifest is not None
        and pins_match(old_manifest, manifest, "syz_base", "syz_series"))
    try:
        bzimage, vmlinux, kernel_rebuilt = stage_kernel(
            args, manifest, kernel_reuse)
        syz = stage_syzkaller(args, manifest, syz_reuse)
        image_out = args.target / ("bookworm-kcov-fresh-v%s.qcow2"
                                   % args.minor)
        bake_manifest_path = image_out.with_suffix(".json")
        bake_reuse = (
            old_manifest is not None and not kernel_rebuilt
            and pins_match(old_manifest, manifest, "lane_script",
                           "service", "deps", "base_image", "minor")
            and image_out.is_file() and image_out.stat().st_size > 0
            and bake_manifest_path.is_file())
        if bake_reuse:
            print("reusing baked image", flush=True)
            manifest["bake"] = json.loads(bake_manifest_path.read_text())
        else:
            if image_out.exists():
                image_out.unlink()
            if bake_manifest_path.exists():
                bake_manifest_path.unlink()
            manifest["bake"] = stage_bake(args, bzimage, image_out)
        if args.skip_verify:
            manifest["verify"] = "skipped"
        else:
            manifest["verify"] = stage_verify(args, image_out, bzimage)
        manifest["status"] = "pass"
    except Exception as error:
        manifest["status"] = "fail"
        manifest["error"] = "%s: %s" % (type(error).__name__, error)
        raise
    finally:
        (args.target / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
