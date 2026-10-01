#!/usr/bin/env python3
"""Build the custom KCOV environment from an empty directory.

End-to-end: clone upstream kernel/syzkaller at pinned revisions, apply
the checked-in patch series, build bzImage + syzkaller binaries, bake a
manager-ready protocol image, and verify the lane status.

Only TARGET_DIR is written. Sources (patches, kernel config, seeds)
are read from the repository this script lives in; their revisions are
pinned in the manifest.

One patched kernel source tree serves every sanitizer variant. Each
--variant is built out of tree from its own pinned config
(kasan: bundle/patches/kernel.config; kcsan: bundle/patches/kernel-kcsan.config,
KASAN off, CONFIG_KCSAN=y); the default is both. stage_verify boots every
variant and records its mem_sanitizer.

TARGET_DIR layout:
  linux/                        patched kernel source tree (never built in)
  syzkaller/                    patched syzkaller tree, binaries in bin/
  build/<variant>/              out-of-tree kernel build (disposable)
  images/<variant>/bzImage      run-time kernel image
  images/<variant>/vmlinux      symbol source for coverage symbolization
  images/bookworm-kcov-fresh-vN.qcow2 (+ .json)   baked VM image, shared
  manifest.json

Usage (all paths explicit, no host defaults besides REPO auto-detect):
  bootstrap_kcov_env.py TARGET_DIR --kernel-repo URL --syz-repo URL \\
      --base-image FILE --ssh-key FILE --deps-tar FILE --minor 1|2 \\
      [--kernel-ref TAG|latest] [--variant kasan|kcsan ...] [--jobs N] \\
      [--skip-build] [--skip-verify]

  --skip-build rebuilds nothing: verifies prebuilt trees only.
  --skip-verify stops after the bake (no VM run).
"""
import argparse
import hashlib
import json
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
WORK = TOOLS.parent
BUNDLE = Path(os.environ.get("KOOV_BUNDLE", str(WORK / "bundle" / "patches")))
ABRUN = Path(os.environ.get("KOOV_ABRUNNER", str(WORK / "bundle" / "ab-runner")))
BAKER = Path(os.environ.get("KOOV_BAKER", str(WORK / "bundle" / "baker")))
FPORT_APPLY = TOOLS / "fport-apply.sh"
VARIANTS = ("kasan", "kcsan")
KCONFIGS = {"kasan": BUNDLE / "kernel.config",
            "kcsan": BUNDLE / "kernel-kcsan.config"}

sys.path.insert(0, str(TOOLS))
import kernel_base  # noqa: E402

# The last verified base lives in one file; --kernel-ref overrides the kernel part.
BASE = kernel_base.read_base(BUNDLE / "BASE")
KERNEL_URL_DEFAULT = kernel_base.KERNEL_URL
SYZ_URL_DEFAULT = "https://github.com/google/syzkaller.git"
KERNEL_TAG = BASE["kernel_tag"]
KERNEL_COMMIT = BASE["kernel_commit"]
SYZ_COMMIT = BASE["syzkaller_commit"]


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


SSH_AUTH_MARKERS = ("Permission denied", "Load key",
                    "Too many authentication failures")


def ssh_auth_failure(text):
    """An SSH key/auth rejection never heals by waiting for the guest."""
    return any(marker in text for marker in SSH_AUTH_MARKERS)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", type=Path)
    parser.add_argument("--kernel-repo", default=KERNEL_URL_DEFAULT)
    parser.add_argument("--kernel-ref", default=None,
                        help="kernel release/rc tag to build, or 'latest' (newest tag, rc "
                        "included); default: the BASE tag of the patch series")
    parser.add_argument("--syz-repo", default=SYZ_URL_DEFAULT)
    parser.add_argument("--base-image", type=Path, required=True,
                        help="clean raw base image (never opened RW)")
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--deps-tar", type=Path, required=True)
    parser.add_argument("--minor", choices=("1", "2"), required=True)
    parser.add_argument("--variant", action="append", choices=VARIANTS,
                        dest="variants",
                        help="sanitizer kernel to build and verify; repeat "
                        "for several (default: all)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-verify", action="store_true")
    parser.add_argument("--update", action="store_true",
                        help="write/update manifest.json after build")
    parser.add_argument("--boot-timeout", type=int, default=240)
    args = parser.parse_args(argv)
    if args.kernel_ref is None:
        args.kernel_ref = KERNEL_TAG
    elif args.kernel_ref == "latest":
        args.kernel_ref = kernel_base.latest_tag(args.kernel_repo)
        print("latest kernel tag: %s" % args.kernel_ref, flush=True)
    else:
        try:
            kernel_base.parse_tag(args.kernel_ref)
        except ValueError as error:
            parser.error(str(error))
    for field in ("base_image", "ssh_key", "deps_tar"):
        path = getattr(args, field).resolve()
        if path.exists() and not os.access(path, os.R_OK):
            parser.error("--%s is not readable by the current user: %s "
                         "(created with sudo? chown it to this user)"
                         % (field.replace("_", "-"), path))
    for field in ("base_image", "ssh_key", "deps_tar"):
        path = getattr(args, field).resolve()
        if not path.is_file() or path.stat().st_size == 0:
            parser.error("missing --%s: %s" % (field.replace("_", "-"), path))
        setattr(args, field, path)
    args.variants = [v for v in VARIANTS if v in (args.variants or VARIANTS)]
    for path in (FPORT_APPLY, *(KCONFIGS[v] for v in args.variants)):
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


def build_dir(args, variant):
    return args.target / "build" / variant


def image_dir(args, variant):
    return args.target / "images" / variant


def build_kernel_variant(args, linux, variant):
    """Build one sanitizer variant out of tree; the source tree stays clean."""
    out = build_dir(args, variant)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    (out / ".config").write_bytes(KCONFIGS[variant].read_bytes())
    run(["make", "-C", str(linux), "O=%s" % out, "olddefconfig"], timeout=600)
    run(["make", "-C", str(linux), "O=%s" % out, "-j%d" % args.jobs,
         "bzImage"], timeout=5400)


def export_kernel_images(args, variant):
    """Copy the run-time kernel artifacts out of the disposable build tree.

    The new images are staged next to the old ones and swapped in at the end, so a
    failed build never leaves images/<variant> half written or missing.
    """
    out = build_dir(args, variant)
    images = image_dir(args, variant)
    bzimage = out / "arch" / "x86" / "boot" / "bzImage"
    if not bzimage.is_file() or bzimage.stat().st_size == 0:
        raise RuntimeError("bzImage missing after %s build" % variant)
    staged = images.with_name(variant + ".new")
    previous = images.with_name(variant + ".old")
    for leftover in (staged, previous):
        if leftover.exists():
            shutil.rmtree(leftover)
    staged.mkdir(parents=True)
    shutil.copy2(bzimage, staged / "bzImage")
    vmlinux = out / "vmlinux"
    if vmlinux.is_file():
        shutil.copy2(vmlinux, staged / "vmlinux")
    if images.exists():
        os.replace(images, previous)
    os.replace(staged, images)
    if previous.exists():
        shutil.rmtree(previous)
    return images / "bzImage", images / "vmlinux"


def stage_kernel(args, manifest, reuse):
    linux = args.target / "linux"
    rebuilt = True
    base_commit = KERNEL_COMMIT if args.kernel_ref == KERNEL_TAG else None
    if (reuse and kernel_sentinel(linux) and all(
            (image_dir(args, v) / "bzImage").is_file()
            and (image_dir(args, v) / "bzImage").stat().st_size > 0
            for v in args.variants)):
        print("reusing kernel build", flush=True)
        rebuilt = False
    else:
        if linux.exists():
            shutil.rmtree(linux)
        for variant in args.variants:
            if build_dir(args, variant).exists():
                shutil.rmtree(build_dir(args, variant))
        run(["git", "clone", "--branch", args.kernel_ref, "--depth", "1",
             args.kernel_repo, str(linux)], timeout=1800)
        for key, value in (("user.email", "knfsd-fuzz@localhost"),
                           ("user.name", "knfsd-fuzz")):
            run(["git", "-C", str(linux), "config", key, value], timeout=60)
        head = subprocess.run(
            ["git", "-C", str(linux), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60,
            check=True).stdout.strip()
        if args.kernel_ref == KERNEL_TAG and head != KERNEL_COMMIT:
            raise RuntimeError("kernel base %s != %s" % (head, KERNEL_COMMIT))
        base_commit = head
        if not args.skip_build:
            if not git_clean(linux):
                raise RuntimeError("linux tree not clean")
            run([str(FPORT_APPLY), "kernel", str(linux)], timeout=600)
            for variant in args.variants:
                build_kernel_variant(args, linux, variant)
        for variant in args.variants:
            export_kernel_images(args, variant)
    kernels = {}
    variants = {}
    for variant in args.variants:
        bzimage = image_dir(args, variant) / "bzImage"
        vmlinux = image_dir(args, variant) / "vmlinux"
        kernels[variant] = (bzimage, vmlinux)
        variants[variant] = {
            "config_sha256": sha256(KCONFIGS[variant]),
            "bzImage_sha256": sha256(bzimage),
            "vmlinux_sha256": sha256(vmlinux) if vmlinux.is_file() else None,
        }
    manifest["kernel"] = {
        "ref": args.kernel_ref,
        "base": base_commit,
        "head": subprocess.run(
            ["git", "-C", str(linux), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=60,
            check=True).stdout.strip(),
        "variants": variants,
    }
    return kernels, rebuilt


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


def reusable_image(args, image_out):
    """The baked image's manifest when it was made from exactly today's inputs, else None.

    The image is booted with -kernel, so a new kernel alone never needs a re-bake;
    only a change of the base image, lane fixture, service, deps or NFS minor does.
    """
    meta_path = image_out.with_suffix(".json")
    if not (args.update and image_out.is_file() and meta_path.is_file()):
        return None
    try:
        meta = json.loads(meta_path.read_text())
    except ValueError:
        return None
    inputs = {
        "base_sha256": sha256(args.base_image),
        "nfs_minor": args.minor,
        "lane_script_sha256": sha256(ABRUN / "frozen_phase9_lane.sh"),
        "boot_fixture_sha256": sha256(ABRUN / "frozen_phase9_boot_fixture.sh"),
        "service_sha256": sha256(ABRUN / "frozen-phase9-fixture.service"),
        "deps_tar_sha256": sha256(args.deps_tar),
    }
    if any(meta.get(key) != value for key, value in inputs.items()):
        return None
    return meta if meta.get("sha256") == sha256(image_out) else None


def discard_staged_image(staging):
    """Remove a partial staged image and its manifest (the bake logs stay for diagnosis)."""
    for path in (staging, staging.with_suffix(".json")):
        path.unlink(missing_ok=True)


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
        last_error = ""
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("QEMU exited before SSH became ready")
            result = subprocess.run([*self.ssh, "true"], capture_output=True,
                                    text=True, timeout=8)
            if result.returncode == 0:
                return
            last_error = result.stderr.strip()
            if ssh_auth_failure(last_error):
                raise RuntimeError("guest SSH rejected the key (not a boot "
                                   "problem): %s" % last_error)
            time.sleep(3)
        raise RuntimeError("timed out waiting for guest SSH; last ssh "
                           "error: %s" % (last_error or "none"))

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


def stage_verify_variant(args, image, variant, bzimage):
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
        sanitizer = detect_mem_sanitizer(
            vm, build_dir(args, variant) / ".config")
        if sanitizer != variant:
            raise RuntimeError("variant %s booted a %s kernel"
                               % (variant, sanitizer))
        return {"fixture_root": root,
                "lane_count": int(json.loads(lanes)["lane_count"]),
                "mem_sanitizer": sanitizer,
                "target_kasan": sanitizer == "kasan",
                "target_kcsan": sanitizer == "kcsan"}
    finally:
        vm.stop()


def stage_verify(args, image, kernels):
    """Boot every variant with the shared image; all must pass."""
    variants = {variant: stage_verify_variant(args, image, variant,
                                              kernels[variant][0])
                for variant in args.variants}
    first = variants[args.variants[0]]
    return {"mode": "base", "fixture_root": first["fixture_root"],
            "lane_count": first["lane_count"], "variants": variants}


def main(argv=None):
    args = parse_args(argv)
    manifest = {"target": str(args.target), "minor": args.minor,
                "repo": str(BUNDLE.parent)}
    # SHA256-based reuse removed (Option A, 2026-09-27).
    kernel_reuse = False
    syz_reuse = False
    try:
        kernels, kernel_rebuilt = stage_kernel(args, manifest, kernel_reuse)
        syz = stage_syzkaller(args, manifest, syz_reuse)
        image_out = args.target / "images" / ("bookworm-kcov-fresh-v%s.qcow2"
                                              % args.minor)
        image_out.parent.mkdir(parents=True, exist_ok=True)
        reused = reusable_image(args, image_out)
        if reused is not None:
            print("reusing the baked image: its inputs are unchanged", flush=True)
            manifest["bake"] = {**reused, "reused": True}
        else:
            # The image is booted with -kernel, so it does not depend on the
            # sanitizer; bake it once with the first variant's kernel. The bake
            # writes a staging file that replaces the previous image only on success.
            boot_variant = args.variants[0]
            staging = image_out.with_name("staging-" + image_out.name)
            discard_staged_image(staging)
            try:
                stage_bake(args, kernels[boot_variant][0], staging)
            except BaseException:
                discard_staged_image(staging)
                raise
            meta_staging = staging.with_suffix(".json")
            meta = json.loads(meta_staging.read_text())
            meta["output"] = str(image_out)
            os.replace(staging, image_out)
            image_out.with_suffix(".json").write_text(json.dumps(meta, indent=2) + "\n")
            meta_staging.unlink()
            manifest["bake"] = {**meta, "boot_kernel_variant": boot_variant}
        if args.skip_verify:
            manifest["verify"] = "skipped"
        else:
            manifest["verify"] = stage_verify(args, image_out, kernels)
        manifest["status"] = "pass"
    except Exception as error:
        manifest["status"] = "fail"
        manifest["error"] = "%s: %s" % (type(error).__name__, error)
        raise
    finally:
        passed = manifest.get("status") == "pass"
        (args.target / ("manifest.json" if passed else "manifest.failed.json")).write_text(
            json.dumps(manifest, indent=2) + "\n")
        if passed:
            (args.target / "manifest.failed.json").unlink(missing_ok=True)
    print(json.dumps(manifest, indent=2)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
