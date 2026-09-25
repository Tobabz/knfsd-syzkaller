#!/usr/bin/env python3
"""Fail-fast host prerequisite check for porting knfsd-fuzz elsewhere.

Checks: KVM, QEMU, Go, gcc, disk space, Debian package network reach,
repo layout markers. Exit 0 when the host can build + run; exit 2 with
a missing-item list otherwise. Override paths via environment:
REPO_ROOT, SYZ_TREE, QEMU_BIN.
"""
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

REPO = Path(os.environ.get("REPO_ROOT", Path(__file__).resolve().parent.parent))
SYZ = Path(os.environ.get("SYZ_TREE",
                          "/home/fuzzer/tools/syzkaller-frozen-attribution"))
QEMU = os.environ.get("QEMU_BIN", "qemu-system-x86_64")


def check(label, ok, detail=""):
    print(("OK   " if ok else "MISS ") + label + (f" ({detail})" if detail else ""))
    return ok


def main():
    missing = []

    def require(label, ok, detail=""):
        if not check(label, ok, detail):
            missing.append(label)

    require("repo layout", (REPO / "scripts").is_dir()
            and (REPO / "config").is_dir(), str(REPO))
    require("syzkaller tree", (SYZ / "Makefile").is_file()
            and (SYZ / "sys" / "linux" / "socket_inet_nfs.txt").is_file(),
            str(SYZ))
    require("/dev/kvm", Path("/dev/kvm").exists())
    qemu = shutil.which(QEMU)
    require("qemu", qemu is not None, qemu or QEMU)
    if qemu:
        try:
            out = subprocess.run([qemu, "--version"], capture_output=True,
                                 text=True, timeout=30).stdout.splitlines()
            check("qemu version", True, out[0] if out else "?")
        except (OSError, subprocess.SubprocessError):
            require("qemu runnable", False)
    go = shutil.which("go")
    require("go toolchain", go is not None, go or "")
    require("gcc", shutil.which("gcc") is not None)
    require("qemu-img", shutil.which("qemu-img") is not None)
    require("ssh/scp", shutil.which("ssh") is not None
            and shutil.which("scp") is not None)
    require("addr2line", shutil.which("addr2line") is not None)
    try:
        st = os.statvfs("/tmp")
        free_gb = st.f_bavail * st.f_frsize / 1e9
        require("/tmp >= 20GB", free_gb >= 20, f"{free_gb:.1f}GB free")
    except OSError:
        require("/tmp stat", False)
    try:
        with urllib.request.urlopen("https://deb.debian.org/debian/",
                                    timeout=15) as response:
            require("debian mirror reachability", response.status == 200)
    except Exception as error:
        require("debian mirror reachability", False, str(error)[:80])
    try:
        ncpu = os.cpu_count() or 0
        require("cpus >= 8", ncpu >= 8, f"{ncpu}")
    except Exception:
        require("cpu count", False)
    try:
        mem_gb = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1e9
        require("ram >= 16GB", mem_gb >= 16, f"{mem_gb:.1f}GB")
    except Exception:
        require("ram size", False)

    if missing:
        print(f"\nmissing {len(missing)}: {', '.join(missing)}")
        return 2
    print("\nhost ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
