"""Recreate the verification inputs under ~/prune-evidence/inputs."""
import io
import os
import subprocess
import tarfile
from pathlib import Path

R = Path("/home/idealinsane/projects/knfsd-syzkaller")
I = Path.home() / "prune-evidence/inputs"
I.mkdir(parents=True, exist_ok=True)

PRELUDE = """action=${1:-}
case "$action" in
    setup)
        systemctl stop frozen-phase9-fixture.service >/dev/null 2>&1 || \\
            /run/frozen-phase9/lane.sh cleanup /tmp/frozen-phase9.manager >/dev/null 2>&1 || true
        ;;
esac
"""


def per_run(lane_text, env=""):
    """A per-run fixture: retire the baked boot fixture first, then run lane.sh with env set."""
    first, rest = lane_text.split("\n", 1)
    return first + "\n" + env + PRELUDE + rest


def show(rev, path):
    return subprocess.run(["git", "-C", str(R), "show", "%s:%s" % (rev, path)],
                          capture_output=True, check=True).stdout


(I / "run_frozen_phase1_vm.py").write_bytes(
    show("ab353b0", "bundle/ab-runner/phases/run_frozen_phase1_vm.py"))
lane = (R / "bundle/lane/lane.sh").read_text()
(I / "lane-direct.sh").write_text(per_run(lane, "SERVER_IMPL=knfsd; export SERVER_IMPL\n"))
(I / "lane-proxy.sh").write_text(per_run(lane))
for f in ("lane-direct.sh", "lane-proxy.sh"):
    os.chmod(I / f, 0o755)
wl = show("ab353b0", "tools/nfs_remote_kcov_ganesha_v41_workload.prog").decode()
(I / "workload-direct.prog").write_text(wl)
for c in ("client0", "client1"):
    wl = wl.replace("nfs-lane/%s\\x00" % c, "nfs-lane/%s-knfsd\\x00" % c)
(I / "workload-proxy.prog").write_text(wl)
for src, dst in (("tools/nfs-proxy/test/guest-syzkaller-four.prog", "workload-raw.prog"),
                 ("bundle/corpus/nfs-normal/async-copy-v42-tcp.prog", "workload-copy.prog")):
    (I / dst).write_bytes((R / src).read_bytes())
(I / "lane-v42.sh").write_text(per_run(lane, "NFS_VERSION=4.2; export NFS_VERSION\n"))
os.chmod(I / "lane-v42.sh", 0o755)
# NFSP_PROXY: a proxy built with build-guest.sh --out, for testing a rebuilt proxy.
# The deps are assembled the same way as the lane image (Ganesha V15.6 + relay).
proxy = Path(os.environ.get("NFSP_PROXY", R / "bundle/src/nfs-proxy-lane"))
deps = I / "deps-ganesha-proxy.tar.gz"
deps.unlink(missing_ok=True)
subprocess.run(["python3", str(R / "tools/assemble-guest-deps.py"),
                "--ganesha-deps", str(R / "bundle/src/guest-deps-ganesha-v15.6.tar.gz"),
                "--proxy", str(proxy), "--out", str(deps)], check=True)
print(sorted(p.name for p in I.iterdir()))
