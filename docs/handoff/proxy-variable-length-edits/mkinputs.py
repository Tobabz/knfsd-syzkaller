"""Recreate the verification inputs under ~/prune-evidence/inputs."""
import io
import os
import subprocess
import tarfile
from pathlib import Path

R = Path("/home/idealinsane/projects/knfsd-syzkaller")
I = Path.home() / "prune-evidence/inputs"
I.mkdir(parents=True, exist_ok=True)


def show(rev, path):
    return subprocess.run(["git", "-C", str(R), "show", "%s:%s" % (rev, path)],
                          capture_output=True, check=True).stdout


(I / "run_frozen_phase1_vm.py").write_bytes(
    show("ab353b0", "bundle/ab-runner/phases/run_frozen_phase1_vm.py"))
lane = show("HEAD", "tools/ganesha-lane.sh").decode()
(I / "lane-direct.sh").write_text(lane)
first, rest = lane.split("\n", 1)
(I / "lane-proxy.sh").write_text(first + "\nSERVER_IMPL=both; export SERVER_IMPL\n" + rest)
for f in ("lane-direct.sh", "lane-proxy.sh"):
    os.chmod(I / f, 0o755)
wl = show("ab353b0", "tools/nfs_remote_kcov_ganesha_v41_workload.prog").decode()
(I / "workload-direct.prog").write_text(wl)
for c in ("client0", "client1"):
    wl = wl.replace("nfs-lane/%s\\x00" % c, "nfs-lane/%s-knfsd\\x00" % c)
(I / "workload-proxy.prog").write_text(wl)
for src, dst in (("tools/nfs-proxy/test/guest-syzkaller-four.prog", "workload-raw.prog"),
                 ("bundle/corpus/nfs-normal/async-copy-v42-tcp.prog", "workload-copy.prog"),
                 ("bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh", "lane-v42.sh")):
    (I / dst).write_bytes(show("HEAD", src))
os.chmod(I / "lane-v42.sh", 0o755)
# NFSP_PROXY: a proxy built with build-guest.sh --out, for testing a rebuilt proxy.
proxy = Path(os.environ.get("NFSP_PROXY", R / "bundle/src/nfs-proxy-control-guest")).read_bytes()
with tarfile.open(R / "bundle/src/guest-deps-ganesha.tar.gz") as tin, \
        tarfile.open(I / "deps-ganesha-proxy.tar.gz", "w:gz") as tout:
    for m in tin:
        tout.addfile(m, tin.extractfile(m) if m.isfile() else None)
    ti = tarfile.TarInfo("usr/sbin/nfs-proxy")
    ti.size, ti.mode = len(proxy), 0o755
    tout.addfile(ti, io.BytesIO(proxy))
print(sorted(p.name for p in I.iterdir()))
