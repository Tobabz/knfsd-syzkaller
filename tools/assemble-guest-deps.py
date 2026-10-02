#!/usr/bin/env python3
"""Add the nfs-proxy binary to the Ganesha deps tarball: the deps the lane image needs.

The lane fixture starts knfsd, NFS-Ganesha and the wire relay in every lane, so the
tarball passed to bootstrap as --deps-tar must carry all three.

  tools/build-ganesha-deps.sh                       -> Bookworm dependency baseline
  tools/build-ganesha-v15.sh                        -> bundle/src/guest-deps-ganesha-v15.6.tar.gz
  tools/nfs-proxy/build-guest.sh --out FILE         -> the relay, built against the guest's glibc
  tools/assemble-guest-deps.py --ganesha-deps bundle/src/guest-deps-ganesha-v15.6.tar.gz \\
      --proxy FILE --out bundle/src/guest-deps-lane.tar.gz
"""
import argparse
import io
import sys
import tarfile
from pathlib import Path

PROXY_MEMBER = "./usr/sbin/nfs-proxy"
REQUIRED = ("usr/sbin/ganesha.nfsd", "usr/sbin/rpc.nfsd")


def normalized(name):
    return name[2:] if name.startswith("./") else name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ganesha-deps", type=Path, required=True)
    parser.add_argument("--proxy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output already exists: %s" % args.out)
    proxy = args.proxy.read_bytes()
    if not proxy.startswith(b"\x7fELF"):
        parser.error("--proxy is not an ELF binary: %s" % args.proxy)
    with tarfile.open(args.ganesha_deps) as source:
        names = {normalized(m.name) for m in source}
        missing = [n for n in REQUIRED if n not in names]
        if missing:
            parser.error("%s lacks %s" % (args.ganesha_deps, ", ".join(missing)))
        if normalized(PROXY_MEMBER) in names:
            parser.error("%s already contains the relay" % args.ganesha_deps)
        tmp = args.out.with_name(args.out.name + ".part")
        with tarfile.open(tmp, "w:gz") as out:
            for member in source:
                out.addfile(member, source.extractfile(member) if member.isfile() else None)
            info = tarfile.TarInfo(PROXY_MEMBER)
            info.size, info.mode = len(proxy), 0o755
            out.addfile(info, io.BytesIO(proxy))
    tmp.rename(args.out)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
