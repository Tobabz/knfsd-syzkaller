#!/usr/bin/env python3
"""Add the nfs-proxy binary to the Ganesha deps tarball: the deps the lane image needs.

The lane fixture starts knfsd, NFS-Ganesha and the wire relay in every lane, so the
tarball passed to bootstrap as --deps-tar must carry all three.

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
NLM_MEMBERS = (("./usr/sbin/lockd-netlink-port", "lockd_port"),
               ("./usr/sbin/nlm-rpcbind-front", "rpcbind_front"))
REQUIRED = ("usr/sbin/ganesha.nfsd", "usr/sbin/rpc.nfsd")


def normalized(name):
    return name[2:] if name.startswith("./") else name


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--ganesha-deps", type=Path, required=True)
    parser.add_argument("--proxy", type=Path, required=True)
    parser.add_argument("--lockd-port", type=Path)
    parser.add_argument("--rpcbind-front", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output already exists: %s" % args.out)
    proxy = args.proxy.read_bytes()
    if not proxy.startswith(b"\x7fELF"):
        parser.error("--proxy is not an ELF binary: %s" % args.proxy)
    if (args.lockd_port is None) != (args.rpcbind_front is None):
        parser.error("NLM helpers must be supplied together")
    extras = []
    if args.lockd_port is not None:
        for member, path in ((NLM_MEMBERS[0][0], args.lockd_port),
                             (NLM_MEMBERS[1][0], args.rpcbind_front)):
            data = path.read_bytes()
            if not data.startswith(b"\x7fELF"):
                parser.error("NLM helper is not an ELF binary: %s" % path)
            extras.append((member, data))
    with tarfile.open(args.ganesha_deps) as source:
        names = {normalized(m.name) for m in source}
        missing = [n for n in REQUIRED if n not in names]
        if missing:
            parser.error("%s lacks %s" % (args.ganesha_deps, ", ".join(missing)))
        if normalized(PROXY_MEMBER) in names:
            parser.error("%s already contains the relay" % args.ganesha_deps)
        if any(normalized(member) in names for member, _ in extras):
            parser.error("NLM helper already exists in %s" % args.ganesha_deps)
        tmp = args.out.with_name(args.out.name + ".part")
        with tarfile.open(tmp, "w:gz") as out:
            for member in source:
                out.addfile(member, source.extractfile(member) if member.isfile() else None)
            for member, data in ((PROXY_MEMBER, proxy), *extras):
                info = tarfile.TarInfo(member)
                info.size, info.mode = len(data), 0o755
                out.addfile(info, io.BytesIO(data))
    tmp.rename(args.out)
    print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
