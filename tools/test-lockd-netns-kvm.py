#!/usr/bin/env python3
"""Probe per-net lockd configuration in a disposable pinned KVM guest."""

import argparse
from pathlib import Path

from agent_pipeline.stage1.host.vm import QemuGuest, VmConfig


def checked(guest, command):
    rc, output = guest.run(command)
    print(f"$ {command}\n{output.strip()}", flush=True)
    if rc:
        raise RuntimeError(f"guest command failed ({rc})")
    return output.strip()


def expect_port(guest, namespace, expected):
    prefix = f"ip netns exec {namespace} " if namespace else ""
    actual = checked(guest, prefix + "/tmp/lockd-netlink-port get")
    if actual != str(expected):
        raise AssertionError(f"{namespace or 'initial'} lockd port: {actual}, expected {expected}")


def expect_rpcbind(output, version, protocol, port):
    rows = [line.split() for line in output.splitlines()]
    matches = [row for row in rows if len(row) >= 4 and row[:3] ==
               ["100021", str(version), protocol]]
    if len(matches) != 1 or matches[0][3] != str(port):
        raise AssertionError(f"NLMv{version} {protocol} rpcbind port: {matches}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bzimage", type=Path, required=True)
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--helper", type=Path, required=True)
    parser.add_argument("--front-helper", type=Path, required=True)
    parser.add_argument("--console", type=Path, required=True)
    args = parser.parse_args()
    guest = QemuGuest(VmConfig(
        qemu="qemu-system-x86_64", bzimage=args.bzimage, image=args.image,
        lane_dir=Path("bundle/lane").resolve(), ssh_key=args.ssh_key,
        cmdline="console=ttyS0 root=/dev/sda rw nokaslr nfs.localio_enabled=N",
        console_log=args.console))
    try:
        guest.start()
        guest.put(args.helper, "/tmp/lockd-netlink-port")
        guest.put(args.front_helper, "/tmp/nlm-rpcbind-front")
        checked(guest, "uname -r; cat /proc/fs/nfsd/threads; ss -ltn; systemctl is-active frozen-phase9-fixture.service || true")
        checked(guest, "ip netns add nlmprobe1 && ip netns add nlmprobe2")
        checked(guest, "ip -n nlmprobe1 link set lo up")
        checked(guest, "ip -n nlmprobe2 link set lo up")
        checked(guest, "ip link add nlmprobe-s type veth peer name nlmprobe-c")
        checked(guest, "ip link set nlmprobe-s netns nlmprobe1 && "
                "ip link set nlmprobe-c netns nlmprobe2")
        checked(guest, "ip -n nlmprobe1 addr add 198.18.66.1/30 dev nlmprobe-s && "
                "ip -n nlmprobe1 link set nlmprobe-s up")
        checked(guest, "ip -n nlmprobe2 addr add 198.18.66.2/30 dev nlmprobe-c && "
                "ip -n nlmprobe2 link set nlmprobe-c up")
        expect_port(guest, None, 0)
        expect_port(guest, "nlmprobe1", 0)
        checked(guest, "ip netns exec nlmprobe1 /tmp/lockd-netlink-port set 4050")
        checked(guest, "ip netns exec nlmprobe2 /tmp/lockd-netlink-port set 4051")
        expect_port(guest, "nlmprobe1", 4050)
        expect_port(guest, "nlmprobe2", 4051)
        expect_port(guest, None, 0)
        if checked(guest, "cat /proc/sys/fs/nfs/nlm_tcpport") != "0":
            raise AssertionError("global NLM TCP port changed")
        checked(guest, "ls /opt/kcov-nfs/deps/usr/sbin/rpc.nfsd /opt/kcov-nfs/deps/sbin/rpcbind /opt/kcov-nfs/deps/usr/bin/rpcinfo /proc/fs/nfsd/threads")
        # The daemon must inherit a private /run, as it does in lane.sh.
        start = (
            "ip netns exec nlmprobe1 unshare --mount --propagation private sh -c '"
            "set -eu; "
            "PATH=/opt/kcov-nfs/deps/usr/sbin:/opt/kcov-nfs/deps/sbin:/opt/kcov-nfs/deps/usr/bin:$PATH; "
            "LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:/opt/kcov-nfs/deps/lib/x86_64-linux-gnu; "
            "export PATH LD_LIBRARY_PATH; "
            "mkdir -p /tmp/nlmprobe-run /tmp/nlmprobe-nfsd; "
            "mount --bind /tmp/nlmprobe-run /run; mkdir -p /run/rpcbind; "
            "rpcbind -w; "
            "mount -t nfsd nfsd /tmp/nlmprobe-nfsd; "
            "printf \"tcp 20490\\n\" > /tmp/nlmprobe-nfsd/portlist; "
            "printf \"1\\n\" > /tmp/nlmprobe-nfsd/threads; "
            "sleep 2; "
            "rpcinfo -T tcp 127.0.0.1 nlockmgr 4; "
            "echo NLM_BEFORE; rpcinfo -p 127.0.0.1; "
            "/tmp/nlm-rpcbind-front 4045; "
            "echo NLM_AFTER; rpcinfo -p 127.0.0.1'"
        )
        output = checked(guest, start)
        remote = ("ip netns exec nlmprobe2 sh -c '"
                  "export PATH=/opt/kcov-nfs/deps/usr/bin:$PATH; "
                  "export LD_LIBRARY_PATH=/opt/kcov-nfs/deps/usr/lib/x86_64-linux-gnu:"
                  "/opt/kcov-nfs/deps/lib/x86_64-linux-gnu; "
                  "rpcinfo -p 198.18.66.1'")
        remote_map = checked(guest, remote)
        for version in (1, 3, 4):
            expect_rpcbind(remote_map, version, "tcp", 4045)
        expect_port(guest, "nlmprobe1", 4050)
        expect_port(guest, "nlmprobe2", 4051)
        expect_port(guest, None, 0)
        listeners = checked(guest, "ip netns exec nlmprobe1 ss -ltn")
        if not any(line.split()[3].endswith(":4050") for line in listeners.splitlines()
                   if len(line.split()) >= 4 and line.startswith("LISTEN")):
            raise AssertionError("server lockd is not listening on TCP 4050")
        before, after = output.split("NLM_AFTER", 1)
        rpcinfo = before.split("NLM_BEFORE", 1)[1]
        for version in (1, 3, 4):
            expect_rpcbind(rpcinfo, version, "tcp", 4050)
        for version in (1, 3, 4):
            expect_rpcbind(after, version, "tcp", 4045)
        print("PASS: per-net lockd 4050/4051, live listener, remote TCP rpcbind front 4045", flush=True)
    finally:
        guest.stop()


if __name__ == "__main__":
    main()
