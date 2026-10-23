#!/usr/bin/env python3
"""Drive one disposable Proxy generation for an NLM KVM diagnostic."""

import argparse
import socket
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("socket_path")
    parser.add_argument("rule_set_id")
    parser.add_argument("operation", choices=("activate", "deactivate"))
    args = parser.parse_args()
    op = {"activate": 1, "deactivate": 2}[args.operation]
    packet = (b"NFSPACT1" + struct.pack(">IIQ", op, 0, 1)
              + bytes.fromhex("b042b7e6a00843878631224539fbbce88a4ac0dfd90ee16198f4f7659a71e01c")
              + args.rule_set_id.encode("ascii"))
    if len(packet) != 120:
        raise ValueError("invalid activation packet")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as sock:
        sock.settimeout(15)
        sock.connect(args.socket_path)
        sock.send(packet)
        answer = sock.recv(24)
    if len(answer) != 24 or answer[:8] != b"NFSPACK1":
        raise RuntimeError("invalid activation answer")
    actual_op, status, generation = struct.unpack(">IIQ", answer[8:])
    print(f"op={actual_op} status={status} generation={generation}")
    if (actual_op, status, generation) != (op, 0, 1):
        raise RuntimeError("activation refused")


if __name__ == "__main__":
    main()
