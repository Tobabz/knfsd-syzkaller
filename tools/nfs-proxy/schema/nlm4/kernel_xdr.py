#!/usr/bin/env python3
"""Pin target-kernel NLMv4 XDR, omitting xdrgen-only pragmas."""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

KERNEL_COMMIT = "c03c1a14507dfaf8b856c2608f9ac216021fc222"
KERNEL_PATH = "Documentation/sunrpc/xdr/nlm4.x"
KERNEL_SHA256 = "2564fbaee85ea23c3499fbf5d1b28a4dbdb24817a9934b10e6f1433c93445a79"
OUTPUT_SHA256 = "1d4812a735e5cec534782097355e8a5e45caf4025a0b8182f914158bc69d7b9c"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def generate(kernel_dir):
    source = subprocess.check_output(
        ["git", "-C", str(kernel_dir), "show", f"{KERNEL_COMMIT}:{KERNEL_PATH}"]
    )
    if digest(source) != KERNEL_SHA256:
        raise ValueError("kernel NLMv4 XDR changed from pinned source")
    lines = source.decode("ascii").splitlines(keepends=True)
    lines = [line for line in lines if not line.startswith("pragma ")]
    header = ("/* Generated from target kernel " + KERNEL_COMMIT + ":" +
              KERNEL_PATH + "; xdrgen pragmas omitted. Do not edit. */\n")
    return header.encode("ascii") + "".join(lines).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "verify", "write"))
    parser.add_argument("--kernel-dir", type=Path)
    args = parser.parse_args()
    output = Path(__file__).with_name("nlm4.x")
    if args.action == "check":
        if digest(output.read_bytes()) != OUTPUT_SHA256:
            raise ValueError("committed NLMv4 XDR differs from its pin")
        return
    if args.kernel_dir is None:
        parser.error("--kernel-dir is required for --verify and --write")
    generated = generate(args.kernel_dir)
    if args.action == "verify":
        if output.read_bytes() != generated:
            raise ValueError("committed NLMv4 XDR differs from target kernel")
    else:
        output.write_bytes(generated)


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"kernel_xdr: {exc}", file=sys.stderr)
        sys.exit(1)
