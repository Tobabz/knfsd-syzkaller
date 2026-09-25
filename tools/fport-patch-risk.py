#!/usr/bin/env python3
"""Focused risk metrics for the kernel patch series.

Counts per series:
  - total hunks, patches, files
  - hunks touching uapi headers (worst drift class)
  - hunks whose added lines sit inside a struct body (between struct X { and };)
  - hunks touching identified high-churn files (tcp.c, kcov.c, svc.c,
    svcsock.c, xprt.c, xprtsock.c, nfs4proc.c, nfs4state.c, sched.c)
"""
import os
import re
import sys
from pathlib import Path
from collections import Counter

_DEF_BUNDLE = Path(__file__).resolve().parent.parent / "bundle" / "patches"
_bundle = Path(os.environ.get("KOOV_BUNDLE", str(_DEF_BUNDLE)))
SERIES = Path(sys.argv[1] if len(sys.argv) > 1 else _bundle / "kernel")
HIGH_CHURN = ["net/ipv4/tcp.c", "net/ipv4/tcp_output.c", "net/ipv4/tcp_ipv4.c",
              "net/ipv4/tcp_bpf.c", "net/ipv4/inet_connection_sock.c",
              "kernel/kcov.c", "net/sunrpc/svc.c", "net/sunrpc/svc_xprt.c",
              "net/sunrpc/svcsock.c", "net/sunrpc/xprt.c",
              "net/sunrpc/xprtsock.c", "fs/nfs/nfs4proc.c",
              "fs/nfs/nfs4state.c", "fs/nfsd/nfs4proc.c",
              "fs/nfsd/nfs4state.c", "net/sunrpc/sched.c"]

def split_files(text):
    """Return {filename: [hunk-body-lists]}."""
    files, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^diff --git a/\S+ b/(\S+)", line)
        if m:
            cur = m.group(1)
            files.setdefault(cur, [])
    return files

def hunks_with_payload(text):
    """Yield (filename, payload-lines) per hunk."""
    cur = None
    for block in re.split(r"^diff --git a/\S+ b/(\S+)$", text, flags=re.M):
        pass
    # simpler: iterate line by line
    out, cur_file, in_hunk = [], None, False
    for line in text.splitlines():
        m = re.match(r"^diff --git a/\S+ b/(\S+)", line)
        if m:
            cur_file = m.group(1)
            in_hunk = False
            continue
        if line.startswith("@@"):
            in_hunk = True
            out.append([cur_file, []])
            continue
        if in_hunk and cur_file:
            if line[:1] in "+-" and not line.startswith("+++") \
                    and not line.startswith("---"):
                out[-1][1].append(line)
            elif line.startswith("@@") is False and not line[:1] in " \n":
                in_hunk = False  # diff header of next file section
    return out

def in_struct_body(payload):
    """Heuristic: added field-ish lines between a struct { and its }."""
    depth = 0
    for line in payload:
        s = line[1:].strip()
        if re.match(r"^struct \w+ \{", s):
            depth = 1
        elif depth and s.startswith("}"):
            depth = 0
        elif depth and re.match(r"^\w+\s*\w*\s*[;:]", s):
            return True
    return False

def main():
    totals = Counter()
    uapi = Counter()
    high = Counter()
    struct_hunks = []
    for path in sorted(SERIES.glob("*.patch")):
        text = path.read_text(errors="replace")
        for fname, payload in hunks_with_payload(text):
            totals[fname] += 1
            if fname.startswith("include/uapi/"):
                uapi[fname] += 1
            if fname in HIGH_CHURN:
                high[fname] += 1
            if in_struct_body(payload):
                struct_hunks.append((path.name, fname))
    print("total hunks: %d" % sum(totals.values()))
    print("patches: %d, files touched: %d" % (
        len(list(SERIES.glob("*.patch"))), len(totals)))
    print("\nuapi-header hunks:")
    for f, c in sorted(uapi.items()):
        print("  %-28s %d" % (f, c))
    print("\nhigh-churn file hunks:")
    for f, c in sorted(high.items(), key=lambda kv: -kv[1]):
        print("  %-36s %d" % (f, c))
    print("\nstruct-body insertion hunks: %d" % len(struct_hunks))
    for name, f in struct_hunks[:25]:
        print("  %s  %s" % (name[:8], f))

if __name__ == "__main__":
    main()