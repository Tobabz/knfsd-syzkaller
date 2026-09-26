# NFSv4 scoped wire relay

`build.sh` runs host framing/walk/delta/relay/control tests under clang and
GCC ASan+UBSan. `build-guest.sh --out FILE` creates a Debian bookworm ABI
guest binary after those checks. The two backend listeners are routed solely
by destination IP, and the source IP identifies the client. `SERVER_IMPL=both`
provides `.1:2049 → knfsd :20490` and `.5:2049 → Ganesha :20491`.

## Arm protocol

`syz_arm_nfs_proxy` sends exactly 140 bytes as one Unix `SOCK_SEQPACKET` on
`/nfs-lane/control/arm.sock`, which is a bind of that executor's
`/syz-nfs-lanes/proc-N/control` directory. The versioned packet is:

| Bytes | Meaning |
|---|---|
| 0–7 | ASCII `NFSPARM1` |
| 8–43 | nine big-endian u32s: direction (0 C2S/1 S2C), backend (0 knfsd/1 Ganesha), client (0/1), first opcode (`0xffffffff` means any), anchor offset/length, patch offset/width, zero reserved flags |
| 44–107 | literal anchor bytes (first `anchor_len` used, max 64) |
| 108–123 | recorded original bytes (first `patch_w` used, max 16) |
| 124–139 | replacement bytes (first `patch_w` used) |

The proxy ACKs with one zero byte **after registering** the rule. The
returned FD owns it: closing the FD or ending the executor program expires
the rule. The ACK says neither that a matching RPC arrived nor that changed
bytes reached the backend. The rule always includes both client and backend;
there is no proxy-side random choice. Only structurally certain typed 32-bit
slots and known raw regions may be patched. A mismatch against recorded
original bytes refuses the mutation and increments the mismatch counter.

Each ACKed arm gets a durable `arm-N.delta` file inside that lane's server
directory, with the predicate, originals, replacements and current applied
count. Every content match is eligible; no ordinal selection is used. The
`--replay DELTA_FILE` mode loads this file, walks each record in the same way,
and invokes the **same `nfsp_apply_rule`** as live mode. It exits unsuccessfully
if application counts differ or originals mismatch. SIGUSR1 produces both
relay and control statistics; SIGTERM prints the final replay comparison.

## Reproduce the guest gate

```sh
tools/nfs-proxy/build-syzkaller.sh
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-control-guest
KOOV_NFS_PROXY_GUEST=bundle/src/nfs-proxy-control-guest \
KOOV_SYZ_FOUR_WORKLOAD=tools/nfs-proxy/test/guest-syzkaller-mutate.prog \
KOOV_EVIDENCE_DIR=evidence/ganesha-asan-relay-replay \
    tools/nfs-proxy/ganesha-asan-relay-run.sh
```

The runner copies the four-choice syzkaller executor and program, checks all
four tagged RPC round trips, both live C2S/S2C deltas, two fresh replay
proxies against real Ganesha traffic, and a separate expected-failure replay
with a derived delta whose anchor matches a different original XID. It
requires `applied=0`, `refused_orig=1`, an unchanged server reply, and a
nonzero replay exit. It also checks ASan runtime/logs, mount tree sharing,
and fixture cleanup. The static `guest-delta-replay.c` probe sends a fixed
NFSv4 record to replay's separate `:20549` listener; it is a deterministic
transport check, not a fuzzer. The ordinary NFS mounts remain on `:2049`.

The arm OFF/ON repeated-run gate uses the same four-socket RPC program in
both groups; ON adds two arm registrations and closes. It calls
`convert-ab-image.sh` before starting, boots fresh snapshot guests in ABBA
order, and requires `--executions 30 --trials 2`. Each trial checks four tagged
RPC replies per execution, ASan, cleanup, and (for ON) 60 durable applied
deltas. The reported exec/s includes a fixed 500 ms reply-drain pause per
program, so it is a controlled end-to-end workload metric rather than an
isolated proxy latency measurement.

```sh
KOOV_NFS_PROXY_GUEST=bundle/src/nfs-proxy-control-guest \
KOOV_EVIDENCE_DIR=evidence/ganesha-asan-relay-ab \
    tools/nfs-proxy/ganesha-asan-relay-ab-run.sh
```

The existing 16 syzkaller patches and `bundle/src/guest-deps.tar.gz` remain
unchanged; the new `bundle/patches/syzkaller/0017-*` is a `git am` patch after
0016, included in the series and hash ledger. The `tools/` build wrapper can
apply just 0017 to an already patched source tree (`KOOV_SYZ_TARGET`); guest
paths can be selected with `KOOV_*` overrides. Binaries and VM trial evidence
are local, gitignored artifacts.
