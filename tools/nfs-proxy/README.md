# NFS wire relay

`build.sh` runs host framing/walk/delta/relay/control tests under clang and
GCC ASan+UBSan. `build-guest.sh --out FILE` creates a Debian bookworm ABI
guest binary after those checks. The two backend listeners are routed solely
by destination IP, and the source IP identifies the client. `SERVER_IMPL=both`
provides `.1:2049 → knfsd :20490` and `.5:2049 → Ganesha :20491`.
NFSv3 calls use the same TCP relay; their MOUNT requests go directly to the
backends on pinned ports. Typed operation matching is defined for NFSv4
COMPOUND requests, while v3 messages expose only the RPC header and raw body.

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

## Building

```sh
tools/nfs-proxy/build-syzkaller.sh      # applies 0017 to an already patched syzkaller tree (KOOV_SYZ_TARGET)
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-control-guest
```

The guest relay gates and the arm OFF/ON repeated-run runners that used these builds
(`ganesha-asan-relay-run.sh`, `ganesha-asan-relay-ab-run.sh`, `run-ganesha-asan-relay-*.py`) were removed in
commit `7833ed3`, together with their evidence. The static `test/guest-delta-replay.c` probe and the unit
tests under `test/` remain.

`bundle/patches/syzkaller/0017-*` is a `git am` patch after 0016, included in the series. The `tools/` build
wrapper can apply just 0017 to an already patched source tree (`KOOV_SYZ_TARGET`); guest paths can be
selected with `KOOV_*` overrides. Binaries are local, gitignored artifacts.
