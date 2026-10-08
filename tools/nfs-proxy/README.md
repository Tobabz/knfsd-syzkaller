# NFS-specific Mutation Engine

`nfs-proxy` is a **Mutation Engine specialized for NFS, implemented as a proxy** between
NFS clients and servers. It applies mutation rules supplied by syzkaller programs to
RPC/XDR traffic, with deterministic edits, mutation logging and replay.

`build.sh` runs host framing/walk/delta/relay/control tests under clang and
GCC ASan+UBSan. `build-guest.sh --out FILE` creates a Debian bookworm ABI
guest binary after those checks. The two backend listeners are routed solely
by destination IP, and the source IP identifies the client. `SERVER_IMPL=both`
provides `.1:2049 → knfsd :20490` and `.5:2049 → Ganesha :20491`.
NFSv3 calls pass through the engine's TCP proxy; their MOUNT requests go directly to the
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

The engine ACKs with one zero byte **after registering** the rule. The
returned FD owns it: closing the FD or ending the executor program expires
the rule. The ACK says neither that a matching RPC arrived nor that changed
bytes reached the backend. The rule always includes both client and backend;
the engine makes no random choice. Only structurally certain typed 32-bit
slots and known raw regions may be patched. A mismatch against recorded
original bytes refuses the mutation and increments the mismatch counter.

Each ACKed arm gets a durable `arm-N.delta` file inside that lane's server
directory, with the predicate, originals, replacements and current applied
count. Every content match is eligible; no ordinal selection is used. The
`--replay DELTA_FILE` mode loads this file, walks each record in the same way,
and invokes the **same `nfsp_apply_rule`** as live mode. It exits unsuccessfully
if application counts differ or originals mismatch. SIGUSR1 produces both
relay and control statistics; SIGTERM prints the final replay comparison.

### Variable-length edits (arm v2)

`syz_arm_nfs_proxy_v2(arm, arm_len)` sends a second, self-describing packet on
the same control socket for edits the fixed 140-byte packet cannot express:
inserting an operation into a COMPOUND, or growing/shrinking a field. The
engine dispatches by magic, so v1 and v2 arms can be registered and applied
together on the same connection.

| Bytes | Meaning |
|---|---|
| 0–7 | ASCII `NFSPARM2` |
| 8–43 | nine big-endian u32s: direction, backend, client, first opcode (as v1), anchor offset/length, mode (0 struct-preserving/1 raw), `nedits` (1–8), zero reserved |
| 44–(44+anchor_len) | literal anchor bytes |
| then, `nedits` times | one edit: `kind` (0 REPLACE/1 INSERT/2 DELETE/3 OP_APPEND/4 OP_PREPEND), `offset`, `orig_len`, `data_len` (four big-endian u32s), then `orig_len` original bytes and `data_len` replacement/inserted bytes |

The packet is self-describing (no fixed length): the header's `nedits` and
each edit's own `orig_len`/`data_len` say how many bytes follow, and the
engine's decoder (`tools/nfs-proxy/src/edit.c`, `control.c`'s `decode_v2`)
requires the declared sizes to consume the packet exactly, with nothing
trailing. All of REPLACE/INSERT/DELETE/OP_APPEND/OP_PREPEND verify any bytes
they claim to overwrite or remove before patching (same verify-before-patch
contract as v1), and all offsets across every edit in a rule, and across every
rule that matches one record, are in the **original** record's coordinates:
applying one edit never shifts where another edit's offset points, and edits
whose spans overlap are refused together rather than applied in some order.

`mode` matters only for `OP_APPEND`/`OP_PREPEND`: struct-preserving also bumps
the COMPOUND's declared op count so the added operation is dispatched; raw
leaves the count alone, for a scenario that specifically wants the declared
count and the real op array to disagree. The record's fragment marker is
always rebuilt to the rule's true output length in both modes; a deliberate
length/content mismatch belongs inside the RPC/XDR body, never in the marker,
or the rest of the TCP stream desynchronises.

Edits are confined to the COMPOUND op-array body (everything after the fixed
RPC/COMPOUND header `nfsp_walk` resolves); a message the walk cannot parse as
a COMPOUND refuses every v2 rule that would otherwise match it, the same way
an unresolvable message refuses a v1 rule's `patch_allowed` check. Delta
replay for v2 arms uses the distinct `NFSPDLT2` file magic and the same
`nfsp_apply_edit_rules` function live mode calls; `nfsp_control_close` in
replay mode fails the same way v1 does when an applied count or a verified
original does not match what was recorded.

## Building

```sh
tools/nfs-proxy/build-syzkaller.sh      # applies 0017 to an already patched syzkaller tree (KOOV_SYZ_TARGET)
tools/nfs-proxy/build-guest.sh --out bundle/src/nfs-proxy-control-guest
```

Host tests are under `test/`; `build.sh` builds and runs them.
`test/guest-delta-replay.c` provides a guest replay probe.

`bundle/patches/syzkaller/0017-*` is a `git am` patch after 0016, included in the series. The `tools/` build
wrapper can apply just 0017 to an already patched source tree (`KOOV_SYZ_TARGET`); guest paths can be
selected with `KOOV_*` overrides. Binaries are local, gitignored artifacts.

`bundle/patches/syzkaller/0019-*` adds `syz_arm_nfs_proxy_v2` (the arm v2 packet above) on top of 0017/0018;
applying the series and running `make descriptions` (`tools/bootstrap-kcov-env.py` does this) regenerates
`sys/gen/*.gob.flate` so the new pseudo-syscall is visible to `prog.GetTarget`.

Implementation background and execution results are maintained in the
[handoff document](../../docs/handoff/proxy-variable-length-edits/handoff.md)
and [validation history](../../report/validation-history.md).
