# NFS-specific Mutation Engine

`nfs-proxy` is a **Mutation Engine specialized for NFS, implemented as a proxy** between
NFS clients and servers. It applies mutation rules supplied by syzkaller programs to
RPC/XDR traffic, with deterministic edits, mutation logging and replay.

`build.sh` runs host framing/walk/delta/golden/rpc_record/rpc_decode/nfs_decode/nfs4_decode/txn/rule/semantic/relay/control tests under clang
and GCC ASan+UBSan, after the ProtocolSchema normalizer's tests, a pin check of the RFC XDR files and a freshness check of every generated schema table. `test_golden` pins the bytes of legacy `NFSPDLT1`/`NFSPDLT2`
delta files independently of their writer and reader. `build.sh` also compiles
the guest delta-replay probe as a build-only regression gate. The host tests
run on Linux only: `test_control` uses `AF_UNIX/SOCK_SEQPACKET`, the real legacy
control transport, and `test_proxy` binds its loopback topology (listeners on
`127.0.0.2`/`.3`, clients on `127.0.0.10`/`.11`). `build-guest.sh --out FILE`
then creates Debian bookworm ABI binaries for the relay and replay probe: it
builds for `linux/amd64` whatever the host architecture, checks each ELF machine
and glibc requirement, and records provenance next to both binaries. The two backend listeners are routed
solely by destination IP, and the source IP identifies the client.
`SERVER_IMPL=both` provides `.1:2049 → knfsd :20490` and
`.5:2049 → Ganesha :20491`.
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

## Target semantic path: RpcRecord, RPC Decoder, ConnectionRef (M1)

These are the first target-architecture components
([06 §24](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md)). They sit
beside the legacy arm path and change none of its bytes or coordinates.

- `src/rpc_record.*` turns a framed record into its canonical marker-free
  `rpc_payload` (a view for one fragment, a concatenation for several) and frames a
  payload back as one last fragment. Offset 0 of the target coordinate space is the
  first RPC byte; legacy `walk.c`/`edit.c` offsets still include the marker.
- `src/rpc_decode.*` decodes only the RFC 5531 envelope of an `rpc_payload`: CALL
  xid/prog/vers/proc, cred and verifier spans, every REPLY arm, and the body offset.
  Values outside RFC 5531 fail closed with a named status. A REPLY never claims a
  procedure.
- `proxy.c` gives every accepted connection a `connection_id` that is nonzero,
  monotonic over the run and never derived from a slot or fd. `on_connection` reports
  opened and closed events; `on_rpc_record` observes each record as an
  `nfsp_rpc_record` before the legacy `on_record` and may refuse it, which closes the
  connection without forwarding (`record_refused`). With both callbacks NULL (`main.c`
  without `--semantic`), the relay behaves exactly as before.

## Target semantic path: ProtocolSchema and NFS Semantic Decoder (M2)

[06 §25](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md),
contract in [02](../../docs/design/03-nfs-proxy/02-semantic-decoder.md).

- `schema/normalize.py` reads pinned XDR and an annotation file and writes constant C tables
  (`src/schema.h`). The tables are committed; `build.sh` regenerates them and fails on any
  difference. See [schema/README.md](schema/README.md) for the annotation grammar, path rules
  and what the normalizer refuses.
- `src/nfs_decode.*` interprets those tables over a CALL or REPLY body and emits one
  `SemanticField` per XDR node, each with a `WireRef` (encoded, value and length/count/
  discriminant/padding spans in `rpc_payload` coordinates). Any status other than `decoded`
  leaves no fields behind.
- A REPLY is decoded only from `reply_dispatch`. Without it the status is
  `transaction_context_missing`; for NFSv4 without a minor version it is `dispatch_incomplete`.
  `test_fixture` dispatch is refused outside host tests.
- `src/schema_nfs4.c` holds NFSv4.0, 4.1 and 4.2, generated from the XDR of RFC 7531, RFC 5662
  and RFC 7863. `schema/rfc_xdr.py` extracts that XDR with each RFC's own rule and pins every RFC
  text and extracted file by SHA-256 (`schema/nfs4/SOURCES`); `build.sh` checks the pins offline.
  NFSv3 has no schema yet, so its messages are `unsupported_schema`.

## Target semantic path: Transaction Context (M3)

[06 §26](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md),
contract in [03](../../docs/design/03-nfs-proxy/03-transaction-context.md).

- `src/txn.*` keeps one entry per live CALL, keyed by `connection_id + call_direction + xid`.
  A REPLY looks up the opposite of its own direction, so a backchannel CALL (S2C) and a
  forechannel CALL (C2S) with the same XID on one connection stay apart. Results are
  `found`, `missing`, `ambiguous` and `expired`; only `found` gives a `reply_dispatch`.
  A different CALL on a live key makes it ambiguous (never overwritten); a retransmission
  (the same bytes, by a two-hash fingerprint) is counted, not re-inserted. A key may take
  a new CALL once its last CALL was answered; while an expired or ambiguous key is still
  retained, a new CALL on it only keeps it ambiguous, since the old reply may yet come.
- Memory is a fixed pool allocated once. Bounds: 4096 outstanding entries, 1024 per
  connection, 1024 ended entries kept for diagnosis, 300 s timeout without traffic, 10 s
  retention. A full table refuses a new CALL (`capacity_exhausted`) and never reclaims a
  live entry; a closed connection drops all its entries.
- `src/semantic.*` is the `on_rpc_record`/`on_connection` observer that ties M1–M3 together:
  envelope, then a CALL entry, then the body decode and its request summary (opcodes and
  minor version); a REPLY decodes only with a `found` entry's dispatch. It never changes or
  refuses a record. `nfs-proxy ... --semantic` turns it on and prints `semantic ...` and
  `txn ...` counter lines with the stats. With `--control`/`--replay` the CALL the peer gets
  may be rewritten after the observer (even its minor version), so a REPLY then gets neither
  a dispatch nor a request summary: it is `transaction_context_missing`.

## Target semantic path: rule set format and validation (M4a)

[06 §27](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md),
format in [04 §35](../../docs/design/03-nfs-proxy/04-semantic-mutation-runtime.md).

- `src/rule.*` reads an `NFSPRUL1` rule set: canonical XDR of `CompiledMutationRule[]` with one
  `schema_id` and one `candidate_id`. Every length and count is checked against its bound and
  the bytes left before anything is copied, and any second encoding of the same set (trailing
  bytes, non-zero padding, unsorted or repeated ids) is `malformed`.
- Validation then checks each rule against the ProtocolSchema its `schema_id` names: selector,
  target path and part, predicate and transform types, mutation shape, and that the declared
  context dependencies are exactly those its ValueRefs need. Loading is all or nothing; the
  first failing rule refuses the set with a typed status and its rule and predicate index.
  What this runtime cannot apply yet (insert, delete, operation edits, builtin transforms, the
  `encoded` part) is `unsupported_capability`.
- `nfsp_schema_resolve()` (`src/schema.*`) finds the node a semantic path names from the type
  graph alone. `test_nfs_decode` and `test_nfs4_decode` resolve every path the decoder emits
  and require the same type back, so a rule and the decoder cannot disagree on a name.
- Nothing installs or applies a rule set yet: that is the Resolver (M4b), the preflight and
  edit adapter (M4c), and the Runner installation path (S1a).

## Building

```sh
tools/nfs-proxy/build-guest.sh \
  --out bundle/src/nfs-proxy-control-guest \
  --probe-out bundle/src/guest-delta-replay
```

Host tests are under `test/`; `build.sh` builds and runs them.
`test/guest-delta-replay.c` provides the replay probe source. Do not use the
host-build copy for guest validation; use the `--probe-out` artifact above.

Build the syzkaller integration with [bootstrap](../../README.md#2-provision-the-fuzzing-environment-build--bake),
which applies the complete checked-in patch series and builds the binaries.
Binaries are local, gitignored artifacts.

`bundle/patches/syzkaller/0019-*` adds `syz_arm_nfs_proxy_v2` (the arm v2 packet above) on top of 0017/0018;
applying the series and running `make descriptions` (`tools/bootstrap-kcov-env.py` does this) regenerates
`sys/gen/*.gob.flate` so the new pseudo-syscall is visible to `prog.GetTarget`.

Implementation background and execution results are maintained in the
[handoff document](../../docs/handoff/proxy-variable-length-edits/handoff.md)
and [validation history](../../report/validation-history.md).
