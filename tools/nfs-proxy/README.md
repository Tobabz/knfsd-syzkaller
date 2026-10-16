# NFS-specific Mutation Engine

`nfs-proxy` is a **Mutation Engine specialized for NFS, implemented as a proxy** between
NFS clients and servers. It applies mutation rules supplied by syzkaller programs to
RPC/XDR traffic, with deterministic edits, mutation logging and replay.

`build.sh` runs host framing/walk/delta/golden/rpc_record/rpc_decode/nfs_decode/nfs4_decode/txn/activation/rule/resolver/mutation_apply/semantic/relay/control tests under clang
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
- `src/schema_nfs3.c` holds NFSv3, generated from the XDR of RFC 1813. RFC 1813 prints no
  extraction script, so `schema/rfc_xdr.py` assembles `schema/nfs3/nfs3.x` from its prose, one
  pinned definition at a time (`schema/nfs3/SOURCES`). An NFSv3 REPLY decodes only under the
  procedure of its CALL's TransactionEntry; MOUNT, NLM and NFSACL stay `unsupported_schema`.

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

## Target semantic path: rule resolution, application and activation (M4a–M4d)

[06 §27](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md),
format in [04 §35](../../docs/design/03-nfs-proxy/04-semantic-mutation-runtime.md).

- `src/rule.*` reads an `NFSPRUL1` rule set: canonical XDR of `CompiledMutationRule[]` with one
  `schema_id` and one `candidate_id`. Every length and count is checked against its bound and
  the bytes left before anything is copied, and any second encoding of the same set (trailing
  bytes, non-zero padding, unsorted or repeated ids) is `malformed`.
- Validation then checks each rule against the ProtocolSchema its `schema_id` names: selector,
  target path and part, that every value the rule reads is in the target's procedure (in a
  family dispatched by procedure, such as NFSv3, a READ rule cannot read a WRITE argument; every
  NFSv4 operation is in COMPOUND, so no NFSv4 rule is refused for what it reads), predicate and
  transform types, mutation shape, and that the declared context dependencies are exactly those
  its ValueRefs need. Loading is all or nothing; the first failing rule refuses the set with a
  typed status and its rule and predicate index.
  What this runtime cannot apply yet (insert, delete, operation edits, builtin transforms, the
  `encoded` part) is `unsupported_capability`.
- `nfsp_schema_resolve()` (`src/schema.*`) finds the node a semantic path names from the type
  graph alone. `test_nfs_decode` and `test_nfs4_decode` resolve every path the decoder emits
  and require the same type back, so a rule and the decoder cannot disagree on a name.
- `src/resolver.*` resolves every rule against one immutable decoded payload. It evaluates
  selectors and typed conjunctions, binds a `current_message` reference to the target's
  operation occurrence, binds explicit forwarded/original request snapshots by proven
  operation sequence, evaluates literal/copy transforms, and owns the live original and
  output value snapshots in each `ResolvedMutation`. Rule summaries and mutations are
  canonical by `rule_id`, so permuting the input rules produces identical eligibility and
  conflict results.
- Runtime version 1 uses `all_matches`. Repeated target fields all become candidates, while a
  repeated predicate reference in one operation is
  `predicate_reference_ambiguous`. Preserve replacements of variable opaque/string values
  own their complete XDR encoding for conflict preflight; raw replacements own only the
  selected schema-proven span. Overlapping ownership refuses the whole eligible set as
  `conflict` rather than selecting a rule by registration order.
- Request-field views are an explicit resolver input. The current M3 transaction table keeps
  dispatch and operation summaries but not arbitrary decoded field snapshots, so an absent
  required view is `transaction_context_unusable`; the resolver never substitutes the other
  view.
- `src/concrete_edit.h` and the lower rebuild boundary in `src/edit.c` accept only an already
  resolved batch. They preflight every shape, span, same-boundary/overlap conflict, original
  precondition and final size before copying, then rebuild once in original canonical-payload
  coordinates. The legacy arm selector behavior remains above this shared byte-moving core.
- `src/mutation_apply.*` lowers a READY resolution to that deterministic batch. Preserve
  replacements of variable opaque/string values derive a live XDR length and zero padding;
  raw replacements change only their selected schema-proven span. The component checks the
  complete rebuilt bytes, re-decodes structure-safe output to verify every semantic target,
  and emits one last-fragment record only after re-parsing its framing successfully. Stale
  originals, structural inconsistencies and concrete conflicts return typed refusals without
  output. Rule registration permutations produce the same batch result and final bytes.
- `src/activation.*` owns one immutable, nonempty `rule_set_id` (at most 128 bytes) for a
  component session and excludes legacy registration for that session. A test-double gate must
  accept `GENERATION_OPEN` before one generation admits CALLs; deactivation closes CALL
  admission before submitting `GENERATION_DRAINING`. A rejected or missing draining ACK
  quarantines the lane permanently, while pending barriers use non-reusable tokens so late ACKs
  cannot reopen it. The callback is only a component test double and provides no durability.
- CALL admission returns the generation to pass to `nfsp_txn_call` plus a bounded, monotonic
  accounting ticket; only consuming that ticket as an inserted transaction adds reply debt.
  Deactivation closes CALL admission immediately but cannot submit its draining gate or close
  cleanly while a ticket is pending. Duplicate, stale and mismatched accounting is typed and
  cannot change counters. A forced abort cancels pending tickets and records each conservatively
  in `reply_unresolved_count`. A REPLY uses its transaction entry's generation, so admitted and draining
  generations are eligible while closed, unknown and generation-zero entries increment
  `outside_activation_window`. Connection-close accounting can satisfy a clean drain without
  claiming a resolved REPLY. Other missing replies block normal closure and require an explicit
  `reply_unresolved` or `aborted` forced-closure reason, which freezes the unresolved count.
- Generation snapshots are sorted by id and retain barrier, admission, reply and closure facts
  for future `GENERATION_COMPLETE` input. Defaults are 256 generation ids retained for the
  session, 16 simultaneous draining generations and 64 pending CALL-account tickets;
  configuration may lower these or raise either lifetime ids or pending tickets to 4096, with
  `max_draining <= max_generations`. Exhaustion refuses the operation rather than recycling a
  generation or ticket id.
- On its own the test gate satisfies none of the durability requirements. Target mode (next
  section) replaces it with the host sink and connects these components to `main`/`proxy`.

## Target mode: semantic Delta journal and live rules (M5)

[06 §28](../../docs/design/03-nfs-proxy/06-implementation-gap-analysis.md),
encodings in [05 §45](../../docs/design/03-nfs-proxy/05-mutation-delta-replay.md).

```sh
nfs-proxy CLIENT0 CLIENT1 K_LISTEN G_LISTEN K_BACKEND G_BACKEND \
    --target RULES.nfsprul1 --session-id ps-1 --journal /dev/virtio-ports/nfsp-journal \
    --lane 0 --activation /run/nfs-proxy/activation.sock [--drain-bound-ms 5000]
```

- `--target` installs one NFSPRUL1 rule set for the whole session and sends it as `RULESET`, the
  session's first journal event. `--control`, `--replay` and `--semantic` cannot be combined with it.
- `--journal` is the host channel: a virtio-serial port in a guest, or a Unix stream socket on the
  host (tests). `src/journal.c` sends one event at a time and waits for the host's answer.
- `--activation` is the executor's SOCK_SEQPACKET endpoint (wire format in `src/target.h`). An
  activate or deactivate request is answered only after the host stored `GENERATION_OPEN` or
  `GENERATION_DRAINING`. Keep the path out of reach of fuzzed programs.
- Mutated bytes leave only after the host stored their `EXPOSURE_INTENT`; a refused or lost intent
  sends the original record. The first hard refusal per generation and rule is stored as
  `APPLY_REFUSAL` before the refused record moves, and without a host answer it never moves.
- A held record stops only its own connection and direction. The final stats line starts with
  `target ruleset=...`, followed by a `journal ...` line.
- On exit the Proxy first settles every answer still owed and the events they queue, then sends
  `RUN_COMPLETE` last, and only when the session ended cleanly (every event ACKed, no event left
  unrecorded, no evidence-path failure, every opened generation summarized, every batch terminal).
  The sink also refuses `RUN_COMPLETE` (`session_dirty`) for a session with any recorded rejection. Otherwise the stats say `run_complete=skipped` and
  the Runner ends the session.

The host side is `agent_pipeline/journal_sink.py`:

```sh
python -m agent_pipeline.journal_sink --dir JOURNAL_DIR --name lane0 \
    --socket /run/knfsd-syzkaller/nfsp-journal.sock --vm vm-0 --channel nfsp-journal \
    --session ps-1 --lane 0 --rules RULES.nfsprul1
```

Run the same command again after a restart: it resumes the recovered session (and re-answers a
retransmitted event without storing it twice), and refuses to start if the binding, lane or rule
set differ.

`tests/agent_pipeline/test_journal_live.py` runs the built Proxy (with ASan when the compiler has
it) against this sink on loopback; `tools/nfs-proxy/build.sh` covers `test_journal` and the relay
hold hooks in `test_proxy`.

**KVM step (run by hand on a KVM host; not covered by CI).** Attach the guest port to the sink's
socket, start the sink before the VM, then run the Proxy in the guest with `--journal
/dev/virtio-ports/nfsp-journal`:

```sh
qemu-system-x86_64 ... \
    -device virtio-serial-pci,id=vser0 \
    -chardev socket,id=nfspj,path=/run/knfsd-syzkaller/nfsp-journal.sock,reconnect-ms=1000 \
    -device virtserialport,bus=vser0.0,chardev=nfspj,name=nfsp-journal
```

(QEMU older than 9.2 spells the option `reconnect=1`.) The guest Proxy binary from
`build-guest.sh` includes target mode. Nothing drives `--activation` from syzkaller yet: the
executor barrier is S1a, a separate syzkaller patch.

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
