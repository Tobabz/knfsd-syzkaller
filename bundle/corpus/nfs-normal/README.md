# Normal NFS syzkaller corpus

This directory is a small parser-checked corpus assembled from the reusable
inputs audited in `report/normal-flow-corpus.md`. The `.prog` files are copied
by value: there are no links back to the Wave1 or Wave3 source worktrees. `manifest.json` is the
machine-readable contract and records source hashes, NF flows, protocol,
transport, guest setup, functional oracle, current execution status, exclusions, and gaps.

> **Status note (2026-10-01).** The A/B harness, the NF-A1 and B06 observers and the attribution
> scenario runner that produced the runtime evidence cited below were removed in commit `7833ed3`.
> The evidence statements stay as records of what those runs showed; seeds are run with a stock
> syz-manager.

Paths to files inside this repository, here and in `manifest.json`, are relative to the
repository root. The kernel/image environment is `env/` (`env/images/<variant>/{bzImage,vmlinux}`,
`env/images/bookworm-kcov-fresh-v1.qcow2`, `env/syzkaller`).

Guest setup comes from the baked image: `frozen-phase9-fixture.service` runs
`lane.sh setup /tmp/frozen-phase9.manager 4` at boot, with the NFS minor version chosen by
`bootstrap --minor N`. Run syz-manager with `procs` equal to that lane count (4).
The default fixture routes every mount through the relay. `nfs-lane/client0` and
`nfs-lane/client1` remain two clients of the same knfsd export; Ganesha uses the
explicit `client0-ganesha` and `client1-ganesha` paths. The corpus contains four
NFSv4 inputs; NFSv3 is outside the current scope. The basic knfsd and Ganesha inputs each have one current KASAN v4.1 snapshot run.
The COPY input has one current KASAN v4.2 snapshot run; detailed callback and
handoff records refer to earlier fixtures.

Parser success only proves that the pinned syzkaller parser can deserialize an
input. It does not prove mount setup, an NFS reply, a background transition,
KCOV collection, cleanup, or functional success. The lane fixture changed after
the historical VM runs; the basic seed has been restored to its original 34 calls.
The current basic runs verify 34 call results on the updated v4.1 image. The
knfsd raw `.extra` contains 77,314 PC records, including 1,581 distinct
`fs/nfsd` source locations. Ganesha produced local client-kernel coverage
files, but no `.extra` or Ganesha user-space coverage. These runs do not
establish repeatability or a server-side RPC handoff trace.

## Execution scope (2026-10-02)

Use one syz-manager corpus with two separate 34-call inputs for v4.1 fuzzing.
The knfsd input uses the default client pair; `basic-v41-ganesha-tcp.prog`
uses the explicit Ganesha client pair. Each input keeps both clients on one
backend. The original functional checks ran the two inputs sequentially in
separate KASAN v4.1 VM snapshots. A shared manager does not provide paired
replay or identical mutations across backends. The four-mount guest check
passed on both current v4.1 and v4.2 images, including the default aliases
and backend isolation (`cache/four-mount-check-20261002/result.json`).

The combined 34+34-call draft was withdrawn: the pinned manager rejects programs
with more than 40 calls. Both separate 34-call inputs were packed into an isolated
`corpus.db`; syz-manager admitted both records and completed `corpus-triage`
with `procs=4` (exit 0). The manager may minimize inputs during fuzzing, so this admission
does not guarantee that an unmodified 34-call oracle remains in the output corpus.
Evidence: `cache/manager-corpus-v41-20261002/result.json` and `manager.log`.
For the first bounded fuzzing run, pack only these two basic inputs into one
`corpus.db` and use one manager with `procs=4`, the KASAN v4.1 image,
`experimental.remote_cover=true`, and `enable_syscalls` limited to
`open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`, `statx`,
`lseek`, `read`, `flock`, `renameat2`, and `unlinkat`. The local configuration
is `cache/manager-unified-v41-20261002/manager-focused.cfg`. Resume its
corpus with:

```sh
env/syzkaller/bin/syz-manager -config cache/manager-unified-v41-20261002/manager-focused.cfg -mode fuzzing
```

A 180-second smoke completed 7,791 executions without a recorded crash or fatal error.
The saved corpus retained both canonical 34-call seeds and additional programs
using each backend path (`focused-smoke.json`, `corpus-inspection.json`).
This is a bounded check, not evidence of long-run stability or equivalent
server-side coverage. An earlier unrestricted manager run reported two fixed
lane executor hangs; its crash logs show non-NFS programs near the failures.
Evidence is in `fuzz-smoke.log` and the matching `workdir/crashes/` directory.

Proxy-managed backend selection is deferred; the existing fixed relay paths
remain in place. See the [design decision](../../../docs/design/01-overview/01-overview.md#backend-execution-decision).

## Intended scenarios -> corpus contract

Each intended scenario/backend pair has one `.prog` in this directory. The baked image's fixture sets the
NFS version and mount topology; a parser PASS alone does not execute it.
`NF-*` identifies targeted source flows, not proof that every transition or
its KCOV was observed.

| Intended scenario | Corpus input | Target flow and observed limit |
| --- | --- | --- |
| Two-client v4.1/TCP file operations and lock conflict | `basic-v41-tcp.prog` | Current KASAN v4.1 image passed all 34 calls; raw `.extra` contains 1,581 distinct `fs/nfsd` locations. Earlier fixture has separate historical evidence. |
| Same v4.1/TCP file operations against Ganesha | `basic-v41-ganesha-tcp.prog` | One separate KASAN v4.1 snapshot run passed the 34-call errno oracle. No knfsd NF-A1/A2 or Ganesha internal-coverage claim. |
| v4.2/TCP asynchronous 32 MiB COPY and CB_OFFLOAD | `async-copy-v42-tcp.prog` | Current KASAN v4.2 image passed one 11-call snapshot run with a 32 MiB copy return and nonempty `.extra`; callback and NF-A1 handoff evidence remain historical. Strict parser mode rejects legacy line-7 offset strings. |
| Two-client v4.1/TCP delegation grant, conflict and CB_RECALL | `delegation-recall-v41-tcp.prog` | Fresh paired v4.1/TCP VM PASS for 15-call functional input and two observed delegation-recall/callback/backchannel-service chains per mode. Full NF-D2 xprtiod receive-to-queue transition and DELEGRETURN are not separately traced. |

NF-B1, NF-B2 and NF-E1 through NF-E5 have no matching normal `.prog` and
event-armed fixture; the exclusions and unsupported transports are enumerated
below and in `manifest.json`. No generated test file is an extra corpus input.

## NF-A1 remote-KCOV stage presence

The original request-owned remote KCOV begins inside `svc_process`, after the
socket callback, transport enqueue and nfsd dequeue. The kernel series patch
`0013-sunrpc-observe-NFSD-transport-stages-with-remote-KCOV` (previously a separate
`nfa1-remote-kcov` worktree) adds
global handle `0x0200000000000001` for **observational** NFSD coverage. It
brackets softirq `svc_data_ready` through `svc_xprt_enqueue` and the nfsd
`svc_xprt_dequeue` window; the existing checked request ticket still owns
`svc_process` and all managed `.extra` files. No legacy observational PC is
merged into a managed generation.

The standalone guest observer (`nfa1-kcov-observer.c`) and the adapter that measured stage presence
were removed in commit `7833ed3`. This section records the earlier patch series;
the current series is listed in `bundle/patches/kernel/series`.

The last recorded paired V2 run (its evidence directory has since been removed) passed:
OFF collected 16,053 observer PCs across the three transport stages and
zero managed PCs; ON collected 13,065 observer PCs with all three stages
present and 721,547 managed PCs including `svc_process`. Both observer
buffers were unsaturated. The first V1 OFF attempt saturated its buffer
while an unnecessary full `svc_process` observer was active; that hook was
removed before V2. V2 checked starts/stops balanced at 68/68; the original
image was unchanged, teardown was clean, and KCSAN reported two findings
in each mode. These are guest-wide **stage-presence** PCs, not a same-request
handoff, sequence proof, per-lane attribution, or sanitizer-clean result.
Softirq observation can skip an interrupted managed ticket; task-context
data-ready callbacks are outside this observer's bracket. Missing PCs
therefore do not prove nonexecution.

## Inputs

| Input | NF flow | Version / transport | Fixture and guest setup | Functional expected result | Current status |
| --- | --- | --- | --- | --- | --- |
| `basic-v41-tcp.prog` | NF-A1, NF-A2 | 4.1 / TCP | `bundle/lane/lane.sh` — baked image (bootstrap --minor 1): frozen-phase9-fixture.service runs lane.sh setup /tmp/frozen-phase9.manager 4 at boot | All 34 calls finish on each execution; call 14 is the deliberate peer-lock conflict and returns errno 11, every other call returns errno 0, local KCOV is positive, and create/write/read/rename/unlink effects succeed across both mounts. | Current KASAN v4.1 image passed all 34 calls; raw `.extra` contains 77,314 records and 1,581 distinct `fs/nfsd` locations. |
| `basic-v41-ganesha-tcp.prog` | — (Ganesha user-space server) | 4.1 / TCP | `bundle/lane/lane.sh` — same four-lane v4.1 image, explicit Ganesha client paths | All 34 calls finish; call 14 returns errno 11 and other calls return errno 0; local kernel client KCOV is present. | One 2026-10-02 KASAN v4.1 snapshot run passed the errno oracle; no Ganesha internal coverage or RPC handoff trace. |
| `async-copy-v42-tcp.prog` | NF-A1, NF-A2, NF-C1, NF-D1 | 4.2 / TCP | `bundle/lane/lane.sh` — baked image (standalone baker --minor 2): frozen-phase9-fixture.service runs lane.sh setup /tmp/frozen-phase9.manager 4 at boot | copy_file_range returns 33554432, async execution reaches nfsd4_do_async_copy, CB_OFFLOAD completes with status 0, and destination fsync and closes finish. | Current KASAN v4.2 image passed 11 calls and returned 32 MiB from copy_file_range with nonempty `.extra`; callback and handoff evidence remain historical. Strict parser mode rejects legacy line-7 offset strings. |
| `delegation-recall-v41-tcp.prog` | NF-A1, NF-A2, NF-D3, NF-D1, NF-D2 | 4.1 / TCP | `bundle/lane/lane.sh` — baked image (bootstrap --minor 1): frozen-phase9-fixture.service runs lane.sh setup /tmp/frozen-phase9.manager 4 at boot | First prove delegation grant; then the client1 conflict must produce ordered CB_RECALL queue/start, backchannel service, callback ACK/status 0, and delegation return/close. File effects alone do not pass. | Fresh paired v4.1/TCP VM PASS for 15-call functional input and two observed delegation-recall/callback/backchannel-service chains per mode. Full NF-D2 xprtiod receive-to-queue transition and DELEGRETURN are not separately traced. |

The fixtures are disposable-VM-only; they run inside the baked guest, never on the host.

## Parser contract

The parser is `env/syzkaller/bin/syz-prog2c`; its binary SHA256 and source
checkout are recorded in `manifest.json`. Each file is checked with:

```
env/syzkaller/bin/syz-prog2c -os linux -arch amd64 -prog ABSOLUTE_INPUT_PATH
```

Generated C byte counts and hashes, and the exact nonfatal formatter stderr,
are stored in `manifest.json`. The 2026-10-02 run evidence is under
`cache/backend-current-v41-20261002/{knfsd,ganesha}` and
`cache/backend-current-v42-20261002/copy`. The v4.1 runs used
`env/images/bookworm-kcov-fresh-v1.qcow2` and the v4.2 run used
`env/images/bookworm-kcov-fresh-v2.qcow2`, each through a QEMU snapshot with
one syz-execprog execution and `-threaded=false`. B05 remains byte-identical to its historical
input. Its default-mode acceptance is the compatibility contract; strict mode
rejects the legacy offset strings and is intentionally not made green by an
untested behavioral rewrite.

## Gaps and exclusions

| Missing flow or boundary | Why it is a gap rather than a `.prog` |
| --- | --- |
| NF-B1 defer/revisit | No reusable `.prog` contract exists. Clean Wave1 Gate8 has a bounded historical predecode auth-unix-ip single-defer PASS (created/restored/grant/start/completed each 1, redeferred 0, operation bytes 20), but it is a C-helper six-case runner, not a `.prog` or a new corpus run. B04's forced redefer hook is not normal flow. |
| NF-B2 cache cleaner; NF-E1 laundromat; NF-E2 reaper; NF-E3 filecache GC; NF-E3b disposal; NF-E4 nfsdcld; NF-E5 pNFS | There is no concrete event-armed fixture plus functional oracle. A syscall that merely waits or creates incidental state would fake coverage. |
| NF-D2 full boundary, NF-D3 DELEGRETURN | B06 r3 OFF+ON paired PASS confirms NF-D2 svc_process_bc dispatch (svc_process_bc_entry x20, record_backchannel delta=20) and NF-D3 delegation recall chain (delegation_grant_observed, complete_recall_chain_observed, matched_recalls=2), independently confirmed by gate st_01a0e689. ON remote KCOV has 294,223 PCs; svc_process_bc absent but execution proved by trace. The full xprtiod->backchannel queue physical boundary remains a gap because the trace captures svc_process_bc_entry but not xs_stream_data_receive_workfn or xprt_complete_bc_request individually. DELEGRETURN is not separately traced. |
| NFSv2 | Disabled in the pinned build. |
| UDP | Fixtures are TCP-only. |
| RPC-over-RDMA | No device or provisioned fixture exists. |
| LOCALIO | Compiled but disabled; no input or fixture exists. |
| NAT | Direct-veth operation does not establish address-rewritten pairing. |

The bounded Gate8 reference above is historical evidence from the phase8 runner, which was removed
in commit `7833ed3`. The v4.2 fixture's presence of an `nfsdcld` binary is not an NF-E4 fixture: there is no
before-fixture probe, so NF-E4 remains a gap.

Wave3 B07 is excluded because it is byte-identical to B05 and only its forced
owner-window runner changes the experiment. Wave3 B12 is excluded because its
`.prog` is only `getpid()` and all NFS traffic comes from a forced retry hook.

## Adversarial boundary

- Out of scope (v3): the NFSv3 seed and its fixture were removed. The lane carries every NFS
  connection through the relay, which handles NFSv4 only, and the v3 fixture never completed setup
  (rpcbind registration failed with `errno 107`; the root cause was not established).
- Historical Wave3 assets: B04 and its v3 fixture are no longer shipped. B06's
  recorded r3 paired PASS used the earlier Wave1 fixture and was independently
  confirmed by gate st_01a0e689; it is provenance, not a new-image validation.
- Misleading parser success and malformed programs: every included file must
  exit 0 under the pinned non-dry-run command, but that result is syntax only.
- Cleanup: runtime VM attempts used the runner's strict fixture cleanup and
  drain checks. Host teardown receipts confirm no QEMU/listener residue for
  completed runs. Fresh corpus assembly changes no VM state.
- B06 confirmed: r3 OFF+ON both PASS with complete recall chains, independently
  confirmed by gate st_01a0e689 (`B06-r3-runtime-gate.md`). ON shows
  OBSERVED_OWNERLESS_KCOV with 294,223 remote PCs; svc_process_bc absent from
  KCOV but execution proved by trace. The full xprtiod->backchannel queue
  physical boundary is not claimed. DELEGRETURN not separately traced. Parser
  accepts 3 malformed synthetic classes; actual r3 passes independent checks.
- KCSAN nonclean: every run that produced KCSAN reports has at least one
  (R2 COPY 2, basic v4.1 ON 1, B05 CORPUS OFF 2, B06 r3 OFF 1). No result
  is labeled sanitizer-clean.
- Static-input timing is N/A: the `.prog` and metadata files add no sleep, polling loop,
  or wait-based fixture. Security, concurrency-policy, and UI classes are N/A
  because these are static syzkaller inputs and metadata only.
