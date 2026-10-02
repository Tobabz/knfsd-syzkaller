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
`env/images/bookworm-kcov-fresh.qcow2`, `env/syzkaller`).

Guest setup uses the baked boot service and a host lane script copied through a
read-only 9P share: `frozen-phase9-fixture.service` runs
`lane.sh setup /tmp/frozen-phase9.manager 4` at boot. The manager config pins
the script hash and selects the NFS minor in `vm.cmdline`; prepare it with
`tools/prepare-live-lane-config.py`. Run syz-manager with `procs` equal to the
lane count (4).
The default fixture routes every mount through the relay. `nfs-lane/client0` and
`nfs-lane/client1` remain two clients of the same knfsd export; Ganesha uses the
explicit `client0-ganesha` and `client1-ganesha` paths. The corpus contains four
NFSv4 inputs; NFSv3 is outside the current scope. The basic knfsd and Ganesha inputs each have one recorded KASAN v4.1 snapshot run.
The COPY input has one recorded KASAN v4.2 snapshot run; detailed callback and
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

Run knfsd and Ganesha as separate campaigns, one backend at a time. Each has
its own syz-manager config, workdir and `corpus.db`. Initialize a new DB from
only its backend's canonical 34-call seed; resume an existing DB without
repacking it. Do not merge these DBs, import the former combined corpus, or
connect the campaigns to a shared corpus hub.

| Backend | Initial seed | Client paths under `nfs-lane/` | `experimental.remote_cover` | Local HTTP endpoint |
| --- | --- | --- | --- | --- |
| knfsd | `basic-v41-tcp.prog` | `client0`, `client1` | `true` | `127.0.0.1:56753` |
| Ganesha | `basic-v41-ganesha-tcp.prog` | `client0-ganesha`, `client1-ganesha` | `false` | `127.0.0.1:56754` |

The current local campaigns are stored as:

```text
cache/manager-separated-v41-20261002/
+-- knfsd/
|   +-- manager.cfg
|   +-- inputs/basic-v41-tcp.prog
|   +-- workdir/corpus.db
|   +-- triage.log
+-- ganesha/
    +-- manager.cfg
    +-- inputs/basic-v41-ganesha-tcp.prog
    +-- workdir/corpus.db
    +-- triage.log
```

From the repository root, resume knfsd with:

```sh
env/syzkaller/bin/syz-manager -config cache/manager-separated-v41-20261002/knfsd/manager.cfg -mode fuzzing
```

Stop that manager and wait for shutdown before starting Ganesha:

```sh
env/syzkaller/bin/syz-manager -config cache/manager-separated-v41-20261002/ganesha/manager.cfg -mode fuzzing
```

Each local config uses `procs=4`, one KASAN VM snapshot, `cover=true`,
`cover_edges=true`, and `reproduce=false`. Enabled syscalls are
`open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`,
`statx`, `lseek`, `read`, `flock`, `renameat2`, and `unlinkat`.
Ganesha's current coverage feedback is from the local client kernel, not
Ganesha user-space code.

These validated configs pin the baked-script V15.6 v4.1 image
`env/images/bookworm-kcov-v41-ganesha-v15.6.qcow2`. For the reusable
`bookworm-kcov-fresh.qcow2` image, prepare each backend's config separately
with `tools/prepare-live-lane-config.py --minor 1`, as described in the
[root usage guide](../../../README.md#3-using-the-result-with-syz-manager).
The helper preserves the workdir and coverage settings. Changing only the
image path is insufficient for the reusable image's host-script boot model.
The cache configs and DBs are local artifacts, not committed repository assets.

Both separate managers completed `corpus-triage` with exit 0 and are stopped
after validation. The saved DBs were unpacked and checked for backend path
literals:

| Saved corpus | Programs | Own backend path | Opposite backend path | Both backend paths | Neither expected path |
| --- | ---: | ---: | ---: | ---: | ---: |
| knfsd | 100 | 22 | 0 | 0 | 78 |
| Ganesha | 109 | 20 | 0 | 0 | 89 |

Evidence: `cache/manager-separated-v41-20261002/{knfsd,ganesha}/triage.log`,
the corresponding `triage-unpacked/` directories, and `maintenance.json`
in the campaign root. These are bounded corpus checks, not proof that every
program reaches NFS or that long runs retain this distribution.

Separate managers do not splice programs from each other's corpus. Ordinary
generation, path mutation and minimization remain enabled: calls or paths may
disappear, and another path can still be generated. The fixture still exposes
both backend mount pairs, so separation does not enforce backend-only execution.
An absent path literal alone does not prove that a program cannot reach NFS.
The two campaigns also do not produce identical mutations or paired replay.

The earlier shared-manager experiment is retired. Its two runtime DBs under
`cache/manager-unified-v41-20261002/{workdir,workdir-focused}/corpus.db` and
two admission-test DBs under
`cache/manager-corpus-v41-20261002/{workdir,workdir-four}/corpus.db`
were deleted on 2026-10-02. Their configs and logs remain historical evidence;
do not resume those configs or repack their combined inputs. The initial
180-second shared-manager smoke recorded 7,791 executions, but subsequent
inspection found mixed-backend programs; it is not the current operating model.

The combined 34+34-call draft remains withdrawn because the pinned manager
rejects programs over 40 calls. Proxy-managed backend selection is deferred;
the existing fixed relay paths remain in place. See the
[design decision](../../../docs/design/01-overview/01-overview.md#backend-execution-decision).

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
`cache/backend-current-v42-20261002/copy`. Those runs used earlier images that have since been removed. Each used a
QEMU snapshot with one syz-execprog execution and `-threaded=false`.
The current reusable V15.6 image is `env/images/bookworm-kcov-fresh.qcow2`. B05 remains byte-identical to its historical
input. Its default-mode acceptance is the compatibility contract; strict mode
rejects the legacy offset strings and is intentionally not made green by an
untested behavioral rewrite.

Ganesha V15.6의 이전 검증에서는 `basic-v41-ganesha-tcp.prog`를 당시 v4.2 이미지
`env/images/bookworm-kcov-fresh-v2.qcow2`에서 다시 실행했다.
파일명은 기존 v4.1 시드의 이름을 유지하지만, 이번 실행의 두 Ganesha 마운트는
v4.2이다. 34개 호출이 모두 완료됐고 14번 호출의 기대 errno 11을 제외한
호출은 errno 0이었다. KCOV 커버리지도 양수였으며, 같은 스냅샷에서 프록시의
`READ_PLUS` 호출과 직접 연결의 교차 읽기·쓰기, 정리까지 확인했다.

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
