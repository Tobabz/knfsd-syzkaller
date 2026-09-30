# Normal NFS syzkaller corpus

This directory is a small parser-checked corpus assembled from the reusable
inputs audited in `report/normal-flow-corpus.md`. The `.prog` files are copied
by value: there are no links back to the Wave1 or Wave3 source worktrees. `manifest.json` is the
machine-readable contract and records source hashes, NF flows, protocol,
transport, exact fixture path/guest setup command, functional oracle, current
execution status, exclusions, and gaps.

Paths to files inside this repository, here and in `manifest.json`, are relative to the
repository root (`runner_working_directory` is `.`); run the commands from the root. The
kernel/image environment is `env/` (`env/images/<variant>/{bzImage,vmlinux}`,
`env/images/bookworm-kcov-fresh-v1.raw`, `env/syzkaller`); change that prefix if the
environment lives elsewhere.

Parser success only proves that the pinned syzkaller parser can deserialize an
input. It does not prove mount setup, an NFS reply, a background transition,
KCOV collection, cleanup, or functional success. No kernel, image, fixture,
descriptor, or runner source was changed while assembling this directory. VMs
were run separately for runtime evidence; results are cited per input below.

## Intended scenarios -> corpus contract

Each intended scenario has one `.prog` in this directory. Its fixture sets the
NFS version and mount topology; a parser PASS alone does not execute it.
`NF-*` identifies targeted source flows, not proof that every transition or
its KCOV was observed.

| Intended scenario | Corpus input and consumer | Target flow and observed limit |
| --- | --- | --- |
| Two-client v4.1/TCP file operations and lock conflict | `basic-v41-tcp.prog` via `tools/run-ab.sh` and `tools/ab-lane-fixture.sh` (2 lanes) | NF-A2 succeeds in paired VM trials (34 calls, expected conflict at call 14); local and remote KCOV collected. NF-A1's socket-to-nfsd handoff was **not** directly witnessed for this input. |
| v4.2/TCP asynchronous 32 MiB COPY and CB_OFFLOAD | `async-copy-v42-tcp.prog` bound by `B05-V1.json` to `ab-lane-fixture-v42.sh`; R2 witness reuses the same input | NF-A2, NF-C1 and COPY-completion NF-D1 observed in paired B05 VM trials; NF-A1 transport handoff observed separately in R2 ON. Remote KCOV collected, but callback-worker PCs are absent from on-only coverage; KCSAN reports remain. |
| Two-client v4.1/TCP delegation grant, conflict and CB_RECALL | `delegation-recall-v41-tcp.prog` via `tools/run-reach-adapted-window.py --callback-observer b06-recall` and `tools/ab-lane-fixture.sh` (1 lane) | NF-D3 recall, NF-D1 callback work and NF-D2 `svc_process_bc` dispatch observed in paired r3 VM trials; ON remote KCOV collected without a `svc_process_bc` PC. NF-A1 transport ingress, earlier NF-D2 receive/queue, and separate DELEGRETURN are **not** established. |
| v3/TCP simple fixture-file read | `basic-read-v3-tcp.prog`; fixture vendored as `ab-lane-fixture-v3.sh` (copied from the former Wave3 B04, unverified) | NF-A1/NF-A2 are intended only. The input parses, but fixture setup failed before workload: no functional VM PASS, handoff witness or KCOV claim. It does not exercise NF-B1 defer/revisit. |

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

`nfa1-kcov-observer.c` is the standalone guest KCOV controller. The
`nfa1-kcov-presence.py` adapter starts it after fixture setup, stops it after
the workload and managed drains, and keeps its raw PCs and metadata **outside**
the executor's `coverage/` archive. Build a static controller and use the
KCSAN kernel built from the full series with the original snapshot image:

```sh
K=env/images
gcc -static -O2 -std=gnu11 -Wall -Wextra -Werror \
    -o "$K/nfa1-kcov-observer" bundle/corpus/nfs-normal/nfa1-kcov-observer.c
python3 -B bundle/corpus/nfs-normal/nfa1-kcov-presence.py \
    --observer-binary "$K/nfa1-kcov-observer" \
    --kernel "$K/kcsan/bzImage" --vmlinux "$K/kcsan/vmlinux" \
    --image "$K/bookworm-kcov-fresh-v1.raw" \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps.tar.gz \
    --lane-fixture bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh \
    --workload bundle/corpus/nfs-normal/async-copy-v42-tcp.prog \
    --syz-bin env/syzkaller \
    --mode both --trials 1 --executions 10 --sample-every 10 \
    --procs 2 --cpus 8 --memory 8192 --output <new-absolute-output-path>
```

The fresh paired V2 run at
`/home/idealinsane/normal-flow-evidence/NF-A1-KCOV-V2-20260928/` passed:
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

| Input | NF flow | Version / transport | Fixture and exact guest setup | Functional expected result | Current status |
| --- | --- | --- | --- | --- | --- |
| `basic-v41-tcp.prog` | NF-A1, NF-A2 | v4.1 / TCP | `tools/ab-lane-fixture.sh`; `/opt/frozen-phase9/lane.sh setup /tmp/frozen-phase9.<RUNNER_RANDOM> 2`; integrated entry point: `tools/run-ab.sh` | All 34 calls finish each execution; call 14 alone returns errno 11; all others return 0; positive local KCOV and the create/write/read/rename/unlink effects are required. | **VM PASS**: `/home/idealinsane/normal-flow-evidence/NF-A1-A2-basic-v41-tcp-v1/` records OFF+ON paired PASS, v4.1/TCP, 4 vCPUs, 2 lanes, 34 calls, 1 execution, expected_lock_conflicts=1, 53 nfsd RPCs each mode. Confirms NF-A2 functional success. No NF-A1 transport witness was captured, so physical handoff is not proven at v4.1. KCSAN: ON 1 report, OFF 0. Host teardown clean. |
| `async-copy-v42-tcp.prog` | NF-A1, NF-A2, NF-C1, COPY-completion NF-D1 | v4.2 / TCP | `bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh`; `/opt/frozen-phase9/lane.sh setup /tmp/frozen-phase9.<RUNNER_RANDOM> 2`; from the main root run `/usr/bin/python3 tools/attr-scenario-run.py --scenario bundle/corpus/nfs-normal/B05-V1.json --output /home/idealinsane/attr-scenario-evidence/<unique-normal-B05-run>` | `copy_file_range` returns 32 MiB, `nfsd4_do_async_copy` runs, CB_OFFLOAD completes with status 0, then destination fsync and closes finish. | **VM PASS**: B05 CORPUS fresh paired run at `/home/idealinsane/attr-scenario-evidence/NORMAL-B05-CORPUS-20260928/` consumed this corpus-local scenario, workload, and fixture; it records overall PASS, all 21 checks, 10 executions each mode, on-only fs/nfsd 1,421 unique PCs, remote_start_ok=68, generation_committed=11. R2 COPY at `/home/idealinsane/normal-flow-evidence/NF-A1-COPY-20260928-R2/` confirms 10x 32 MiB returns, NF-A1 transport witness (assert=true, independently confirmed by st_01a0e678), and 10/10 callback deliveries (ON-only, 8 vCPUs, 2 lanes). The runner does not consume `nfs-normal/manifest.json`; the original B05 scenario is a byte-identical alternate baseline, not this run's binding. `nfsd4_run_cb_work` absent from on-only KCOV. KCSAN: B05 CORPUS OFF 2 reports; R2 ON 2 reports. Historical B05-V1-g703-20260927 retained as audited baseline. Strict mode's known line-7 `wrong string arg` is not repaired without a VM test. |
| `delegation-recall-v41-tcp.prog` | NF-A1, NF-A2, NF-D3, NF-D1, NF-D2 | v4.1 / TCP | Main fixture `tools/ab-lane-fixture.sh`; `/opt/frozen-phase9/lane.sh setup /tmp/frozen-phase9.<RUNNER_RANDOM> 1` | All 15 calls (indexes 0-14) finish with errno 0. Separately prove delegation grant before conflict, then ordered CB_RECALL queue/start, backchannel service, callback ACK/status 0, and return/close. File effects alone are insufficient. | **VM PASS**: r3 at `/home/idealinsane/normal-flow-evidence/B06-V1-delegation-recall-v41-r3/` records OFF+ON paired PASS, v4.1/TCP, 8 vCPUs, 1 lane, 1 proc, 15 calls, 10 executions. Both b06-verdict files show assert=true, delegation_grant_observed=true, complete_recall_chain_observed=true, matched_recalls=2, record_backchannel delta=20 (0 before, 20 after). ON status OBSERVED_OWNERLESS_KCOV: 294,223 remote PCs in ten extras; svc_process_bc absent from KCOV but execution proved by svc_process_bc_entry x20 in the trace. Functional: 150 calls, all errno 0. KCSAN: OFF 1 report, ON 0. Independently confirmed by gate st_01a0e689 (`B06-r3-runtime-gate.md`) with server-to-client stateid CRC validation. DELEGRETURN not separately traced. Full xprtiod->BC queue boundary not claimed. Parser accepts 3 malformed synthetic classes; actual r3 passes independent checks. Historical r2 OFF-only preliminary evidence superseded by this r3 paired run. |
| `basic-read-v3-tcp.prog` | NF-A1, NF-A2 only | v3 / TCP forechannel and TCP mount protocol | Vendored fixture `bundle/corpus/nfs-normal/ab-lane-fixture-v3.sh` (SHA-256 93edf872c6173aede8a30abede8f983470123309337bb7f5fc81d42146a4a7ab); `/opt/frozen-phase9/lane.sh setup /tmp/frozen-phase9.<RUNNER_RANDOM> 1` | Open `nfs-lane/client0/shared/fixture`, read its 30-byte `frozen Phase 9 lane 0 fixture\n` content into the 128-byte buffer, return 30, and close successfully. This input does not prove NF-B1. | Parser-only; Wave3 B04 fixture attempts r4-r11 failed setup before workload, and the vendored fixture remains blocked/unverified. |

Invoke the B06 runner with `KOOV_EXPECTED_CALLS=15 KOOV_CONFLICT_CALL=-1` and `--callback-observer b06-recall`; the shared AB defaults remain 34 calls with conflict call 14.

`<RUNNER_RANDOM>` is the alphanumeric suffix produced by the runner's
`mktemp -d /tmp/frozen-phase9.XXXXXX`; the resulting full path is passed
verbatim. The host fixture is copied into the guest as
`/opt/frozen-phase9/lane.sh` before that command. Cleanup is runner-owned and
must call the same fixture's `cleanup` action for the allocated root; no manual
host invocation is valid because these fixtures are disposable-VM-only.

## Parser contract

The required parser is
`env/syzkaller/bin/syz-prog2c`, SHA256
`ae5e6c3b2c31d340265088e28835103dedbb8441b7b874f281353604e59ac533`,
from checkout `8c1901085e70fcfd88acdcc934410c79fbf27e1b`. Each file is checked with:

```
env/syzkaller/bin/syz-prog2c -os linux -arch amd64 -prog ABSOLUTE_INPUT_PATH
```

Generated C byte counts and hashes, and the exact nonfatal formatter stderr,
are stored in `manifest.json`. B05 remains byte-identical to its historical
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
| UDP | Fixtures are TCP-only; no source-backed UDP NFSv3 execution contract exists. |
| RPC-over-RDMA | No device or provisioned fixture exists. |
| LOCALIO | Compiled but disabled; no input or fixture exists. |
| NAT | Direct-veth operation does not establish address-rewritten pairing. |

The bounded Gate8 reference above is
`/home/idealinsane/frozen-gate8-baked-evidence12/phase8-evidence.json` (historical
PASS 28/28). Its exact clean-Wave1 runner command is:

```
/usr/bin/python3 bundle/ab-runner/phases/run_frozen_phase8_vm.py --kernel env/images/kcsan/bzImage --image env/images/bookworm-kcov-fresh-v1.raw --ssh-key artifacts/bookworm.id_rsa --deps-tar bundle/src/guest-deps.tar.gz --lane-script tools/ab-lane-fixture-gate8.sh --output <unique>
```

That command runs six cases and has no single-case selector. The v4.2 fixture's
presence of an `nfsdcld` binary is not an NF-E4 fixture: there is no before-fixture
probe, so NF-E4 remains a gap.

Wave3 B07 is excluded because it is byte-identical to B05 and only its forced
owner-window runner changes the experiment. Wave3 B12 is excluded because its
`.prog` is only `getpid()` and all NFS traffic comes from a forced retry hook.

## Adversarial boundary

- Known unresolved (v3): `ab-lane-fixture-v3.sh` does not complete setup. NFSv3 and lockd fail to
  register with rpcbind (kernel `errno 107` in Wave3 attempts r4-r10), so the fixture's final
  `rpcinfo ... 100003 3` check fails. Root cause is not established; the private-`/run` rpcbind
  hypothesis is unverified. The vendored file is the Wave3 r11 fixture with its tracefs hist-trigger
  diagnostics removed (SHA-256 93edf872c6173aede8a30abede8f983470123309337bb7f5fc81d42146a4a7ab). It is unrun in this tree. v3 stays out of the
  runnable corpus until a VM run passes fixture setup and the workload.
- Stale external Wave3 assets: B04 program bytes and its v3 fixture are now copied by value and hashed, but
  the fixture is not called runnable. B06 uses the verified Wave1
  fixture and has r3 paired PASS, independently confirmed by gate st_01a0e689.
- Selective integration: Wave3 remains provenance-only and unchanged. The copied
  artifacts now live under this directory in dirty main; their source bytes remain fingerprinted in the Wave1 gate.
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
