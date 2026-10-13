# Validation and project history

This document preserves campaign results, evidence locations and repository changes.
It is a historical record; current setup and operation are described in the
[root README](../README.md) and [corpus guide](../bundle/corpus/nfs-normal/README.md).

## Execution scope (2026-10-02)

The campaign configs and DBs below were uncommitted local artifacts. They were absent
from the checkout during the 2026-10-08 documentation review, so their effective settings
and results could not be independently rechecked. The commands require those original artifacts.

| Backend | Initial seed | Client paths under `nfs-lane/` | `experimental.remote_cover` | Local HTTP endpoint |
| --- | --- | --- | --- | --- |
| knfsd | `basic-v41-tcp.prog` | `client0`, `client1` | `true` | `127.0.0.1:56753` |
| Ganesha | `basic-v41-ganesha-tcp.prog` | `client0-ganesha`, `client1-ganesha` | `false` | `127.0.0.1:56754` |

The recorded local campaigns were stored as:

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

The record describes `procs=4`, one KASAN VM in program snapshot mode, `cover=true`,
`experimental.cover_edges=true`, and `reproduce=false`. The listed enabled syscalls are
`open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`,
`statx`, `lseek`, `read`, `flock`, `renameat2`, and `unlinkat`.
Ganesha's current coverage feedback is from the local client kernel, not
Ganesha user-space code.

Program snapshot mode runs one program at a time with one proc. The recorded campaigns
therefore provide no validation of parallel lanes. Parallel execution requires the manager's
top-level `snapshot` to be `false` (or absent). The separate `vm.snapshot` setting defaults
to `true` and makes QEMU's disk writes temporary; it does not control program snapshot mode.
Completed four-lane checks and the remaining manager validation gap are described in
[parallel-lane verification](#parallel-lane-verification).

The recorded configs pinned the baked-script V15.6 v4.1 image
`env/images/bookworm-kcov-v41-ganesha-v15.6.qcow2`. For the reusable
`bookworm-kcov-fresh.qcow2` image, prepare each backend's config separately
with `tools/prepare-live-lane-config.py --version 4.1`, as described in the
[root usage guide](../README.md#3-using-the-result-with-syz-manager).
The helper preserves the workdir and coverage settings. Changing only the
image path is insufficient for the reusable image's host-script boot model.
The cache configs and DBs are local artifacts, not committed repository assets.

The record reports that both separate managers completed `corpus-triage` with exit 0 and were stopped
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


## Parallel-lane verification

The bounded four-lane guest check is complete. Its saved results were rechecked on 2026-10-08;
this review did not start a new VM or fuzzing campaign.

| Scope | Evidence and status |
| --- | --- |
| KASAN proxy check, 2026-10-02 (`de348e5`) | `syz-execprog` with four procs completed 30 executions with exit 0. Saved `.extra` files are nonempty in 30/30 cases; lane 0–3 are healthy; per-lane edit counts are 8/7/7/8. Recorded proxy errors, fatal dmesg entries, `generation_aborted` and `outstanding_tokens` are all zero. |
| Callback attribution, 2026-10-05 | The [decision record](../docs/design/decisions/2026-10-05-callback-attribution.md#검증) reports four-lane mixed-program checks on KASAN and KCSAN. It states that raw evidence was not retained, so these results could not be independently rechecked here. |
| Parallel `syz-manager` campaigns | The [earlier lane-attribution record](../docs/design/decisions/2026-10-01-lane-attribution.md#실험-kasan-syz-execprog-프로그램-30회) reports a ten-minute, four-lane manager run. That record states its raw evidence was not retained; the effective snapshot settings and later campaign topology could not be rechecked. It does not establish long-run stability of the later configuration. |

The retained proxy evidence is local to the original host:
`~/prune-evidence/proxy-kasan-4lane-final/raw/`. It contains `result.json`,
`phase1-evidence.json`, `cov/*.extra`, per-lane proxy logs and `dmesg.txt`.
The [handoff record](../docs/handoff/proxy-variable-length-edits/handoff.md)
describes the tested fixture and remaining coverage gaps. These checks used that run's kernel
and fixture; they do not certify later changes or every proxy edit type.


## Seed execution records

The following table preserves the reported execution results. Seed hashes and per-input
metadata are in the [corpus manifest](../bundle/corpus/nfs-normal/manifest.json).

| Input | Target | Functional oracle | Recorded execution scope |
| --- | --- | --- | --- |
| `basic-v41-tcp.prog` | knfsd v4.1/TCP, two clients | 34 calls; peer lock conflict at call 14 returns errno 11, other calls return 0; create/read/write/rename/unlink work across both mounts | One KASAN snapshot passed; knfsd remote `.extra` was nonempty. No request handoff trace. |
| `basic-v41-ganesha-tcp.prog` | Ganesha v4.1/TCP, two clients | Same 34-call errno and file-operation oracle | One KASAN snapshot passed; client-kernel KCOV was present. Ganesha user-space coverage was not collected. |
| `async-copy-v42-tcp.prog` | knfsd v4.2/TCP COPY | 11 calls, 32 MiB `copy_file_range` return and successful close/fsync | An earlier KASAN snapshot passed with nonempty `.extra`. A separate 2026-10-05 trace recorded COPY and callback transitions (S3 in the thread report). |
| `delegation-recall-v41-tcp.prog` | knfsd v4.1/TCP delegation conflict | Delegation grant, ordered recall, client ACK and return | One KASAN execution on 2026-10-05; the recall and return chain over the session backchannel was observed in trace events (S3b in the thread report). |
| `basic-v3-tcp.prog` | knfsd v3/TCP, two clients | 25 calls, all errno 0. No `flock`: the v3 mounts use `nolock`, so `flock` is client-local and no peer conflict occurs. | One KASAN execution on 2026-10-05 completed 25 calls. Thread transitions S1-01 to S1-11 were observed. NLM locking is not reached (`nolock`, no `rpc.statd`). |
| `deleg-recall-v40-tcp.prog` | knfsd v4.0/TCP delegation conflict | 16 calls, all errno 0. Client0 opens read-only; client1 opens for write and its first OPEN is delayed (`NFS4ERR_DELAY`) until the recall completes. | One KASAN execution on 2026-10-05 completed 16 calls. Thread transitions S2-01 to S2-13 were observed, including the separate callback connection. |

## Fixture checks recorded in earlier documentation

Earlier README records describe cross-client reads and writes, backend isolation and cleanup
with NFSv3, v4.0, v4.1 and v4.2 on the reusable image. The Ganesha V15.6 record also describes
direct mounts and loop-device release on the v4.1/v4.2 images. These are prior recorded results;
no new guest execution was performed during the documentation review.

The earlier flow-trace README records attachment failures for `receive_cb_reply`,
`__cld_pipe_upcall` and `svc_revisit_deferred` on kernel `25456a766`.

## Repository history

- The original handoff repo tarball `knfsd-fuzz-HEAD.tar.gz`
  (sha256 `42f2789ce0dd8c2591239da100b5c08b7ae369fccb1e4e544ce65a284b438c0d`)
  was **deleted 2026-09-25** during the bundle independence restructure; its
  hash is kept here for audit. Its useful contents survived as the flat
  `patches/` + `lane/` (+`baker/`, `corpus/`) above.

The site-generated base image and keypair model was adopted on 2026-09-26.
Commit `7833ed3` removed the custom guest relay and A/B runners with their evidence.

## NFSD trace.c KCOV activation (2026-10-10)

The existing KASAN guest was tested at 00:00–00:01 KST on 2026-10-10
(2026-10-09 15:00–15:01 UTC). No kernel patch or `capture.py` change was made.
The guest ran `basic-v41-tcp.prog` with one executor proc, one execution per condition,
`threaded=false`, and existing remote coverage enabled.

In the same VM, `/sys/kernel/tracing/events/nfsd/enable` was set to `0`, then `1`,
then `0`. The trace buffer was cleared between conditions and `tracing_on` was enabled
during each execution. Raw per-program `.extra` coverage and trace output were retained.

| Condition | NFSD trace records | Unique remote PCs in generated NFSD trace functions | Generated functions reached |
| --- | ---: | ---: | ---: |
| OFF before | 0 | 0 | 0 |
| ON | 768 | 136 | 22 |
| OFF after | 0 | 0 | 0 |

The ON coverage includes `trace_event_raw_event_nfsd_compound`,
`trace_event_raw_event_nfsd_compound_status`, `trace_event_raw_event_nfsd_io_class`
and generated file-operation callbacks. PC membership was determined from the matching
`vmlinux` symbol address ranges; inline-aware symbolization resolves sample PCs through
`fs/nfsd/trace.h`. The counts refer to generated functions and PC locations, not unique
event names or RPCs. Trace records can include background activity.

All three executions completed with exit 0 and the seed's expected errno results
(34 calls, call 14 returning errno 11, all others returning 0). The ON trace reports
768 entries in the buffer and 768 written. Recorded generation aborts, scratch overflow,
aggregate truncation and outstanding tokens were zero. No fatal dmesg signatures were found.
The guest was stopped, and the backing image's SHA-256 was unchanged.

The running guest and `vmlinux` had the same GNU Build ID:
`5704eca19cd5d05a9c0b820691fe199fb53f6128`. Evidence is stored locally under
`evidence/nfsd-tracec-kcov-20261009T150019Z/`:

- `metadata.json`: actual input hashes, guest Build ID, commands and exit status.
- `coverage-comparison.json`: counts and per-function PC matches.
- `nfsd-trace-symbols.json`, `sample-pc-locations.txt`: symbol ranges and sample source mappings.
- `{off-before,on,off-after}/coverage/`: original coverage files.
- `*-executor.stdout`, `*-trace.stdout`, `*-stats.stdout`, `dmesg-after.stdout`: execution and diagnostic logs.

This confirms that enabling NFSD events is sufficient to collect the exercised generated
trace code through the existing KCOV path in this configuration. It does not establish
coverage of every generated function, every background context, KCSAN, or parallel manager execution.

## NFSD trace.c automatic activation (2026-10-10)

Fresh KASAN and KCSAN guests were booted with the updated host-injected `lane.sh`.
The test issued no manual event-enable or `tracing_on` writes. Immediately after boot,
both guests had tracefs mounted and reported `1` for `events/nfsd/enable` and `tracing_on`.
The guest lane script hash matched the host input, and each running kernel's GNU Build ID
matched the `vmlinux` used to classify the coverage PCs.

Each guest ran the unchanged `basic-v41-tcp.prog` once with one executor proc,
`threaded=false` and remote coverage enabled. Both executions matched the functional oracle.

| Kernel | Automatic tracing | Unique remote PCs in generated NFSD trace functions | Generated functions reached | Sanitizer diagnostics |
| --- | --- | ---: | ---: | --- |
| KASAN | Enabled at boot and after execution | 141 | 23 | No fatal signatures |
| KCSAN | Enabled at boot and after execution | 141 | 23 | One data-race report in `kthread_is_per_cpu`, with scheduler frames; origin reported as unknown |

The KCSAN report is preserved in `kcsan/dmesg.stdout`; its cause was not investigated in
this activation change. A successful coverage check does not mean that this run was free
of sanitizer reports. Both guests were stopped and the reusable image hash was unchanged.

Evidence: `evidence/nfsd-tracec-autostart-20261009T152248Z/`. `result.json` contains the
lane and kernel hashes, Build IDs, checks and per-function PC counts. Each variant directory
contains the raw coverage, trace, guest command outputs and dmesg.

## NFS proxy M0 legacy baseline acceptance (2026-10-13)

PR #17의 M0 변경을 독립 검토한 뒤 코드 커밋
`eec30fdd768f822da3d5c3439330b9004c52a8bd`에서 Linux 호스트와 실제
x86_64 KVM guest 검증을 다시 수행했다. 검토 범위는 `583896c`의 독립
`NFSPDLT1`/`NFSPDLT2` golden vector, `93ba2ee`의 Linux topology 및
fail-closed gate, `20ada7b`의 `linux/amd64` guest build, 사용자 결정에
따라 Darwin 지원을 범위에서 제거한 `83e4cdb`, 이 코드 커밋의 자동 guest
replay gate다.

사용한 기준과 산출물은 다음과 같다.

| 항목 | 식별값 |
| --- | --- |
| 검증 대상 코드 커밋 | `eec30fdd768f822da3d5c3439330b9004c52a8bd` |
| kernel base / patched tip | `72d3fcf802c45d00b300f25b848a93c3a2bd7c7e` / `7f1a35fcc0e5eac322241632125d2bd926ca31b5` |
| syzkaller base / patched tip | `801f0966669a37e048adabf9e5f38ce52825ea82` / `bb6b482c4951566957f30e29a4d3b0c96de60a59` |
| host | Linux `5.15.0-198-generic`, x86_64, Intel Xeon Silver 4215R, WSL 아님 |
| guest kernel | `7.3.0-rc5-00003-g7f1a35fcc0e5`, x86_64, GNU Build ID `88a6f604bb4dd4911d51a29dd1001af2eb1f17d5` |
| KASAN kernel | `bzImage` SHA-256 `f12b9d2b5b219e71e06bf3b3c8eaa5de4fd30a2a319674e3959b285581da94d7`; `vmlinux` SHA-256 `99e3ade05ac68ac3fff351a5c5b087f13fbb66b49e839dbf034813701228b5ce` |
| guest image | qcow2 SHA-256 `bb0829d84d24491d6cefe0f3f41e07740abe626660bc54cd573c41d7c4878a2f`; raw SHA-256 `50ca1ecc19291073e0499539ff19533893a6ef057dfba07c8046a654071bef49` |
| guest relay | Debian 12 `linux/amd64`, SHA-256 `1013d4456a86ede71310f8d4f305e814806ac7e4e78b4932fbb2f3c7e48b5d38` |
| guest replay probe | SHA-256 `e6b78937aad28ac5024585bf80f10c558b6a754068d2d60a756098ddfb097241` |
| guest deps | SHA-256 `1bc0097d9b6f55b779ad9f47cb37a0ed80e5643915c9d7321c098f3daacaa938` |

호스트에서는 `tools/nfs-proxy/build.sh`와
`tools/nfs-proxy/build.sh --test`를 각각 실행했다. primary 및
ASan/UBSan 조합에서 framing 213, walk 1694, delta 86, edit 84,
golden 422, proxy 56, control 82 checks가 모두 실패 0건으로 통과했다.
Docker guest build는 실제 `linux/amd64` ELF를 만들었고 provenance와
이미지 digest를 함께 보존했다. `python3 -m py_compile`, `bash -n`,
`git diff --check`, syzkaller `go test ./sys/linux/...`도 통과했다.
`shellcheck`는 이 호스트에 설치되어 있지 않아 실행하지 않았다. 존재하지
않는 arm은 arm별 `rc=2`, 전체 `rc=1`로 종료되어 wrapper가 실패를 숨기지
않음을 확인했다.

다음 명령으로 동일 KASAN guest에서 세 arm을 각각 한 번 실행했다.

```sh
OUT=/home/fuzzer/prune-evidence/m0-issue19-final-83e4 \
IMAGE=/home/fuzzer/prune-env-image.raw \
docs/handoff/proxy-variable-length-edits/run-verify.sh \
  env kasan legacy-v1 legacy-v2 legacy-v2-refusal
```

| arm | live oracle | 생성 delta 및 replay | 결과 |
| --- | --- | --- | --- |
| `legacy-v1` | 네 client/backend route가 모두 connect 및 양방향 전달, `armed=2`, `expired=2`, `applied=2`, 오류 counter 0 | C2S/S2C `NFSPDLT1` 두 개 exact replay 성공; unmatched count, original mismatch, 변조한 `applied_count` mismatch는 proxy `rc=1` | arm `rc=0`, KCOV `.extra` 1/1, fatal dmesg 0 |
| `legacy-v2` | `edit_applied=1`, 오류 counter 0 | resize `NFSPDLT2` exact replay 성공; original mismatch와 `applied_count` mismatch는 proxy `rc=1` | arm `rc=0`, KCOV `.extra` 1/1, fatal dmesg 0 |
| `legacy-v2-refusal` | `edit_applied=0`, `edit_refused_orig=1` | live refusal delta의 replay도 `expected=0`, `applied=0`, `refused_orig=1`, proxy `rc=1` | arm `rc=0`, KCOV `.extra` 1/1, fatal dmesg 0 |

#20의 L1–L3, L6, L7은 다음 명령으로 추가 실행했다. L4, L5, L8은 위
`legacy-v1`, `legacy-v2`, `legacy-v2-refusal` 실행이 각각 같은 workload와
oracle을 더 엄격한 replay gate와 함께 수행한다.

```sh
OUT=/home/fuzzer/prune-evidence/m0-issue20-live-baselines \
IMAGE=/home/fuzzer/prune-env-image.raw PROCS=4 \
docs/handoff/proxy-variable-length-edits/run-verify.sh \
  env kasan direct proxy raw

OUT=/home/fuzzer/prune-evidence/m0-issue20-L6-append \
IMAGE=/home/fuzzer/prune-env-image.raw EXECUTIONS=1 PROCS=1 \
WORKLOAD=$PWD/tools/nfs-proxy/test/guest-syzkaller-v2-append.prog \
docs/handoff/proxy-variable-length-edits/run-verify.sh env kasan raw

OUT=/home/fuzzer/prune-evidence/m0-issue20-L7-append-raw \
IMAGE=/home/fuzzer/prune-env-image.raw EXECUTIONS=1 PROCS=1 \
WORKLOAD=$PWD/tools/nfs-proxy/test/guest-syzkaller-v2-append-raw.prog \
docs/handoff/proxy-variable-length-edits/run-verify.sh env kasan raw
```

| # | 경로 | 판정 근거 | 결과 |
| --- | --- | --- | --- |
| L1 | direct, 4 proc × 30 | `execprog rc=0`, KCOV `.extra` 30/30, `fs/nfsd` PC 1867 | PASS, fatal dmesg 0 |
| L2 | no-edit proxy, 4 proc × 30 | 네 lane 모두 proxy 오류 0, KCOV `.extra` 30/30, `fs/nfsd` PC 1868 | PASS, fatal dmesg 0 |
| L3 | raw 4-route, 4 proc × 30 | 네 lane 각각 네 client/backend tuple에서 `connected`, `c2s`, `s2c`가 모두 1 이상이고 `failed=0`; KCOV `.extra` 30/30 | PASS, fatal dmesg 0 |
| L4 | v1 mutation | `applied=2`, `refused_orig=0` | PASS |
| L5 | v2 replace | `edit_applied=1`, `edit_refused_orig=0` | PASS |
| L6 | v2 struct append | `edit_applied=3`, proxy 오류 0, KCOV `.extra` 1/1 | PASS, fatal dmesg 0 |
| L7 | v2 raw append | `edit_applied=3`, proxy 오류 0, KCOV `.extra` 1/1 | PASS, fatal dmesg 0 |
| L8 | v2 wrong original | `edit_applied=0`, `edit_refused_orig=1` | PASS |

| # | replay 판정 | 결과 |
| --- | --- | --- |
| R1 | v1 C2S exact: `expected=1 applied=1 refused_orig=0`, 응답 XID `0x22222223` | probe `rc=0`, relay `rc=0` |
| R2 | v1 S2C exact: `expected=1 applied=1 refused_orig=0`, 응답 XID `0x22222222` | probe `rc=0`, relay `rc=0` |
| R3 | 원본 v1 delta에 XID `0x22222224`를 보내 미적용: `expected=1 applied=0 refused_orig=0` | 변조 없는 응답, probe `rc=0`, relay `rc=1` |
| R4 | v1 delta의 original 필드 4바이트만 변경: `expected=1 applied=0 refused_orig=1` | 변조 없는 응답, probe `rc=0`, relay `rc=1` |
| R5 | v2 resize exact: `edit=1 expected=1 applied=1 refused_orig=0` | probe `rc=0`, relay `rc=0` |

추가로 v1/v2 delta의 `applied_count`를 2로 바꿔 실제 적용 1회와 불일치할
때도 relay `rc=1`인지, v2 original mismatch가 `refused_orig=1`인지 확인했다.

원본 delta, 파생 mismatch delta, bounded log, `result.json`, 실행 명령과
입력 해시는 [보존 증거](evidence/m0-legacy-baseline-20261013/)에 있으며
`SHA256SUMS` 62개 항목을 모두 재검증했다. 이 검증은 Linux 호스트와
x86_64 KVM guest 범위를 충족한다. Darwin host와 Docker fallback은
2026-10-13 사용자 결정 및 `83e4cdb`에 따라 M0 범위에서 제외되었고,
그 플랫폼에 대한 지원이나 검증 완료를 주장하지 않는다.

## Related records

- [Normal-flow scope](normal-flow-corpus.md)
- [Thread-transition measurements](normal-flow-threads.md)
- [Proxy implementation handoff](../docs/handoff/proxy-variable-length-edits/handoff.md)
