# 정상 NFS 실행 흐름 코퍼스

> **기록 안내 (2026-10-01).** 이 문서가 언급하는 A/B 하네스, 관측기(NF-A1, B06), attribution 시나리오 러너,
> `tools/run-*.sh`와 `phases/*`, 그리고 그 증거 디렉터리는 커밋 `7833ed3`에서 제거되었습니다.
> 아래의 실행 방법과 경로 설명은 당시 기록이며 현재는 실행할 수 없습니다.
> 시드는 stock syz-manager로 실행합니다(`README.md` 3절).

## 현재 목표 (2026-09-28 교정)

여러 정상 NFS 시나리오에서 도달 가능한 스레드 실행 흐름을 파악하고, 이들을 실행하는
하나의 syzkaller 코퍼스를 만든다. 각 흐름의 실제 실행과 remote-KCOV 수집 여부를 확인한다.
통합 코퍼스는 `bundle/corpus/nfs-normal/`에 정적 조립·통합되었으며, 아래에 명시한 미검증·미계측·환경 공백 때문에 전체 정상 흐름의 런타임 완료는 아니다.
하나의 코퍼스 안에 여러 `.prog`와 필요한 fixture/버전별 실행 전제를 둔다.

진행 기준은 `정상 시나리오 → 입력 → 스레드 전환 → 실행 증거 → KCOV 상태`다.
이전 B01–B12 × V1–V7 매트릭스와 9/20 작업 수는 이 목표의 완료율이 아니다.

## 조사·완료 기준

1. 정상 연산, 상태 관리, 비동기 작업, callback 및 background 동작에서 시작해
   RPC, workqueue, kthread, delayed work의 제출/실행 경로를 조사한다.
2. KCOV 심볼이 없는 전환도 포함한다. 기존 `attribution-boundaries.md`는 계측 경계
   조사 자료이며 정상 실행 흐름 전체가 발견됐다는 증거는 아니다.
3. 흐름마다 소스 지점, 시작 조건, 실행 문맥 전후, 대상 입력, 실행 관측 자료,
   KCOV 수집/미수집 상태를 기록한다. PC 집합만으로 실제 스레드 handoff를 단정하지 않는다.
4. 지원 커널·NFS 버전·전송방식·fixture 범위와 미지원 환경을 명시한다.
   현재 TCP/v4.1·v4.2 fixture만으로 다른 전송방식까지 조사 완료했다고 하지 않는다.
5. 입력을 고정한 syzkaller에서 읽고 실제 실행할 수 있어야 한다. 정상 기능의 성공과
   목표 흐름 실행을 확인한다. 미도달·미계측·환경 실패는 각각 남긴다.
6. 정의한 지원 범위의 정상 흐름이 입력과 실행 증거에 연결되어야 완료다.
   미검증 공백이 남으면 부분 완료로 보고한다.

## 출발 자료와 현재 상태

아래는 재사용 후보 목록이며 정상 흐름 전수 목록이나 최종 corpus 목록이 아니다.
Wave3의 파일/증거는 main에 통합됐다고 가정하지 않는다.

| 정상 시나리오 후보 | 기존 자료 | 교정 시점의 상태 / 다음 확인 |
| --- | --- | --- |
| 기본 파일·디렉터리·상태 연산 | `bundle/ab-runner/nfs_remote_kcov_ab_workload.prog`, AB 실행기 | 기존 워크로드 있음. 연산별 스레드 흐름 매핑·현재 runner 경로 점검 필요 |
| 캐시 조회 지연 후 정상 재개 | B04 소스 조사, Wave3 `B04/deferred-lookup.prog` | 강제 두 번째 재지연과 분리해 정상 조건·입력 실행 가능성부터 확인 |
| NFSv4.2 async COPY | `bundle/corpus/attr-scenarios/B05/`, 외부 `B05-V1-wave3-r1/` | 기존 paired VM 귀속 PASS. 최종 코퍼스 편입·현재 환경 재현 여부는 별도 확인 |
| delegation/recall 및 backchannel | Wave3 `B06/delegation-recall.prog` | 후보 입력 있음. 실제 정상 callback 흐름 관측과 KCOV 상태 미확인 |
| outbound callback | COPY 실행의 callback trace, Wave3 B07 후보 | 과거 callback 증거를 재검토. 정상 실행과 현재 ownerless 정책을 각각 기록 |
| background/lifecycle 흐름 | B08–B10 소스 조사와 후보 자료 | 정상 발생 조건·실행 관측 조사 필요. 미수집을 미실행으로 해석하지 않음 |
| 정상 raw RPC 송수신 | B12 소스와 기존 raw 입력 | 정상 NEW 요청 흐름·입력 적합성 확인. RETRY/FINAL 강제 회귀검증은 후속 |

이전 B11-V7 PASS는 레인 귀속 회귀검증 증거다. 정상 흐름 커버리지 완료 수에 자동 가산하지 않는다.
기존 PASS 실행의 KCSAN 발견 사항은 원본 증거에 남아 있으며 sanitizer-clean을 뜻하지 않는다.

## 후속 과제

의도적인 세대 중단, 저장 작업 취소, 반복 재지연/재시도 강제, 경쟁 타이밍 제어,
교차 레인 오귀속 전수 검증은 정상 코퍼스의 선행 조건에서 제외한다.
정상 처리 자체의 비동기 COPY, 지연 후 재개, callback, 자연스러운 다중 클라이언트 흐름은
계속 조사한다. 단순히 V1만 골라 기존 매트릭스를 축소하는 것으로 조사를 대체하지 않는다.

ownerless 또는 미계측 흐름은 관측된 실행과 계측 공백을 보고한다. 미계측 상태를 없애기 위한
커널 변경은 별도 판단 사항이다. `UNFORCEABLE` 표기만으로 도달 코퍼스가 완성된 것으로 계산하지 않는다.

## 재사용과 작업 위치

- 구현·검증 도구와 테스트, 정상 입력, 기존 실행 증거를 보존하고 필요한 부분을 재사용한다.
- Wave3: `/home/idealinsane/knfsd-syzkaller-fresh-wt/kcov-handle-wave3` (미통합·미추적 파일 포함).
- 증거: `/home/idealinsane/attr-scenario-evidence/`.
- 로컬 실행 계획: `C:/Users/idealinsane/.omo/plans/kcov-normal-flow-corpus.md`.
- 다음 작업: 정상 NFS 진입점과 스케줄링 경로의 전수 조사로 위 후보 목록을 보강한다.

## 의도한 시나리오와 코퍼스 대응

실행 계약의 단일 기준은 `bundle/corpus/nfs-normal/README.md`의
`Intended scenarios -> corpus contract`와 `manifest.json`이다. 아래는
시나리오에서 입력을 찾는 색인이다. `NF-*` 연결은 목표 흐름이며, 실제 관측 범위는
각 행의 증거와 이 보고서의 흐름별 표로 제한한다.

| 의도한 정상 시나리오 | 코퍼스 입력 · 소비 경로 | 확인된 범위 · 남은 공백 |
| --- | --- | --- |
| v4.1/TCP 두 클라이언트 파일 작업과 잠금 충돌 | `basic-v41-tcp.prog` · `tools/run-ab.sh` · `tools/ab-lane-fixture.sh` | NF-A2 기능 및 KCOV: OFF/ON PASS. 이 입력에 대한 NF-A1 물리적 handoff는 미관측. |
| v4.2/TCP 비동기 COPY와 CB_OFFLOAD | `async-copy-v42-tcp.prog` · 코퍼스의 `B05-V1.json`과 `ab-lane-fixture-v42.sh`; 동일 입력의 R2 witness | NF-A2·NF-C1·COPY 완료 NF-D1의 B05 페어 실행, NF-A1의 R2 ON handoff 관측 및 remote-KCOV 수집. 콜백 worker의 on-only PC 부재는 미실행 증거가 아님. |
| v4.1/TCP delegation grant → 충돌 → CB_RECALL | `delegation-recall-v41-tcp.prog` · B06 observer와 `tools/ab-lane-fixture.sh` | r3 페어 실행에서 NF-D3 recall, NF-D1 콜백, NF-D2 `svc_process_bc` 진입 관측. ON remote-KCOV는 있으나 그 executor PC는 없음. 초기 NF-D2 ingress와 DELEGRETURN 별도 trace는 없음. |
| v3/TCP fixture 파일의 단순 읽기 | `basic-read-v3-tcp.prog` · 외부 dirty Wave3 B04 fixture | 파서만 PASS. fixture가 workload 전에 실패해 NF-A1/NF-A2 기능·handoff·KCOV 미검증; NF-B1 재방문 입력이 아님. |

NF-B1·NF-B2·NF-E1–E5 및 미지원 버전/전송은 현재 코퍼스의 실행 시나리오로
계산하지 않는다. 시나리오별 실행 조건, 실패 경계와 KCOV 상태는 코퍼스
README 및 아래 증거 표에 명시한다.

## NF-A1 계측 범위 교정

기존 요청별 remote KCOV는 완전한 레코드 수신·소유권 확인 뒤
`net/sunrpc/svc.c`의 `svc_process`에서 시작한다. 따라서 그보다 앞선
`svc_data_ready`·`svc_xprt_enqueue`·`svc_xprt_dequeue`의 PC 부재는 미실행
증거가 아니라 수집 구간의 공백이다. 요청 핸들을 앞당겨 추정하지 않고,
별도 커널 worktree `/home/idealinsane/kcsan-env-0012/linux-wt/nfa1-remote-kcov`에
NFSD 전역 관측 핸들 `0x0200000000000001`을 추가했다. softirq 소켓 콜백과
nfsd 인출 구간만 별도 descriptor로 감싸고, `svc_process`의 기존
요청별 checked ticket과 `.extra` 집계는 그대로 둔다. collector와
실행 명령은 `bundle/corpus/nfs-normal/README.md`에 있다.

신규 v4.2/TCP COPY 페어 VM 증거
`/home/idealinsane/normal-flow-evidence/NF-A1-KCOV-V2-20260928/`:

| 모드 | 관측용 transport PC | 요청별 PC | 함수 영역 판정 |
| --- | ---: | ---: | --- |
| OFF | 16,053 (비포화) | 0 | data-ready·enqueue·dequeue 있음; 요청별 process 없음 |
| ON | 13,065 (비포화) | 721,547 | data-ready·enqueue·dequeue 및 `svc_process` 모두 있음 |

ON의 요청별 시작/종료는 68/68이고 scratch overflow는 0이다.
두 trial 모두 원본 이미지 해시가 보존되고 cleanup 검사와 기능 검사가
통과했다. KCSAN 보고는 모드별 2건으로 sanitizer-clean은 아니다.
첫 V1 실행의 OFF 관측 버퍼는 1,048,575개 한도까지 포화됐다.
불필요한 전체 `svc_process` 관측을 제거하고 새 커널로 재빌드한 V2만
비포화 결과로 사용한다. 관측용 PC는 guest 전체의 **코드 구간 존재**
증거이며 같은 요청의 스레드 handoff, 이벤트 순서나 요청별 귀속은
입증하지 않는다. callback이 task 문맥에서 호출되거나 이미 관리 중인
ticket을 softirq가 중단하면 관측을 건너뛸 수 있으므로 PC 부재도
미실행으로 단정하지 않는다. R2의 실제 물리적 handoff trace와
v4.1/v3의 미검증 범위는 그대로 별개다.

## Main integration and consumer entries

Wave1에서 검증한 단위는 현재 main 경로에 선택적으로 통합했다. 아래 명령은
저장소 루트를 작업 디렉터리로 사용한다. Wave3 B04의 v3
fixture는 외부·미검증 의존성으로 남으며 main에 복사하지 않았다.

- B05 COPY: `/usr/bin/python3 tools/attr-scenario-run.py --scenario bundle/corpus/nfs-normal/B05-V1.json --output /home/idealinsane/attr-scenario-evidence/<unique-normal-B05-run>`. 이 descriptor는 main의 `bundle/corpus/nfs-normal/async-copy-v42-tcp.prog`와 `ab-lane-fixture-v42.sh`를 실제 소비한다.
- B06 delegation recall: `KOOV_EXPECTED_CALLS=15 KOOV_CONFLICT_CALL=-1 python3 tools/run-reach-adapted-window.py --callback-observer b06-recall ... --lane-fixture tools/ab-lane-fixture.sh --workload bundle/corpus/nfs-normal/delegation-recall-v41-tcp.prog --output /home/idealinsane/normal-flow-evidence/B06-V1-delegation-recall-v41-$(date +%s%N) --mode both --trials 1 --executions 10 --sample-every 10 --procs 1`. 기존 r3 경로는 실행 명령의 출력 대상이 아니라 역사 증거다.
- NF-A1 COPY witness: `/usr/bin/python3 bundle/corpus/nfs-normal/nfa1-transport-witness.py ... --lane-fixture bundle/corpus/nfs-normal/ab-lane-fixture-v42.sh --workload bundle/corpus/nfs-normal/async-copy-v42-tcp.prog --preflight`.
- main의 이동된 phase runner 기본값 일곱 개는 `bundle/ab-runner/phases/run_frozen_phase{1,3,4,5,6,8,9}_vm.py`를 유지한다.

## Verified Wave1 source inventory and evidence
## Purpose and evidence rules

This is a source-first inventory of normal NFS server execution flows, not the
historical B01-B12 attribution matrix. The source baseline is
`/home/idealinsane/kcsan-env-0012/linux` at commit `02102ee22924`.

| Status | Exact meaning |
| --- | --- |
| `source candidate` | Cited source establishes the mechanism and normal trigger; this task did not execute it. |
| `runtime observed` | Captured evidence directly identifies execution of the transition/executor. |
| `KCOV collected` | Captured evidence contains KCOV PCs/counters for that executor. |
| `uninstrumented` | No request handle/ticket crosses the transition. |
| `environment blocked` | The fixture lacks a required service, device, mode, protocol, or transport. |
| `unverified` | No direct runtime proof was found; source or effects are not promoted to runtime evidence. |
| `provisional` | Captured evidence includes functional PASS and physical observations; pending independent reviewer confirmation before promotion to `runtime observed`. |

Historical B05-V1 from 2026-09-27 is retained as audited baseline. Fresh VM
runs exist for v4.1 basic (NF-A1-A2-basic-v41-tcp-v1, OFF+ON PASS), v4.2 COPY
with NF-A1 transport witness (NF-A1-COPY-20260928-R2, independently confirmed
by st_01a0e678), v4.2 COPY paired B05 rerun (NORMAL-B05-CORPUS-20260928,
overall PASS, all 21 checks), and v4.1 delegation recall
(B06-V1-delegation-recall-v41-r3, independently confirmed by gate
st_01a0e689 at `B06-r3-runtime-gate.md`).
KCSAN remains nonclean across all runs that produced reports; no result is
labeled sanitizer-clean.

## Search scope and fixture limits

Entry-point search covered NFS program/version tables and dispatchers in
`fs/nfsd/{nfssvc,nfsproc,nfs3proc,nfs4proc,nfs2acl,nfs3acl,localio}.c`, service
threads and receive paths in `net/sunrpc/{svc,svc_xprt,svcsock,backchannel_rqst}.c`,
and normal state, callback, recovery, layout, and file-cache code under
`fs/nfsd/`. Transition-API search covered `queue_work`, `schedule_work`,
`queue_delayed_work`, `mod_delayed_work`, `schedule_delayed_work`,
`kthread_create`, `kthread_run`, `wake_up_process`, `svc_wake_up`, `svc_defer`,
and `cache_defer_req` in `fs/nfsd/*.c` and `net/sunrpc/*.c`, plus `INIT_WORK`,
`INIT_DELAYED_WORK`, and `INIT_DEFERRABLE_WORK` to bind work to executors.

Enabled NFS versions are selected at `fs/nfsd/nfssvc.c:97-105`; NFS, NFSACL,
and LOCALIO programs are routed at `fs/nfsd/nfssvc.c:107-139`. Runtime evidence
covers direct-veth TCP with NFSv4.1 (basic, delegation recall) and NFSv4.2
(COPY), LOCALIO disabled, 4 or 8 vCPUs, 1 or 2 lanes, 1 or 2 syzkaller
processes. v3, UDP, RDMA, LOCALIO, and NAT remain uncovered.

## A. Forechannel and synchronous request flows

| ID / normal scenario | Trigger; conditional scope | Before -> after context | Submit and executor sites | Handle propagation / absence | Runtime | KCOV | Next input / VM evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NF-A1 TCP request arrival | TCP RPC record; any enabled NFS/NFSACL version over TCP | socket data-ready callback -> pooled nfsd kthread | data-ready entry and skb sample `net/sunrpc/svcsock.c:413-429`; set `XPT_DATA` and enqueue `net/sunrpc/svcsock.c:435-437`; publish/wake `net/sunrpc/svc_xprt.c:528-530`; nfsd calls `svc_recv` `fs/nfsd/nfssvc.c:919`; dequeue `net/sunrpc/svc_xprt.c:944`; execute `svc_process` `net/sunrpc/svc_xprt.c:889`. | skb handle is provenance. `svc_process` clears it and admits only authoritative remote work at `net/sunrpc/svc.c:1666-1670`; valid wire work can propagate, ordinary traffic is ownerless. | `runtime observed` for v4.2/TCP: R2 COPY transport witness at `.../NF-A1-COPY-20260928-R2/remote_on/trial_01/nfa1-transport-verdict.json` has assert=true, all 8 checks true, matched_xprt=0xffff888111e5d000, distinct producer PID 74 (kworker/u32:2) and consumer PID 2700 (nfsd) on rqst 0xffff88810092f800. Independently confirmed by `NF-A1-COPY-R2-runtime-gate.md` (st_01a0e678). 1,664/1,664 retained events, zero loss. v4.1/TCP basic (NF-A1-A2-basic-v41-tcp-v1): functional PASS in both OFF+ON, 34 calls, 53 nfsd RPCs, but no transport witness captured, so physical handoff is confirmed only for v4.2. | `KCOV collected`: R2 remote KCOV has 694,531 PCs across 10 .extra files, including svc_process (12 range hits), nfsd4_copy (27), nfsd4_do_async_copy (24). No svc_xprt_enqueue or svc_process_bc in remote KCOV symbol ranges. Coverage is aggregate program-level, not attributed to a specific request ticket or to the observed transport handoff. KCSAN: R2 has 2 reports (pre-marker udev workers); basic v4.1 ON has 1 report, OFF has 0. | v4.1 transport witness remains uncaptured. v3/UDP/RDMA/LOCALIO remain `environment blocked` or `unverified`. |
| NF-A2 synchronous operation / duplicate-reply cache | Decoded NFSv2/v3/v4, NFSACL, or LOCALIO procedure | same nfsd kthread before -> after; **no thread transition** | cache decision `fs/nfsd/nfssvc.c:1028-1035`; direct `proc->pc_func` call `fs/nfsd/nfssvc.c:1038`; update `fs/nfsd/nfssvc.c:1045`. | Active `svc_rqst` ticket stays on the kthread; no enqueue/executor handoff. | `runtime observed` for v4.1/TCP: NF-A1-A2-basic-v41-tcp-v1 OFF+ON trials each report 34 calls, 1 execution, expected_lock_conflicts=1, 53 nfsd RPCs. For v4.2/TCP: R2 COPY reports 110 calls across 10 executions, every expected errno zero, ten 32 MiB COPY returns confirmed; B05 CORPUS fresh paired PASS (NORMAL-B05-CORPUS-20260928) with all 21 checks, 10 executions per mode. Cache lookup is synchronous, not an async handoff. | Conditional on NF-A1 admission; no separate handoff. v4.1 basic ON: 84,357 local KCOV records. v4.1 basic OFF: 79,746. R2 COPY remote: 694,531 PCs. B05 CORPUS on-only fs/nfsd: 1,421 unique PCs. KCSAN: basic ON 1 report, OFF 0; R2 2 reports; B05 CORPUS OFF 2 reports. | Cached-reply evidence and v3 operation PCs remain uncaptured. |

## B. Cache deferral and maintenance

| ID / normal scenario | Trigger; conditional scope | Before -> after context | Submit and executor sites | Handle propagation / absence | Runtime | KCOV | Next input / VM evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NF-B1 authentication/export cache replay | `cache_check_rcu` gets `-EAGAIN`; transport-neutral, but request must fit `svc_defer`. Pre-decode authentication can defer after `RQ_USEDEFERRAL` is set at `net/sunrpc/svc.c:1447`; NFSv4 clears the bit before COMPOUND decoding at `fs/nfsd/nfs4xdr.c:6785`, so a post-decode v4 export/idmap miss is not presumed replayable. | active nfsd kthread -> userspace cache updater/deferred list -> possibly another nfsd kthread | defer request `net/sunrpc/cache.c:320`; save child `net/sunrpc/svc_xprt.c:1320`; completion calls `dreq->revisit` `net/sunrpc/cache.c:769`; revisit enqueues `net/sunrpc/svc_xprt.c:1268-1269`; receiver selects replay `net/sunrpc/svc_xprt.c:869-871`; restore `net/sunrpc/svc_xprt.c:1355`. | `svc_deferred_req.fuzz_saved_work` carries a fresh child to `svc_rqst`; failed save/grant leaves functional ownerless replay. | `source candidate`, `unverified`. | Source supports collection after restore; none claimed here. | Deterministic pre-decode auth upcall fixture that withholds then supplies one entry; capture defer, revisit, restore, checked start, executor PCs, and successful reply. Treat any post-decode v4 case separately. |
| NF-B2 generic SUNRPC cache cleaner | cache-detail registration / expired entry | setup or timer -> `system_power_efficient_wq` worker | queue `net/sunrpc/cache.c:419`; bind `do_cache_clean` `net/sunrpc/cache.c:1708`; execute/reschedule `net/sunrpc/cache.c:519-531`. | Global deferrable work has no request child/ticket. | `source candidate`, `unverified`. | `uninstrumented`. | Create expiring entry and directly observe worker entry plus expiry; expiry effect alone is insufficient. |

## C. NFSv4.2 asynchronous COPY

| ID / normal scenario | Trigger; conditional scope | Before -> after context | Submit and executor sites | Handle propagation / absence | Runtime | KCOV | Next input / VM evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NF-C1 async server-side COPY | NFSv4.2 `OP_COPY` chooses async; reused fixture is intra-server TCP. Inter-SSC also needs its configured source server. | admitted COMPOUND nfsd kthread -> one-shot `copy thread` -> callback queue | save ASYNC child `fs/nfsd/nfs4proc.c:2264`; create/wake `fs/nfsd/nfs4proc.c:2292` and `fs/nfsd/nfs4proc.c:2308`; executor starts saved work `fs/nfsd/nfs4proc.c:2151`, copies `fs/nfsd/nfs4proc.c:2179-2184`, queues callback `fs/nfsd/nfs4proc.c:2201`, stops `fs/nfsd/nfs4proc.c:2203`. | `cp_fuzz_saved_work` becomes a checked kthread ticket. Callback does not inherit it (NF-D1). | `runtime observed`: B05 CORPUS fresh paired PASS (`.../NORMAL-B05-CORPUS-20260928/attr_verdict_B05-V1.json`, overall PASS, all 21 checks, 10 executions each mode, generation_begin/committed=11, remote_start_ok=68). R2 COPY (`.../NF-A1-COPY-20260928-R2/remote_on/trial_01/`) confirms 10x 32 MiB returns and 10/10 callback deliveries via callback-trace.txt with maximum delivery 0.075648s. Historical B05-V1-g703-20260927 retained as audited baseline. | `KCOV collected`: B05 CORPUS on-only fs/nfsd 1,421 unique PCs; on-only fs/nfs 0 (client PCs identical across modes); on-only net/sunrpc 290 (809 ON, 536 OFF, 519 shared). R2 remote KCOV 694,531 PCs with nfsd4_copy (27 range hits), nfsd4_do_async_copy (24), sunrpc_fuzz_saved_work_start (2), sunrpc_fuzz_saved_work_stop (5). `nfsd4_run_cb_work` absent from on-only KCOV in both B05 CORPUS and R2. KCSAN: B05 CORPUS OFF 2 reports; R2 ON 2 reports. | Strict-mode line-7 offset syntax remains unrepaired. Thread-isolated COPY KCOV count vs. aggregate is not separated. |

## D. Callbacks and backchannel

| ID / normal scenario | Trigger; conditional scope | Before -> after context | Submit and executor sites | Handle propagation / absence | Runtime | KCOV | Next input / VM evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NF-D1 outbound callback worker | recall, async COPY completion, notification, or probe; v4.0 separate callback connection, v4.1+ session backchannel | nfsd/kthread/state worker -> per-client callback workqueue -> asynchronous SUNRPC task on rpciod | queue `fs/nfsd/nfs4callback.c:1166-1171`; executor `fs/nfsd/nfs4callback.c:1849`; `rpc_call_async` `fs/nfsd/nfs4callback.c:1891`; binding `fs/nfsd/nfs4callback.c:1908`; async RPC is made runnable on rpciod and executed by `rpc_async_schedule` at `net/sunrpc/sched.c:1019-1033`. | `cb_work` has no saved child/ticket and RPC gets no explicit request origin: ownerless. | `runtime observed` for COPY completion: B05 CORPUS fresh PASS pairs copy-thread callback queue/worker/success. R2 COPY callback-trace.txt confirms 10/10 deliveries with maximum delivery 0.075648s, ten queue/execute work pointers with distinct task PIDs. Historical B05-V1-g703 trace retained as baseline. `runtime observed` for delegation recall trigger: B06 r3 OFF+ON both show assert=true, complete_recall_chain_observed=true, matched_recalls=2, nfsd_cb_queue=20, nfsd_cb_start=20, workqueue_queue_work/execute nfsd4_run_cb_work matched, nfsd_cb_recall_done=11 with status=0. Record_backchannel delta=20 (0 before, 20 after). Independently confirmed by gate st_01a0e689 (`B06-r3-runtime-gate.md`), including server-to-client stateid CRC validation for all 11 recall/ACK pairs per mode. KCSAN: B06 r3 OFF 1 report, ON 0. | `uninstrumented` for request attribution; `nfsd4_run_cb_work` absent from on-only KCOV in both B05 CORPUS and B06 r3 ON. B06 ON status is OBSERVED_OWNERLESS_KCOV: remote KCOV enabled, 294,223 remote PCs in ten extras, but svc_process_bc absent from those PCs. Absence is not evidence of nonexecution; the trace directly proves dispatch via svc_process_bc_entry x20. Ownerless: `cb_work` has no saved child/ticket and RPC gets no explicit request origin. | Other callback triggers (layout, notification, probe) remain `unverified`. |
| NF-D2 same-connection callback CALL | NFSv4.1+ client receives callback CALL; `CONFIG_SUNRPC_BACKCHANNEL`; TCP in fixture | xprtiod socket receive worker -> callback service-pool thread -> synchronous reply | socket readiness queues `recv_worker` at `net/sunrpc/xprtsock.c:1572`; `xs_stream_data_receive_workfn` executes at `net/sunrpc/xprtsock.c:824-832` and completed CALL parsing invokes `xprt_complete_bc_request` at `net/sunrpc/xprtsock.c:641-661`; handoff continues at `net/sunrpc/backchannel_rqst.c:409`, list enqueue/wake `net/sunrpc/backchannel_rqst.c:420-423`, dequeue/call `net/sunrpc/svc_xprt.c:976-983`, and executor `net/sunrpc/svc.c:1774-1838`. | `rpc_rqst`/recycled `svc_rqst` have no authoritative child/ticket; executor has no checked start/stop. | `runtime observed` for the svc_process_bc dispatch portion of v4.1/TCP: B06 r3 OFF+ON both show svc_process_bc_entry x20, record_backchannel delta=20 (0 before, 20 after), same-task client ACK with error=0 for all 11 pairs per mode. OFF status OBSERVED_REMOTE_KCOV_DISABLED; ON status OBSERVED_OWNERLESS_KCOV with 294,223 remote PCs in ten extras. The trace captures svc_process_bc_entry but not the xprtiod socket receive worker (xs_stream_data_receive_workfn) or xprt_complete_bc_request individually; full xprtiod->backchannel queue physical boundary is not claimed as directly observed. Independently confirmed by gate st_01a0e689 (`B06-r3-runtime-gate.md`). KCSAN: B06 r3 OFF 1 report, ON 0. | `uninstrumented`: svc_process_bc absent from ON remote KCOV (294,223 PCs, 6,491 unique) despite remote coverage being enabled. Absence is not evidence of nonexecution; the trace directly proves dispatch via svc_process_bc_entry. ON has real remote data (12 unique PCs in svc_process, 32 in svc_process_common). No request ticket crosses this path. | Confirm full xprtiod receive -> enqueue -> service-pool chain with individual tracepoints if the physical boundary claim is needed. |
| NF-D3 delegation conflict recall | client holds delegation; conflicting access invokes lease break; NFSv4 | VFS/nfsd conflict -> callback workqueue -> RPC task | trigger `nfsd_break_deleg_cb` `fs/nfsd/nfs4state.c:6142`; call to break helper `fs/nfsd/nfs4state.c:6166`; queue recall via `nfsd4_run_cb` `fs/nfsd/nfs4state.c:3675`; then NF-D1. | Delegation callback state has no initiating request ticket; callback-running bit coalesces triggers. | `runtime observed` for v4.1/TCP: B06 r3 OFF+ON both show delegation_grant_observed=true (nfs4_set_delegation x14), nfsd_cb_recall x11, nfsd_cb_recall_done x11 with status=0, nfs4_cb_recall x11 (client ACK). Matched_recalls=2 from 15-call program, 10 executions, 1 lane. Complete_recall_chain_observed=true in both modes. First observed chain: nfsd PID 2705 queues cb_recall for stateid 00000003:00000001, kworker/u32:3 PID 79 executes nfsd4_run_cb_work, NFSv4 callback PID 2714 processes svc_process_bc_entry, nfs4_cb_recall error=0, recall_done status=0. Independently confirmed by gate st_01a0e689 (`B06-r3-runtime-gate.md`) with server-to-client stateid CRC validation for all 11 recall/ACK pairs. KCSAN: B06 r3 OFF 1 report, ON 0. DELEGRETURN is not separately traced. | `uninstrumented`. | DELEGRETURN not separately traced. B06 parser accepts 3 malformed synthetic trace classes (wrong ACK dstaddr, wrong client stateid, header count mismatch); actual r3 data passes independent peer/state/header checks. Full xprtiod->BC queue boundary remains unobserved. |

## E. Lifecycle, pressure, periodic, and pNFS work

| ID / normal scenario | Trigger; conditional scope | Before -> after context | Submit and executor sites | Handle propagation / absence | Runtime | KCOV | Next input / VM evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| NF-E1 NFSv4 laundromat | service start schedules grace/lease expiry; state paths can force immediate run | lifecycle/timer/state path -> `laundry_wq` delayed worker | initial queues `fs/nfsd/nfs4state.c:9850-9856`; execute/reschedule `fs/nfsd/nfs4state.c:7752-7760`; binding `fs/nfsd/nfs4state.c:9773`. | Per-net delayed work has no owner/child/ticket. | `source candidate`, `unverified`. | `uninstrumented`. | Observe direct worker entry and bounded grace-end/expiry event; record configured times, do not sleep and assume. |
| NF-E2 state shrinker/reaper | reclaim while courtesy clients/delegations exist; NFSv4 and pressure dependent | reclaim caller -> `laundry_wq` worker -> reapers | queue `fs/nfsd/nfs4state.c:5538-5545`; executor `fs/nfsd/nfs4state.c:7808-7814`; binding `fs/nfsd/nfs4state.c:9776`. | Coalesced per-net work has no unique request ticket. | `source candidate`, `unverified`. | `uninstrumented`. | Establish reclaimable state, subscribe to worker, induce bounded pressure, capture queue and entry. |
| NF-E3 nfsd filecache GC | normal acquisition adds eligible `nfsd_file` to LRU | nfsd kthread -> `system_dfl_wq` delayed worker -> reschedule | LRU add `fs/nfsd/filecache.c:1300`; queue `fs/nfsd/filecache.c:120-124`; executor/reschedule `fs/nfsd/filecache.c:609-613`; binding `fs/nfsd/filecache.c:935`. | Global delayed work has no request child/ticket. | `source candidate`, `unverified`; `trace_nfsd_file_gc_removed` at `fs/nfsd/filecache.c:605` is emitted even for a zero-removal scan, but is absent when the worker skips an empty LRU, so it is not sufficient worker-entry evidence. | `uninstrumented`. | LRU-producing open/close input; subscribe before trigger and capture worker entry plus GC effect without fixed sleep. |
| NF-E3b GC/shrinker disposal return to nfsd | GC isolates dead cached files at `fs/nfsd/filecache.c:603`, or memory reclaim does so through the shrinker at `fs/nfsd/filecache.c:633`; this is especially relevant to cached NFSv3 files and is not exercised by the v4.2-only fixture. | GC workqueue or reclaim context -> per-net `fcache_dispose_list` -> awakened nfsd service kthread | delayed disposal moves files to the per-net list and calls `svc_wake_up` at `fs/nfsd/filecache.c:458-468`; the non-transport wake implementation is `net/sunrpc/svc_xprt.c:614-628`; the nfsd loop invokes `nfsd_file_net_dispose` at `fs/nfsd/nfssvc.c:957`, whose executor drains up to eight entries, optionally wakes another nfsd thread, and closes them at `fs/nfsd/filecache.c:481-505`. | The per-net list carries `nfsd_file` objects only; no initiating `svc_rqst`, saved child, or remote ticket crosses from GC/shrinker to the awakened service thread. | `source candidate`, `unverified`. | `uninstrumented`. | Use a v3 file-cache workload and separately bounded memory-pressure case; arm queue/wake and nfsd-dispose observers before GC/reclaim, then capture close/disposal completion. |
| NF-E4 nfsdcld grace-start upcall | client tracking selects nfsdcld and daemon has rpc_pipefs open | service lifecycle -> userspace daemon exchange -> same lifecycle context | caller `fs/nfsd/nfs4recover.c:1494`; blocking upcall `fs/nfsd/nfs4recover.c:1292-1305`; no workqueue executor. | Lifecycle/upcall has no request ticket. | `environment blocked` (no captured nfsdcld fixture), otherwise `unverified`. | `uninstrumented`. | nfsdcld-enabled fixture; capture daemon request/reply, kernel return and daemon version at startup. |
| NF-E5 pNFS layout recall/fence | conflicting layout access; fencing additionally requires timeout and fence-capable layout driver | lease break -> callback worker; timeout -> `system_dfl_wq` fence worker | recall queue `fs/nfsd/nfs4layouts.c:341-356`; fence queue `fs/nfsd/nfs4layouts.c:904-922`; executor `fs/nfsd/nfs4layouts.c:793`; binding `fs/nfsd/nfs4layouts.c:266`. | Callback and coalesced fence work have no initiating ticket. | `environment blocked`: no pNFS export/device/fence backend; `unverified`. | `uninstrumented`. | Provision recorded pNFS fixture; obtain layout, trigger conflict, observe recall; test timeout/fence separately, not as prerequisite for normal recall. |

### Observation drafts for E flows (from the removed Wave3 B08-B10 candidates)

These are unrun drafts (`NOT_RUN`, fixture unproven) kept only as observation designs for NF-E1, NF-E2, NF-E3 and NF-E4.
Wave3 also carried V7 cross-lane cells; they are dropped because cross-lane attribution is not a corpus prerequisite.
Each trigger must run after subscribing to the witness and must not rely on a fixed sleep.
Effect-only traces (for example `nfsd_mark_client_expired`, `nfsd_file_gc_removed`) and `rpc_pipefs` status do not prove worker execution.

| Flow | Trigger | Direct witness | KCOV expectation |
| --- | --- | --- | --- |
| NF-E1 laundromat | In an auxiliary nfsd net/mount namespace whose grace is active, write `Y` to `/proc/fs/nfsd/v4_end_grace`. Stop if it returns EBUSY. | Filtered workqueue events (`workqueue_queue_work`, `workqueue_execute_start`, `workqueue_execute_end`) for the same work pointer and `laundromat_main`, resolved through kallsyms. | `laundromat_main` absent from remote coverage. |
| NF-E4 nfsdcld grace start | Start nfsdcld and nfsd in an auxiliary server namespace. | Paired tracefs kprobe entry/return of `nfsd4_cld_grace_start` in one task, return value 0; remove both kprobe events afterwards. Nfsdcld selection and rpc_pipefs readiness are supporting evidence only. | `nfsd4_cld_grace_start` absent. |
| NF-E3 filecache GC | NFS open/close until `nfsd_file_lru_add` fires, then wait for the next worker event. | Same-work-pointer queue and execute events for `nfsd_file_gc_worker`. | `nfsd_file_gc_worker` absent. |
| NF-E2 state shrinker | With a delegation or courtesy client present, write `2` to `/proc/sys/vm/drop_caches`. | Same-work-pointer queue and execute events for `nfsd4_state_shrinker_worker`. | `nfsd4_state_shrinker_worker` absent. |
| NF-D3 recall callback worker | Verify a real delegation in `/proc/fs/nfsd/clients/*/states`, then open/write from the other client. | `nfsd_cb_recall` correlated with `nfsd_cb_queue` and the `nfsd4_run_cb_work` interval. Already covered by the B06 r3 evidence. | `nfsd4_run_cb_work` absent. |

Auxiliary-namespace triggers (NF-E1, NF-E4) start extra nfsd instances beside the lane fixture; they must not perturb the primary service, and the lane fixture cannot host them as is.

## Protocol and transport boundaries

| Boundary | Current status and reason | Evidence needed |
| --- | --- | --- |
| NFSv2 | Disabled in the pinned build (`.config:4670`); `environment blocked`. | Rebuild with NFSD_V2, then use a version-pinned successful input plus queue/executor observations. |
| NFSv3 + NFSACL | Compiled support exists (`CONFIG_NFSD_V3_ACL=y` at `.config:4671`), but no v3 runtime fixture succeeded; v4.1 and v4.2 fixtures do exist: `unverified`. NFSv3 has no v4 callback/state flows and is relevant to NF-E3b disposal. | Version-pinned successful inputs plus queue/executor/disposal observations. |
| NFSv4.0 | Forechannel/state apply; callbacks use separate connection: `unverified`. | v4.0 callback-address and transport evidence. |
| NFSv4.1 | Session/backchannel applies. Basic-v41-tcp-v1 confirms NF-A2 functional PASS (OFF+ON). B06 r3 confirms delegation recall with backchannel svc_process_bc_entry x20, independently confirmed by gate st_01a0e689. No v4.1 NF-A1 transport witness captured. | v4.1 NF-A1 transport witness. Full xprtiod->BC queue physical boundary. Separate DELEGRETURN trace. |
| NFSv4.2 TCP | NF-A1 physical handoff confirmed (R2 transport witness). NF-A2, NF-C1, COPY-completion NF-D1 confirmed (B05 CORPUS fresh PASS, R2 COPY). KCOV collected. KCSAN nonclean. | Thread-isolated COPY KCOV. Attributed callback-worker KCOV. Strict-mode parser fix. |
| UDP | UDP shares `svc_data_ready` and the XPT_DATA/enqueue path because `svc_udp_init` assigns that callback at `net/sunrpc/svcsock.c:868-874`. Its transport-specific parser and attribution path is `svc_udp_recvfrom` at `net/sunrpc/svcsock.c:630`; the fixture remains TCP-only, so UDP is `environment blocked`, `unverified`. | UDP NFSv3 receive/parser, shared enqueue, service-thread, and attribution observations. |
| RPC-over-RDMA | Distinct paths; no device/fixture or enabled config established: `environment blocked`. | RDMA provisioning/config and transport-specific evidence. |
| LOCALIO | Compiled, but B05 says disabled and no input exists: `environment blocked`, `unverified`. | Enablement plus local-filehandle dispatch proof. |
| NAT | Direct-veth evidence does not establish address-rewritten pairing; outside fixture. | Explicit NAT topology and mapping evidence. |

Pinned config has `CONFIG_NFSD_V4=y`, `CONFIG_NFSD_V4_2_INTER_SSC=y`,
`CONFIG_NFS_LOCALIO=y`, `CONFIG_SUNRPC_BACKCHANNEL=y`, and `CONFIG_KCOV=y`.
Compilation is not provisioning. `.config:5419` disables function tracing;
`CONFIG_KPROBE_EVENTS=y`; NF-A1 and B06 guest probes were installed for their bounded runs, but no background-specific probe was installed, so background rows
remain unverified rather than inferred from source or effects.

## Evidence ledger, next corpus, and adversarial review

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| `/home/idealinsane/attr-scenario-evidence/B05-V1-g703-20260927/experiment_manifest.json` | Historical TCP/v4.2 fixture and hashes. | Current run, other versions/transports, all normal flows. |
| Same directory's `attr_verdict_B05-V1.json` | COPY kthread and attributed KCOV; callback enqueue reached. | Callback-worker KCOV; worker is absent-on-only. |
| Same directory's `remote_on/trial_01/callback-trace.txt:18-23` | Historical COPY thread -> callback kworker execution with matching work pointer, successful client callback, and completion status 0. | Current-corpus execution, other callback trigger classes, or attributed worker KCOV. |
| `/home/idealinsane/normal-flow-evidence/NF-A1-A2-basic-v41-tcp-v1/experiment_manifest.json` | v4.1/TCP basic OFF+ON paired PASS, 4 vCPUs, 2 lanes, 2 procs, 1 execution, 34 calls. Functional success for NF-A2. Input `basic-v41-tcp.prog` SHA256 `59e1d766...f02`, fixture `ab-lane-fixture.sh` SHA256 `e91f0f40...5bf`. Host teardown clean: 0 QEMU/executor/listener residue. | NF-A1 physical handoff (no transport witness captured). NF-A1 for v4.2 or other versions. KCSAN cleanliness (ON has 1 report). |
| `/home/idealinsane/normal-flow-evidence/NF-A1-COPY-20260928-R2/experiment_manifest.json` | v4.2/TCP COPY ON-only PASS, 8 vCPUs, 2 lanes, 2 procs, 10 executions, 11 calls each. Input `async-copy-v42-tcp.prog` SHA256 `b7b2ed5b...068`, fixture `ab-lane-fixture-v42.sh` SHA256 `b2b47a9e...9d3`. | Paired OFF comparison (ON-only run). KCSAN cleanliness (2 reports). v4.1 transport witness. |
| Same directory's `remote_on/trial_01/nfa1-transport-verdict.json` | NF-A1 direct physical handoff: assert=true, all 8 checks, matched_xprt=0xffff888111e5d000, distinct producer/consumer PIDs, 1,664/1,664 events, zero loss. Independently confirmed by gate st_01a0e678. | Transport witness for v4.1. Physical handoff for other transports. |
| Same directory's `remote_on/trial_01/callback-trace.txt` | 10/10 COPY callback deliveries, max delivery 0.075648s, distinct task PIDs per queue/execute. R2 NF-C1 and COPY-completion NF-D1. | Other callback trigger classes. Attributed worker KCOV. |
| `/home/idealinsane/attr-scenario-evidence/NORMAL-B05-CORPUS-20260928/attr_verdict_B05-V1.json` | Fresh B05 paired PASS, overall PASS, all 21 checks, 10 executions each mode. On-only fs/nfsd 1,421 PCs, remote_start_ok=68, generation_committed=11. Same input/fixture as historical B05. NF-C1 and COPY-completion NF-D1 confirmed. | Callback-worker KCOV (`nfsd4_run_cb_work` absent on-only). KCSAN cleanliness (OFF 2 reports). Thread-isolated COPY KCOV. |
| `/home/idealinsane/normal-flow-evidence/B06-V1-delegation-recall-v41-r3/experiment_manifest.json` | v4.1/TCP delegation recall OFF+ON paired PASS, 8 vCPUs, 1 lane, 1 proc, 10 executions, 15 calls each. Input `delegation-recall-v41-tcp.prog` SHA256 `2a25b683...978`, fixture `ab-lane-fixture.sh` SHA256 `e91f0f40...5bf`. Independently confirmed by gate st_01a0e689. | Full xprtiod->BC queue physical boundary. KCSAN cleanliness (OFF 1 report). Separate DELEGRETURN trace. Universal B06 parser completeness (3 accepted malformed classes). |
| Same directory's `remote_off/trial_01/b06-verdict.json` and `remote_on/trial_01/b06-verdict.json` | Both assert=true, delegation_grant_observed, complete_recall_chain_observed, matched_recalls=2, record_backchannel delta=20. OFF: OBSERVED_REMOTE_KCOV_DISABLED. ON: OBSERVED_OWNERLESS_KCOV with 294,223 remote PCs (svc_process_bc absent from KCOV; absence is not nonexecution). NF-D2 svc_process_bc_entry x20 observed. NF-D3 delegation recall chain observed. Independently confirmed by gate st_01a0e689 with server-to-client stateid CRC validation. | Full xprtiod->backchannel queue physical boundary. Attributed backchannel KCOV. Separate DELEGRETURN trace. Universal parser completeness. |
| `C:/Users/idealinsane/.omo/evidence/B06-r3-runtime-gate.md` | Independent confirmation of B06 r3 delegation recall, callback worker, svc_process_bc dispatch, functional execution, counter/KCOV classification, cleanup and preservation. Gate st_01a0e689 APPROVE. ON remote KCOV 294,223 PCs; svc_process_bc absent but execution proved by trace. Parser accepts 3 malformed synthetic classes; actual r3 passes independent peer/state/header checks. | Full xprtiod->BC queue boundary. Separate DELEGRETURN. Attributed backchannel KCOV. Universal parser fail-closed behavior. All normal flows or callback triggers. |
| `C:/Users/idealinsane/.omo/evidence/NF-A1-COPY-R2-runtime-gate.md` | Independent confirmation of R2 NF-A1 transport witness, functional execution, retained-trace accounting, callback delivery, remote KCOV, cleanup and preservation. Gate st_01a0e678 APPROVE. | KCSAN cleanliness. All-protocol completion. B06 result. |
| This report's source citations | Candidate triggers, queues, executors, contexts and handle policy. | Runtime, operation success, or KCOV. |

Remaining corpus gaps: v3 defer/revisit (B04 fixture setup failures persist),
lifecycle/background executors (NF-E1 through NF-E5), and fixture-bound
NEW|FINAL input. v4.1 basic proves NF-A2 functional success but lacks a
transport witness for NF-A1 physical handoff at that version. Every run must
preserve kernel/image/input hashes, protocol/transport, operation success, an
observer armed before the trigger, enqueue and executor signals, and KCOV
counters/PCs where expected. Environment-blocked rows need their named fixture.

Adversarial probes: stale matrix claims are rejected; source is never called
runtime; authoring was confined to the Wave1 worktree during evidence collection; this selective integration leaves Wave3
remains read-only. Historical B05-V1-g703 is retained as audited baseline, not
promoted to fresh evidence. B06 r3 delegation recall, callback worker, and
svc_process_bc dispatch portions are independently confirmed by gate
st_01a0e689 (`B06-r3-runtime-gate.md`). No full xprtiod->backchannel queue
physical boundary is claimed for NF-D2 because the trace captures
svc_process_bc_entry but not the preceding xprtiod socket receive or
xprt_complete_bc_request individually. DELEGRETURN is not separately traced.
B06 parser accepts 3 malformed synthetic trace classes; actual r3 data passes
independent peer/state/header checks.

## Reusable-input audit

Locations below are exact relative to `$W=/home/idealinsane/knfsd-syzkaller-fresh-wt/kcov-normal-flow-wave1`, `$X=/home/idealinsane/knfsd-syzkaller-fresh-wt/kcov-handle-wave3` (read-only, dirty Wave3), or `$M=/home/idealinsane/knfsd-syzkaller-fresh` (dirty main, read-only during the audit). `Runnable present` means that a workload is connected to a runner and fixture; it does **not** mean it was run in this audit.

| Input and exact location | NF flow(s) | NFS / transport / fixture | Functional success condition | Pinned parser result | Integration / actual-execution feasibility | Missing dependency or disposition |
| --- | --- | --- | --- | --- | --- | --- |
| Marker-hidden 34-call AB: `$W/tools/nfs_remote_kcov_ab_workload_markerhidden.prog`; actual entry point `$W/tools/run-ab.sh:23-40` | NF-A1, NF-A2 | v4.1, TCP, two direct-veth client mounts from `$W/tools/ab-lane-fixture.sh` | Calls 0-33 are each reported for every execution with none unfinished and positive local KCOV; deliberate peer-lock conflict call 14 returns errno 11 (`EAGAIN`/`EWOULDBLOCK`), every other call returns errno 0, and create/write/read/rename/unlink effects succeed across both mounts (`tools/run_ab_adapted.py:128-153`). | default `0`; strict `0` | **Runnable present**: `run-ab.sh` selects this file and the marker-hidden fixture. No VM was run here. | Stock defaults lack `$W/bundle/src/bookworm.id_rsa`; pass `$M/artifacts/bookworm.id_rsa` and the explicit main kernel/image/vmlinux and sibling syzkaller binaries. Those paths passed argument preflight only, not a VM trial. |
| Legacy marker-bearing AB: `$W/bundle/ab-runner/nfs_remote_kcov_ab_workload.prog` | NF-A1, NF-A2 | Intended v4.1/TCP legacy two-lane fixture | All 34 calls complete with positive local KCOV; deliberate peer-lock conflict call 14 returns errno 11 (`EAGAIN`/`EWOULDBLOCK`), every other call returns errno 0, the initial `.lane_id` read succeeds, and the file effects match the marker-hidden AB contract. | default `0`; strict `0` | **Parser-only/stale**: the file parses, but call 0 requires the marker hidden by syzkaller patch 0014; stock `tools/run-ab.sh` deliberately uses the adapted file instead. | Do not use with the active hidden-marker executor; remove the marker read or use the already adapted tools input. |
| Frozen Phase9 probe: `$W/bundle/ab-runner/frozen_phase9_probe.prog` | NF-A1, NF-A2 | v4.1, TCP, frozen two-client Phase9 fixture | Both canary files complete write/fsync/read or peer write/fsync successfully. | default `0`; strict `0` | **Parser-only/stale for this corpus**: its first three calls also read `.lane_id`; it is not the workload selected by `tools/run-ab.sh`. | Hidden-marker incompatibility; it also contains a fixed two-second `nanosleep`, so it is unsuitable as a deterministic normal-corpus gate without replacement by an event-based condition. |
| B05 COPY: `$W/bundle/corpus/attr-scenarios/B05/reach-copy-offload-x2.prog`, fixture `.../B05/ab-lane-fixture-v42.sh` | NF-A1, NF-A2, NF-C1, COPY-completion NF-D1 | v4.2, TCP, two-lane in-kernel nfsd fixture; 64 MiB request over a 32 MiB source extent selects async COPY | `copy_file_range` returns 32 MiB, async copy reaches `nfsd4_do_async_copy`, callback completes with status 0, and destination fsync/close finish. | default `0`; strict `1`, `wrong string arg` at line 7 offset arguments | **Current VM PASS**: B05 CORPUS fresh paired run at `/home/idealinsane/attr-scenario-evidence/NORMAL-B05-CORPUS-20260928/` records overall PASS with all 21 checks, 10 executions each mode, on-only fs/nfsd 1,421 PCs. R2 COPY at `/home/idealinsane/normal-flow-evidence/NF-A1-COPY-20260928-R2/` confirms 10x 32 MiB returns, NF-A1 transport witness, and 10/10 callback deliveries (ON-only). Historical B05-V1-g703-20260927 retained as audited baseline. | Strict-mode cleanup of the legacy `""/8` offset syntax is needed if strict parsing becomes a gate; the default parser accepted the historically and currently executed bytes. |
| Wave3 B04 deferred lookup: `$X/bundle/corpus/attr-scenarios/B04/deferred-lookup.prog`, fixture `.../B04/ab-lane-fixture-v3.sh` | NF-A1, NF-A2, NF-B1 | v3, TCP forechannel and TCP mount protocol, two-lane fixture with `rpc.mountd`/rpcbind and `nfsd.fh` forcing | Exactly one observed `svc_defer` -> revisit -> restore -> checked start, followed by a successful read/reply and drained saved-work resources. | default `0`; strict `0` | **Wave3-only, parser-only/unfinished**: the old `/home/idealinsane/attr-scenario-evidence/B04-V5-wave3-r2` attempt used this `.prog` with v4.2 and recorded OFF PASS/ON FAIL. The newer `B04-V5-wave3-r11-v3-netns-trace` attempt used the C Phase8 driver with v3, failed during fixture setup, and has an empty `trial_order`. The v3 normal `.prog` remains unexecuted. | Finish and VM-verify the v3 normal-input fixture/binding and its single-defer observer. Explicitly exclude `$X/bundle/corpus/attr-scenarios/B04/B04-V5-2.json`: its C `phase8-probe`, `v5.redefer-cache-revisit` hook, `deferred_redeferred == 1`, and two-child oracle are a forced historical experiment, not an alternative normal PASS or dependency. |
| Wave3 B06 delegation recall: `$X/bundle/corpus/attr-scenarios/B06/delegation-recall.prog`, fixture `.../B06/ab-lane-fixture-v41.sh` | NF-A1, NF-A2, NF-D3, NF-D1, NF-D2 | v4.1, TCP, two distinct clients/backchannel | Prove a delegation was granted before client1 conflicts, then observe ordered CB_RECALL queue/start, backchannel service, callback ACK/status 0, and return/close. File effects alone are insufficient. | default `0`; strict `0` | **Wave1 corpus copy has r3 paired VM PASS**, independently confirmed by gate st_01a0e689: `/home/idealinsane/normal-flow-evidence/B06-V1-delegation-recall-v41-r3/` records OFF+ON both PASS with b06-verdict assert=true, matched_recalls=2, complete_recall_chain_observed=true, record_backchannel delta=20. ON status OBSERVED_OWNERLESS_KCOV with 294,223 remote PCs; svc_process_bc absent from KCOV but execution proved by trace. The Wave1 corpus copy `delegation-recall-v41-tcp.prog` uses the verified Wave1 fixture `ab-lane-fixture.sh`, not the Wave3 fixture. Wave3's `B06-V1.candidate.json` remains `CANDIDATE_NOT_RUN`. KCSAN: OFF 1, ON 0. | DELEGRETURN is not separately traced. Full xprtiod->backchannel queue physical boundary is not claimed. Parser accepts 3 malformed synthetic classes; actual r3 passes independent checks. |
| Wave3 B07 COPY duplicate: `$X/bundle/corpus/attr-scenarios/B07/reach-copy-offload-x2.prog` | NF-C1 and NF-D1 only as an attribution experiment | v4.2, TCP, B05 fixture clone plus two lanes | One lane's forced owner must remain open while the other lane's COPY callback worker executes in the exact entered/queue/execute/release order. | default `0`; strict `1`, same line-7 `wrong string arg` | **Wave3-only, not a normal input**: SHA256 `b7b2ed5b...18068` is byte-identical to B05 and the candidate says `NOT_RUN`; its distinguishing behavior exists only in a forced owner-window runner contract. | **Do not import**: it adds no input coverage and requires unintegrated owner-window schema, runner, identity receipts, and per-owner oracle. Use B05 for normal COPY. |
| Wave3 B12 retry driver: `$X/bundle/corpus/attr-scenarios/B12/retry-driver.prog`; behavior supplied by `tools/attr_hooks.py:116-181` and `bundle/ab-runner/frozen_phase7_probe.c:171-194` | Raw RPC arrival/synchronous NULL dispatch is nearest to NF-A1/NF-A2; no normal NFS operation flow | Manifest says v4.2/TCP fixture, but the `.prog` is only `getpid()`; the hook injects raw NEW/RETRY/FINAL on one socket | The forced hook, not the `.prog`, must produce three replies and exact retry counters on one fd. That proves a retry scenario, not a normal corpus operation. | default `0`; strict `0` | **Parser-only/non-input**: parsing `getpid()` says nothing about NFS execution; operation depends entirely on the forced retry hook. | Not reusable for normal flow. The helper hardcodes `10.77.0.1`, while active scenario lanes use `10.89.<lane>.1`; it also requires the forced RETRY/FINAL hook. |
| Existing single NEW\|FINAL helper: `$W/bundle/ab-runner/frozen_phase7_probe.c:171-247,301-309,492-493` (`normal-final`) | NF-A1/NF-A2 raw NFSv4 NULL baseline only | Raw TCP NFS program 100003, version 4, procedure 0 to hardcoded `10.77.0.1:2049`; no active normal-corpus fixture binding | One NEW\|FINAL NFSv4 NULL send gets its matching reply and increments the normal-final counters exactly once, without retry. | N/A: C helper, **not a `.prog`** | **Helper-only, not yet a corpus input**. It is the closest normal raw baseline but is not wired to the active fixture or syzkaller workload path. | Parameterize/bind the server address to the active fixture, package a `.prog` or explicit helper-driver contract, and validate through the actual runner before promotion. |

### Parser pin and reconciliation

The parser used above is the fixed historical-runtime sibling `/home/idealinsane/kcsan-env-0012/syzkaller/bin/syz-prog2c`, SHA256 `ae5e6c3b2c31d340265088e28835103dedbb8441b7b874f281353604e59ac533`, from checkout `8c1901085e70fcfd88acdcc934410c79fbf27e1b`. Each result used `syz-prog2c [-strict] -prog INPUT`. Successful parses emitted C and only the nonfatal stderr warning `failed to format source: exec: "clang-format": executable file not found in $PATH`; default output SHA256s for representative AB/B05/B06/B12 were respectively `fdb7ce12...52f7`, `663fd583...f6db`, `0bec8127...6077`, and `14612209...8ea`. B05/B07 strict mode emitted no C and failed exactly at line 7 as recorded above. The pristine `801f0966669a37e048adabf9e5f38ce52825ea82` cache/source pin is an upstream source base, **not** the runnable generated parser pin and cannot replace this runtime sibling for compatibility claims. Parser success establishes syntax deserialization only, never fixture compatibility or operation success.

### Runner and unsupported-gap boundary

Main's phase runners were moved under `$M/bundle/ab-runner/phases/`, but their standalone defaults derive `scripts = Path(__file__).resolve().parent` and then append `phases/...`; this can resolve to a nonexistent `phases/phases/...` runner, while sibling fixtures are sought inside `phases/` instead of its parent. The normal-flow runner must therefore receive explicit runner and fixture paths. Separately, stock `$W/tools/run-ab.sh` defaults to missing `$W/bundle/src/bookworm.id_rsa`; `$M/artifacts/bookworm.id_rsa` exists. Explicit main resource/runner arguments have passed path/argument preflight only; no VM execution is claimed.

The unsupported gaps are v2, UDP, RDMA, LOCALIO, current v3 defer/revisit
(B04 fixture setup failures persist through r11), lifecycle and background
fixtures (NF-E1 through NF-E5), and a fixture-bound single NEW\|FINAL input.
v4.1 basic confirms NF-A2 functional success but lacks the transport witness
needed for NF-A1 physical handoff at that version. B06 r3 confirms delegation
recall, callback worker, and svc_process_bc dispatch (independently confirmed
by gate st_01a0e689), but does not claim the full xprtiod->backchannel queue
physical boundary or a separate DELEGRETURN trace. Current VM evidence covers
v4.1/TCP basic (NF-A2), v4.2/TCP COPY (NF-A1 physical handoff, NF-A2, NF-C1,
COPY-completion NF-D1), and v4.1/TCP delegation recall (NF-D1 recall trigger,
NF-D2 dispatch portion, NF-D3). B07's forced owner window,
B12's retry hook, and B04's deferred lookup remain unexecuted. KCSAN is
nonclean in every run that produced reports.
