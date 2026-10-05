# NFS 실행 주체와 스레드 전환

> 상태: draft · 최종 확인: 2026-10-05 · 기준: kernel `25456a766` (v7.3-rc5 + 패치 3개) / syzkaller `01fa50721`
> 관련 패치: kernel 0001(kcov 요청 generation), 0002(sunrpc lane 귀속), 0003(nfsd async COPY 귀속)
> 관련 흐름: NF-A1–E5(기존), NF-F1–F6, NF-G1–G3(이 문서가 정의한다)

## 요약

이 문서는 커널 NFS client, knfsd, lockd, 보조 데몬에서 요청·응답·callback을 실행하는 실행 주체를 모두 식별한다.
이 문서는 NFS 버전별 시나리오 S1–S5에서 실행 주체 사이의 전환을 추적하고, 전환마다 확정 수준(`측정됨`, `코드상`, `미검증`)을 기록한다.
이 문서가 틀리면 PC가 있다는 사실을 스레드 전환의 증거로 읽거나, PC가 없다는 사실을 미실행으로 읽는다.

## 용어

이 문서는 아래 용어만 쓴다. 오른쪽 열의 말은 쓰지 않는다.

| 용어 | 정의 | 쓰지 않는 말 |
|---|---|---|
| 실행 주체 | 커널 코드를 실행하는 문맥 하나. 종류는 사용자 태스크, 스레드, workqueue work, softirq 콜백, 타이머, 사용자 공간 데몬이다 | 컨텍스트, 주체 |
| 스레드 | 이름을 가진 kthread 하나. 예: `nfsd`, `copy thread`, `NFSv4 callback` | 데몬 스레드 |
| 제출 | 한 실행 주체가 다른 실행 주체가 실행할 일을 큐에 넣거나 깨우는 동작 | 큐잉, 넘김, 디스패치 |
| 실행 | 제출된 일을 실행 주체가 시작하는 동작 | 처리, 수행 |
| 전환 | 제출 하나와 그에 대응하는 실행 하나의 쌍 | 핸드오프 |
| 연결 키 | 제출 이벤트와 실행 이벤트에 같은 값으로 나타나서 둘을 같은 일로 묶는 값. 예: work 포인터, xid, 소켓 주소 쌍 | 상관 ID |
| 흐름 | `normal-flow-corpus.md`의 NF 식별자 하나가 가리키는 전환의 묶음 | 경로, 플로우 |
| 시나리오 | 여러 흐름을 정해진 순서로 일으키는 입력과 조건의 묶음. S1–S5 | 케이스 |
| 귀속 | remote KCOV가 수집한 PC를 특정 프로그램의 generation에 기록하는 일 | 할당, 매핑 |
| LINKED | 제출 이벤트와 실행 이벤트가 같은 연결 키를 가진다 | |
| ORDERED | 연결 키가 없다. 다른 태스크의 실행 이벤트가 제출 이벤트 뒤에 시간 창 안에서 나타난다 | |
| UNPAIRED | 제출 이벤트는 있으나 규칙을 만족하는 실행 이벤트가 없다 | |
| MISSING | 제출 이벤트가 없다 | |

`LINKED`와 `ORDERED`만 관측으로 센다. `ORDERED`는 `LINKED`보다 약하다. 두 이벤트를 같은 일로 묶는 값이 없기 때문이다.

workqueue 이름은 트레이스가 표시하는 이름을 쓴다. `system_percpu_wq`의 이름은 `events`이고 `system_dfl_wq`의 이름은 `events_unbound`이다(`kernel/workqueue.c`의 `alloc_workqueue`).

## 해결하려는 문제

`report/normal-flow-corpus.md`는 서버 쪽 흐름 NF-A1–E5만 정의한다. 완료 기준 2는 "제출과 실행을 같은 대상으로 연결한 관측"을 요구한다. 그러나 이 요구를 만족하는 실행 주체 목록과 관측 수단이 없었다. 그 결과 세 가지 오독 위험이 있었다.

1. **PC 존재를 전환의 증거로 읽는다.** remote KCOV가 서버 PC를 수집해도, 그 PC가 어느 실행 주체에서 나왔는지 알 수 없다.
2. **PC 부재를 미실행으로 읽는다.** 기준 커널은 `svc_process` 구간, async COPY 구간, softirq 관측 구간만 귀속한다. callback work, rpciod, laundromat 같은 실행 주체는 귀속 대상이 아니다. 이 실행 주체가 실행되어도 PC는 비어 있다(코드상).
3. **스레드 이름으로 실행 주체를 가른다.** `kworker/u16:2-53` 하나가 `nfsd4_run_cb_work`, `rpc_async_schedule`, `xs_stream_data_receive_workfn`을 차례로 실행한다(측정됨, `s3-v42-copy`). 소켓 콜백은 softirq로 실행되며, 트레이스는 softirq가 끼어든 태스크의 이름(예: `nfs-proxy`)을 표시한다(측정됨). 이름만으로는 어느 workqueue, 어느 콜백인지 알 수 없다.

또한 `normal-flow-corpus.md`는 커널 NFS client 쪽 실행 주체, NFSv4.0의 별도 callback 연결, NFSv3의 lockd를 다루지 않는다.

## 구조

### 실행 주체 구성도

```text
+- client side (netns c0/c1) -------+      +- server side (netns s) ---------+
| C1 syscall task (R3 sync wait)    |      | K2 data_ready [softirq]         |
|   |                               | RPC  |   | svc_xprt_enqueue            |
|   v                               |=====>|   v                             |
| R1 rpciod <-- R2 xprtiod recv     | TCP  | K1 nfsd thread x4               |
|   | rpc_release                   |<=====|   +-> K10 copy thread           |
|   v                               | reply|   +-> K4 nfsd4_callbacks wq     |
| C2 nfsiod                         |      |         | rpc_call_async        |
|                                   |      |         v                       |
| C6 NFSv4 callback thread <========|======|== K5 CB rpc_task on R1 rpciod   |
|   | (v4.0: own TCP, v4.1: BC)     |  CB  |                                 |
|   v                               |      | K6 laundromat  K8 filecache gc  |
| C4 state manager  C5 cl_renewd    |      | K12 cache_cleaner K7 shrinker   |
+-----------------------------------+      +----------------+----------------+
                                                            | upcall
+- user space (server netns) ---------------------------------v--------------+
| L7 rpc.mountd   L8 nfsdcld   L2 rpcbind   [absent: rpc.statd gssd tlshd]    |
+----------------------------------------------------------------------------+
```

범례: `[softirq]`=softirq 콜백, `x4`=lane 하나의 nfsd 스레드 4개, `=====>`=TCP로 오가는 RPC, `-->`=제출.
읽는 순서: 위쪽 화살표는 요청, 가운데는 callback, 아래쪽 상자는 사용자 공간 데몬이다. 이 구성에서 client와 server는 같은 게스트 커널에서 실행된다. lane에서 client0의 트래픽은 사용자 프로세스 `nfs-proxy`를 지난다.

### 판정 파이프라인

```text
 seed (.prog)        capture.py              handoffs.py
 or shell script --> guest VM + tracefs ---> trace.txt.gz --> verdict per
 (stimulus)          events.txt kprobes      (pid, ctx,        transition
                                              ts, detail)      (LINKED ...)
```

범례: `events.txt`=기록할 tracepoint와 kprobe, `scenarios/*.json`=전환 규칙.
읽는 순서: 왼쪽에서 오른쪽. `capture.py`는 트레이스만 남기고 판정하지 않는다.

## 설계

### 범위

- 대상: 커널 NFS client, knfsd, lockd, sunrpc 공통 계층, 서버·client가 호출하는 사용자 공간 데몬(`rpc.mountd`, `nfsdcld`, `rpcbind`).
- 버전: NFSv3, NFSv4.0, NFSv4.1, NFSv4.2. 전송은 TCP이다.
- 목록은 커널이 가진 모든 실행 주체를 포함한다. 현재 lane 환경이 도달하지 못하는 실행 주체도 포함한다. 각 행에 `lane` 열을 쓴다.
- 확정 수준은 행마다 쓴다.
  - `측정됨`: 트레이스에서 실행 주체 자신의 이벤트를 관측했다. 관측한 실행의 이름을 괄호에 쓴다.
  - `코드상`: 코드를 읽어서 확인했다. 트레이스로 확인하지 않았다.
  - `미검증`: 코드로도 트레이스로도 확인하지 못했다.
- `KCOV 귀속` 열은 기준 커널의 코드를 읽은 결과이다. 이 열은 측정하지 않았다.

### 실행 주체 목록

기준 소스는 `env/linux`의 `25456a766`이다. 이 소스의 트리는 코드를 읽은 `prune-linux`의 `c22d8f1ac`와 같다(트리 해시 `6deaddf4b61c`). 심볼은 이름으로 쓴다. 줄 번호는 쓰지 않는다. `측정됨` 옆의 이름은 증거 실행의 이름이며, 실행 정의는 "측정 도구" 절에 있다.

**R. 공통 SUNRPC 계층**

| ID | 실행 주체 | 제출 지점 → 실행 함수 | 깨우는 원인 → 다음 제출 | lane | 확정 |
|---|---|---|---|---|---|
| R1 | workqueue `rpciod` (`WQ_UNBOUND\|WQ_MEM_RECLAIM`) | `rpc_make_runnable()`가 제출한다. 실행 함수는 `rpc_async_schedule` → `__rpc_execute` | `rpc_execute`, `rpc_wake_up*` → xprt 송신, `rpc_release` 제출(C2) | 도달 | 측정됨 |
| R2 | workqueue `xprtiod` (`WQ_UNBOUND\|WQ_MEM_RECLAIM`) | 소켓 콜백(C3a)이 제출한다. 실행 함수는 `xs_stream_data_receive_workfn`, `xs_tcp_setup_socket`, `xs_error_handle`, `xprt_autoclose` | 소켓 데이터·상태 변화 → `xprt_complete_rqst`가 R1 또는 R3을 깨운다. backchannel이면 `xprt_complete_bc_request`가 C7을 호출한다 | 도달 | 측정됨: 수신, connect, error, autoclose worker |
| R2a | R2가 실행하는 `rpc_async_schedule` | write lock 인계 때 `rpc_wake_up_first_on_wq(xprtiod_workqueue, ...)`가 제출한다 | `xprt_release_xprt` → 다음 송신 태스크 | 도달 | 측정됨(`s2-v40-deleg` 7회, `s3-v42-copy` 2회) |
| R3 | 동기 RPC를 호출한 태스크 | `rpc_run_task` → `rpc_execute` → `__rpc_execute`. 대기는 `rpc_task_sync_sleep` | `rpc_make_runnable`이 `wake_up_bit`로 깨운다 | 도달 | 측정됨 |
| R4 | `rpc_wait_queue` 타임아웃. rpciod에서 도는 delayed work `__rpc_queue_timer_fn` | `rpc_set_queue_timer`가 `mod_delayed_work`로 제출한다 | 타임아웃 → 대기 태스크를 깨운다 | 도달 | 측정됨(`ctl-v41-basic` 1회) |
| R5 | xprt 유휴 타이머와 `xprt_autoclose` work | `xprt_init_autodisconnect`(timer)가 xprtiod에 제출한다 | 유휴 시간 초과 → 연결을 닫는다 | 도달 | 측정됨: work. 미검증: 타이머 자체 |

예외: RPC 타임아웃에는 `timer_list`가 없다. 각 `rpc_wait_queue`가 delayed work를 가진다(코드상, R4가 측정으로 확인한다).
예외: `.workqueue = nfsiod_workqueue` 설정은 RPC 상태 기계를 nfsiod로 옮기지 않는다. 이 설정은 `rpc_release`를 nfsiod에서 실행하게 한다(코드상, 측정됨: S1-06, S1-07).

**K. knfsd 서버**

| ID | 실행 주체 | 제출 지점 → 실행 함수 | 깨우는 원인 → 다음 제출 | lane | KCOV 귀속(코드상) | 확정 |
|---|---|---|---|---|---|---|
| K1 | 스레드 `nfsd` (풀마다 N개, lane은 4개) | `nfsd_svc` → `svc_set_num_threads` → `svc_new_thread`가 만든다. 실행 함수는 `nfsd()`: `svc_recv` → `svc_handle_xprt` → `svc_process` → `nfsd_dispatch` | `svc_xprt_enqueue`가 idle 스레드를 깨운다 → 응답 `svc_send`, `nfsd4_run_cb`, `kthread_create`("copy thread"), cache upcall | 도달 | `svc_process` 구간 | 측정됨 |
| K1b | K1이 v4.1+ CB 응답을 받는다 | `svc_tcp_recvfrom` → `receive_cb_reply` → `xprt_complete_rqst` | 응답 수신 → CB `rpc_task`를 깨우고 `rpc_async_schedule`를 R1에 제출한다 | v4.1+에서 도달 | 무소유자(CB 응답) | 측정됨: `rpc_task_wakeup`이 nfsd 스레드에서 실행되었다. `receive_cb_reply`는 인라인되어 kprobe가 불가능하다 |
| K2 | 소켓 콜백(softirq) `svc_data_ready` | `sk_data_ready`로 등록된다 | skb 도착 → `svc_xprt_enqueue` → K1 | 도달 | `NFS_PROGRAM`이고 softirq일 때만 observe 전용 | 측정됨. 코드상: `svc_tcp_listen_data_ready`, `svc_tcp_state_change`, `svc_write_space` |
| K3 | accept | K1이 `XPT_LISTENER` 소켓에서 `svc_tcp_accept`를 실행한다 | 연결 → 새 소켓을 `svc_add_new_temp_xprt`에 등록한다 | 도달 | 무소유자 | 측정됨(`svc_xprt_accept`) |
| K4 | workqueue `nfsd4_callbacks` (client마다 ordered) | `nfsd4_run_cb` → `queue_work`. 실행 함수는 `nfsd4_run_cb_work` | CB 제출 → `rpc_call_async`로 R1에 제출한다 | 도달 | 무소유자 | 측정됨 |
| K5 | CB `rpc_task`(서버가 RPC client 역할) | K4가 `rpc_call_async`로 제출한다. 송신은 R1에서 실행한다 | 응답 → `nfsd4_cb_done` → `nfsd4_cb_release` | 도달 | 무소유자 | 측정됨 |
| K6 | laundromat. workqueue `nfsd4` (`WQ_UNBOUND`)의 delayed work | `nfs4_state_start_net`이 처음 제출한다. `laundromat_main`이 스스로 다시 제출한다. 타이머가 만료되면 softirq에서 `queue_work`가 실행된다 | 주기 → client 만료, `deleg_reaper`, `nfsd4_async_copy_reaper` | 도달 | 무소유자 | 측정됨 |
| K7 | client shrinker worker `nfsd4_state_shrinker_worker` | shrinker 콜백(`nfsd4_state_shrinker_count`)이 reclaim 문맥에서 `nfsd4` workqueue에 제출한다 | 메모리 압력 → `courtesy_client_reaper`, `deleg_reaper` | 도달 | 무소유자 | 측정됨(`s4-v41-state`의 `drop_caches`) |
| K8 | filecache laundrette `nfsd_file_gc_worker` (`events_unbound`) | `nfsd_file_schedule_laundrette` | 2초 지연 → `nfsd_file_dispose_list_delayed` → `svc_wake_up` → K1이 `nfsd_file_net_dispose` 실행 | 도달 | 무소유자 | 측정됨(`s1-v3-basic`만) |
| K9 | delegation break. lease manager 콜백 `nfsd_break_deleg_cb` | `__break_lease`를 호출한 태스크의 문맥에서 실행된다 | 충돌하는 OPEN → `nfsd_break_one_deleg` → `nfsd4_run_cb`(K4) | 도달 | 호출자가 K1이면 `svc_process` 구간 | 측정됨: 충돌 OPEN을 실행한 nfsd 스레드의 문맥에서 실행했다 |
| K10 | 스레드 `copy thread` (COPY마다 1개) | `nfsd4_copy`가 `kthread_create` + `wake_up_process`로 만든다. 실행 함수는 `nfsd4_do_async_copy` | 비동기 COPY → `nfsd4_send_cb_offload`가 `nfsd4_run_cb`(K4)를 호출한다 | v4.2에서 도달 | COPY 연속 구간 | 측정됨(`s3-v42-copy`) |
| K11 | cache upcall과 downcall | K1이 `cache_check` → `sunrpc_cache_upcall`로 요청을 큐에 넣는다. 사용자 공간 `rpc.mountd`가 `/proc/net/rpc/*/channel`에 쓴다 | 캐시 miss → mountd의 write 문맥에서 `cache_revisit_request`가 실행된다 → 대기 중인 K1이 이어서 실행한다 | 도달 | 무소유자 | 측정됨. 미검증: 대기 중인 K1이 깨어나는 순간(tracepoint 없음) |
| K12 | `cache_cleaner`. `events_power_efficient`의 deferrable delayed work `do_cache_clean` | `INIT_DEFERRABLE_WORK` | 주기 | 도달 | 무소유자 | 측정됨 |
| K13 | client 추적 upcall | `nfsd4_client_record_*` → `cld_pipe_upcall`이 요청을 rpc_pipefs의 큐에 넣고 완료를 기다린다. `nfsdcld`(L8)가 write로 `cld_pipe_downcall`을 실행한다 | SETCLIENTID_CONFIRM, RECLAIM_COMPLETE, grace 종료 | 도달 | 무소유자 | 측정됨: downcall. 미검증: upcall 쪽(`__cld_pipe_upcall`은 kprobe 불가) |
| K14 | grace 종료 | 서버를 시작한 제어 태스크(`sh`)의 문맥에서 `nfsd_grace_complete`가 실행된다 | reclaim할 client 기록이 없으면 grace가 시작 직후 끝난다 | 도달 | 무소유자 | 측정됨(`s4b-v41-grace`) |
| K15 | 제어 평면 | 사용자 프로세스가 `/proc/fs/nfsd/threads`, `portlist`에 쓴다 → `nfsd_svc`, `nfsd_startup_net`(`lockd_up`, `nfs4_state_start_net`) | 관리자 동작 → K1, L1, K6 생성 | 도달 | 무소유자 | 측정됨(`nfsd_ctl_threads`) |
| K16 | 다른 shrinker: `nfsd-reply`, `nfsd-DRC-slot`, `nfsd-filecache` | reclaim 문맥 | 메모리 압력 | 도달 | 무소유자 | 코드상 |
| K17 | fsnotify 핸들러, lease notifier, `nfsd4_lm_notify` | VFS 동작을 실행한 태스크의 문맥 | 로컬 또는 원격 변경 → K4 | 도달 | 무소유자 | 코드상 |
| K18 | pNFS layout recall과 fence work | `nfsd4_layout_lm_break` → K4. fence는 `events_unbound` | layout 충돌 | 미도달: pNFS export 없음 | 무소유자 | 코드상 |
| K19 | TLS handshake (xprtsec) | K1이 `svc_tcp_handshake`에서 `tlshd`를 기다린다 | `XPT_HANDSHAKE` | 미도달: `tlshd` 없음 | 무소유자 | 코드상 |
| K20 | LOCALIO 서버 쪽 | client 태스크 문맥에서 `nfsd_open_local_fh`를 호출한다. LOCALIO RPC 프로그램은 K1이 실행한다 | 로컬 NFS client I/O | 미도달: 부팅 인자 `nfs.localio_enabled=N` | 해당 없음 | 코드상 |

**C. 커널 NFS client**

| ID | 실행 주체 | 제출 지점 → 실행 함수 | 깨우는 원인 → 다음 제출 | lane | 확정 |
|---|---|---|---|---|---|
| C1 | syscall 태스크 | 동기 RPC는 `rpc_call_sync` → R3. 비동기 RPC는 `rpc_run_task` → R1에 제출한다 | syscall → 송신 | 도달 | 측정됨(`syz-executor` 태스크 `syz.*`) |
| C2 | workqueue `nfsiod` (`WQ_MEM_RECLAIM\|WQ_UNBOUND`) | `rpc_put_task`가 `tk_workqueue`가 설정된 task의 `rpc_async_release`를 제출한다 | 마지막 참조 해제 → `rpc_release` 콜백: pgio·commit 완료, unlink, delegreturn 해제 | 도달 | 측정됨 |
| C2b | LOCALIO probe work `nfs_local_probe_async_work` (nfsiod) | `nfs_get_client`가 `nfs_local_probe_async`로 제출한다 | client 생성 | 도달 | 측정됨: `nfs.localio_enabled=N`이어도 실행한다(`s3-v42-copy` 19회) |
| C3 | R2의 수신 worker | C3a가 제출한다. 실행 함수는 `xs_stream_data_receive_workfn` → `xs_stream_data_receive` → `xs_read_stream` | 소켓 데이터 → `xprt_complete_rqst`, `xprt_complete_bc_request` | 도달 | 측정됨 |
| C3a | 소켓 콜백(softirq): `xs_data_ready`, `xs_tcp_state_change`, `xs_write_space`, `xs_error_report` | 소켓 연결 때 등록된다 | skb 도착 → `queue_work(xprtiod)` | 도달 | 측정됨: `xs_data_ready`. 코드상: 나머지 |
| C4 | 스레드 `<서버주소>-manager` (state manager) | `nfs4_schedule_state_manager`가 `kthread_run`으로 필요할 때 만든다. 실행 함수는 `nfs4_run_state_manager` → `nfs4_state_manager` | 에러 발생, 위임 반환, lease 확인 → 동기 RPC, `rpc_async_schedule` 제출 | 도달 | 측정됨. 이름은 15자로 잘린다(`10.89.0.1-manag`). 호출마다 새 pid를 가진다 |
| C5 | lease 갱신 `cl_renewd`. `events`(`system_percpu_wq`)의 delayed work `nfs4_renew_state` | `nfs4_schedule_state_renewal` → `mod_delayed_work` (lease의 2/3) | 타이머 → 비동기 RENEW 또는 SEQUENCE를 R1에 제출한다 | 도달 | 측정됨 |
| C6 | 스레드 `NFSv4 callback` (minor version마다 `svc_serv` 하나) | `nfs_callback_up` → `svc_set_num_threads`. 실행 함수는 `nfs4_callback_svc` → `svc_recv` | v4.0: 리스너 소켓에 서버가 연결한다. v4.1+: `sv_cb_list`에 backchannel 요청이 들어온다 → `nfs4_callback_compound`가 C4를 만든다 | 도달 | 측정됨 |
| C7 | backchannel 요청 수신 (v4.1+) | R2의 수신 worker가 `xprt_complete_bc_request` → `xprt_enqueue_bc_request`로 `sv_cb_list`에 넣고 C6을 깨운다 | CB 요청 수신 | v4.1+에서 도달 | 측정됨 |
| C8 | writeback flusher `wb_workfn` | VM이 제출한다. 실행 함수는 `nfs_writepages` | dirty 임계값, 주기 → `nfs_initiate_pgio`로 R1에 제출한다 | 도달 | 측정됨(`wb_workfn`) |
| C9 | delegation 반환 | (a) 동기: `nfs4_inode_return_delegation`을 호출한 syscall 태스크. (b) 비동기: C6이 C4를 만들고 C4가 `nfs_client_return_marked_delegations`를 실행한다 | CB_RECALL → DELEGRETURN RPC를 R1에 제출한다 | 도달 | 측정됨: (b). 코드상: (a) |
| C10 | mount와 umount | `mount.nfs`, `umount` 태스크 | 동기 RPC. mount는 C4(EXCHANGE_ID, CREATE_SESSION), C6을 만든다. umount 뒤 `rpc_free_client_work`, `xprt_destroy_cb`가 `events`에서 실행된다 | 도달 | 측정됨: MOUNT RPC, umount RPC, 해제 work |
| C11 | readahead | 읽는 태스크의 문맥에서 `read_pages()` → `nfs_readahead`가 실행된다 | read, page fault → 비동기 READ를 R1에 제출한다 | 도달 | 코드상 |
| C12 | idmapper | 요청 태스크가 `request_key`를 호출한다. 사용자 공간 `nfsidmap`이나 rpc_pipefs 경로를 쓴다 | uid/gid 이름 변환 | 미도달: `sec=sys`, 숫자 id | 코드상 |
| C13 | 마운트 만료와 `nfslocaliod` | `nfs_expire_automounts`(`events`). `nfslocaliod`는 LOCALIO I/O 전용 | | 미도달 | 코드상 |
| C14 | pNFS layout 반환과 block layout 정리 | C6의 layoutrecall, `events` | | 미도달 | 코드상 |
| C15 | NLM client 호출 | 잠금을 요청한 태스크가 `nlmclnt_proc`에서 `nsm_monitor`(SM_MON, 동기 RPC)와 `LOCK` 동기 RPC를 보낸다. 해제는 `UNLOCK` 비동기 RPC이다 | fcntl/flock → 서버의 `LCK_GRANTED` 또는 `NLM_BLOCKED` | 미도달: lane 마운트가 `nolock`이다. S5는 서버 네임스페이스의 loopback 마운트로 도달시킨다 | 측정됨(S5) |
| C15a | 스레드 `<host>-reclaim` (NLM reclaimer) | `nlmclnt_recovery`가 `kthread_run`으로 만든다. 실행 함수는 `reclaimer` | lockd가 `SM_NOTIFY`를 받아 `nlm_host_rebooted`를 실행한다 → 재획득 `LOCK` RPC | S5b로 도달 | 측정됨(S5b) |

**L. lockd와 보조 서비스**

| ID | 실행 주체 | 제출 지점 → 실행 함수 | 깨우는 원인 → 다음 제출 | lane | 확정 |
|---|---|---|---|---|---|
| L1 | 스레드 `lockd` (전역 1개) | `lockd_up`이 `svc_create` + `svc_set_num_threads`로 만든다. NFSv2·v3가 켜져 있으면 `nfsd_startup_net`이 호출한다 | NLM RPC, `nlmsvc_retry` 타이머 → `nlmsvc_retry_blocked` → `nlm_async_call` | v3에서 도달 | 측정됨(`s1-v3-basic`: 스레드 시작 1회, `nlmsvc_retry_blocked` 25회). 같은 스레드가 NLM의 서버 쪽 요청과 client 쪽 콜백(`GRANTED_MSG`, `SM_NOTIFY`)을 모두 실행한다(측정됨, S5, S5b) |
| L2 | rpcbind 등록 | 서버를 시작한 제어 태스크가 `svc_register` → `rpcb_register` → `rpc_call_sync`로 호출한다 | 서비스 시작 | 도달 | 측정됨(`rpcb_register`). 데몬 쪽은 트레이스 대상이 아니다 |
| L3 | lockd grace 종료 `grace_ender`. `schedule_delayed_work`이므로 `events`(`system_percpu_wq`) | `set_grace_period` | 타이머 | v3에서 도달 | 측정됨(`s1-v3-basic` 4회) |
| L4 | NLM GRANTED 콜백 `nlmsvc_grant_callback` | `nlmsvc_grant_blocked`(인라인, kprobe 불가)가 `nlm_async_call`로 R1에 제출한다. 콜백은 R1에서 실행된다 | `GRANTED_MSG`의 RPC 완료 → client 쪽 lockd가 `nlmclnt_grant`를 실행한다 | lane은 미도달(`nolock`). S5로 도달 | 측정됨(S5) |
| L4a | lm_notify 콜백 `nlmsvc_notify_blocked` | 잠금을 해제한 태스크의 문맥에서 VFS가 호출한다 | 충돌하던 잠금의 해제 → lockd를 깨운다(`svc_wake_up`) | lane은 미도달. S5로 도달 | 측정됨(S5: `plock` 태스크 문맥) |
| L5 | NSM: `nsm_monitor`가 `rpc.statd`에 SM_MON을 보낸다 | 잠금을 요청한 태스크(client 쪽)와 lockd 스레드(서버 쪽)가 `rpc_call_sync`로 호출한다. `rpc.statd`는 사용자 프로세스이다 | 잠금 → statd 응답이 softirq로 xprtiod 수신 worker를 제출한다. 재시작한 statd와 `sm-notify`는 `SM_NOTIFY`를 lockd에 보낸다 | 미도달: lane에 `rpc.statd`가 없다. S5는 서버 키퍼 네임스페이스에서 statd를 시작한다 | 측정됨(S5, S5b) |
| L6 | auth_gss: gssd/gssproxy | `gss_refresh_upcall`, `gssp_accept_sec_context_upcall` | RPCSEC_GSS | 미도달: `sec=sys` | 코드상 |
| L7 | `rpc.mountd` | 사용자 프로세스. K11의 downcall과 MOUNT RPC 응답을 실행한다 | 캐시 upcall, v3 마운트 | 도달 | 측정됨(`cache_revisit_request`가 `rpc.mountd` 문맥에서 실행되었다) |
| L8 | `nfsdcld` | 사용자 프로세스. K13의 downcall을 실행한다 | cld upcall | 도달(v4) | 측정됨 |

### 시나리오

S1–S4는 lane 0에서 `syz-execprog`(proc 0) 또는 셸 스크립트를 실행한다. S5, S5b는 lane 0 서버 키퍼 네임스페이스 안의 loopback 마운트에서 셸 스크립트를 실행한다. 서버 시작을 추적하는 시나리오는 추적을 켠 뒤에 fixture 서비스를 재시작한다. 재시작은 4개 lane 전체를 다시 만든다. 그러므로 트레이스에는 lane 1–3의 서버 시작 이벤트도 있다.

`판정` 열의 값은 증거 실행 `~/flow-trace-evidence/run2/judgement/summary.txt`의 결과이다. `키` 열은 연결 키 종류이다.

#### S1. NFSv3: 서버 시작, 동기·비동기 RPC, 캐시 upcall, lockd

전제 조건:

- 부팅 인자는 `koov.nfs_version=3`이다.
- 마운트 옵션은 `nolock`을 포함한다(`bundle/lane/lane.sh`의 `mount_lane_export`).
- 입력은 `bundle/corpus/nfs-normal/basic-v3-tcp.prog`이다. 이 시드는 `flock`을 쓰지 않는다. 이유는 `nolock` 마운트에서 `flock`이 client 로컬 잠금이 되어 피어 충돌이 일어나지 않기 때문이다(코드상: `NFS_MOUNT_LOCAL_FLOCK`, `NFS_MOUNT_LOCAL_FCNTL`).
- `capture.py`는 `--restart-fixture --stop-fixture --settle 75`로 실행한다. 75초는 lockd grace가 nfsd grace보다 길기 때문이다.

```text
+- control + client c0 -----------+     +- server s ----------------------+
| sh (control task)               |     |                                 |
|   | write threads=4             |     |                                 |
|   +-----------------------------+---->| K15 nfsd_svc -> K1 nfsd x4      |
|   |                             |     |                -> L1 lockd      |
|   | rpcb_register               |     |                                 |
|   +-----------------------------+---->| L2 rpcbind (user)               |
|                                 |     |                                 |
| C1 syz task                     |     | K2 data_ready [softirq]         |
|   | NFSv3 request (xid)         |     |   | svc_xprt_enqueue            |
|   +-----------------------------+---->|   v                             |
|   | sleeps in R3                |     | K1 nfsd thread                  |
|   |                             |     |   | cache miss: upcall          |
|   |                             |     |   +--> L7 rpc.mountd (user)     |
| C3a data_ready [softirq]        |     |   | svc_send (reply, xid)       |
|   v queue_work xprtiod          |<----+---+                             |
| C3 xprtiod recv worker          |     |                                 |
|   | rpc_task_wakeup             |     |                                 |
|   v                             |     |                                 |
| C1 resumes                      |     |                                 |
+---------------------------------+     +---------------------------------+
```

범례: `-->`=제출, `[softirq]`=softirq 콜백.
읽는 순서: 위에서 아래로. 위쪽은 서버 시작, 아래쪽은 요청 한 번의 왕복이다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S1-01 | NF-A1 | C1 → K1 | xid | LINKED | client가 `nfs-proxy`를 지나도 xid는 변하지 않는다(측정됨). 예외: 비동기 RPC는 rpciod가 송신하므로 태스크 이름이 `syz`가 아니다(S1-06) |
| S1-02 | NF-A1 | K2 → K1 | 소켓 주소 쌍 | LINKED | 조건: TCP. softirq가 끼어든 태스크 이름(`nfs-proxy`)과 무관하게 `ctx`로 판정한다 |
| S1-03 | NF-A1 | K1 → C3 | xid | LINKED | 서버의 `svc_send` xid와 client의 `xs_stream_read_request` xid가 같다 |
| S1-04 | NF-F1 | C3a → C3 | work 포인터 | LINKED | client 소켓 콜백이 `xs_stream_data_receive_workfn`을 xprtiod에 제출한다 |
| S1-05 | NF-F1 | C3 → C1(R3 대기) | rpc task id | LINKED | 조건: 동기 RPC. 비동기 RPC는 대기 태스크가 없으므로 짝이 없다(`submits`가 `pairs`보다 많다) |
| S1-06 | NF-F2 | C1 → R1 | work 포인터 | LINKED | WRITE, RENAME, REMOVE, READ는 비동기이다 |
| S1-07 | NF-F2 | R1 → C2 | work 포인터 | LINKED | `rpc_async_release`가 nfsiod에서 실행된다. 같은 kworker가 제출과 실행을 모두 할 수 있다 |
| S1-08 | NF-B1 | K1 → L7 | 없음 | ORDERED | 조건: export 캐시 항목이 없다. 예외: 서버는 요청을 `svc_defer`로 보류하지 않는다. `svc_defer` 이벤트는 S1, S2, S4 실행에서 0건이다(측정됨). 코드상: K1이 `cache_wait_req`에서 `thread_wait`(1초 또는 5초)까지 기다린다 |
| S1-09 | NF-G1 | `sh` → K1 | 없음 | ORDERED | 제어 태스크의 이름은 `sh` 또는 `sleep`이다. `nfsd_main`은 스레드마다 한 번 실행한다 |
| S1-10 | NF-G1 | `sh` → L1 | 없음 | ORDERED | 조건: NFSv3. 같은 규칙을 v4.1 서버 시작에 적용하면 `UNPAIRED`이다(측정됨: lockd가 없다) |
| S1-11 | NF-G1 | 타이머(softirq) → kworker | work 포인터 | LINKED | `grace_ender`가 `events`에서 4회 실행한다. 코드상 `grace_period_end`는 netns마다 하나이다. 4회가 lane 4개와 대응하는지는 미검증이다 |

관측하지 못한 것: NLM 잠금 대기, GRANTED 콜백(L4), NSM(L5). 이유는 lane의 마운트가 `nolock`이고 `rpc.statd`가 없기 때문이다. 이 흐름(`NF-G2`)은 S5와 S5b가 별도 구성으로 다룬다.

#### S2. NFSv4.0: 위임 부여, 별도 callback 연결, recall, 반환

전제 조건:

- 부팅 인자는 `koov.nfs_version=4.0`이다.
- 입력은 `bundle/corpus/nfs-normal/deleg-recall-v40-tcp.prog`이다. client0이 읽기 전용으로 OPEN하고, client1이 쓰기 OPEN으로 충돌한다.
- NFSv4.0에서 서버는 callback 경로가 `UP`일 때만 위임을 부여한다. NFSv4.1 이상에서 서버는 `UP` 또는 `UNKNOWN`일 때 위임을 부여한다. 세션은 별도 연결 없이 callback을 보내기 때문이다(코드상: `nfsd4_cb_channel_good`). 이 실행에서 `nfsd_cb_start`가 `state=UP`을 표시했다(측정됨).
- 충돌한 OPEN은 `NFS4ERR_DELAY`(-10008)로 끝나고, client가 재시도한다(측정됨, `nfs4_open_done`).

```text
+- client c0 / c1 ----------------+     +- server s ----------------------+
| c0 syz: OPEN read -> delegation |     |                                 |
| c1 syz: OPEN write (conflict) --+---->| K1 nfsd thread: svc_process     |
|                                 |     |   | K9 nfsd_break_deleg_cb      |
|                                 |     |   | queue_work nfsd4_run_cb_work|
|                                 |     |   v                             |
|                                 |     | K4 kworker -> R1 rpciod         |
|                                 |     |   | CB_RECALL, own TCP (v4.0)   |
| C6 NFSv4 callback thread <------+-----+---+                             |
|   | svc_process, cb_recall      |     |                                 |
|   v                             |     |                                 |
| C4 state manager (new kthread)  |     |                                 |
|   | DELEGRETURN via R1 rpciod --+---->| K1 nfsd thread: svc_process     |
| C3 xprtiod recv <---------------+-----+-- CB reply -> R1: nfsd4_cb_done |
+---------------------------------+     +---------------------------------+
```

범례: `own TCP`=서버가 client의 callback 리스너에 여는 별도 TCP 연결.
읽는 순서: 위에서 아래로. 충돌 OPEN이 recall을 일으키고, 반환 RPC가 서버로 돌아온다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S2-01 | NF-A1 | C1 → K1 | xid | LINKED | S1-01과 같다 |
| S2-02 | NF-D3 | K1 → K9 | 없음 | ORDERED | 같은 태스크 안의 호출이다. `break_deleg`는 callback work가 아니라 충돌 OPEN을 실행한 nfsd 스레드에서 실행한다(측정됨) |
| S2-03 | NF-D3 | K1 → K4 | work 포인터 | LINKED | `nfsd4_run_cb_work`를 `nfsd4_callbacks`에 제출한다 |
| S2-04 | NF-D1 | K4 → R1 | work 포인터 | LINKED | 같은 kworker가 두 work를 차례로 실행한다 |
| S2-05 | NF-F5 | R1 → C6 | xid | LINKED | CB 요청 xid가 client `svc_process`의 xid와 같다. v4.1은 같은 규칙이 backchannel로도 통과한다 |
| S2-06 | NF-F5 | 서버 송신 중 softirq → C6 | 소켓 주소 쌍 | LINKED | 조건: v4.0. 서버의 송신 호출이 client 리스너의 `svc_data_ready` softirq를 호출 중에 실행한다(같은 커널). v4.1에서는 `MISSING`이다(측정됨) |
| S2-07 | NF-F3 | C6 → C4 | 없음 | ORDERED | C4는 CB_RECALL마다 새 kthread로 시작한다(pid가 다르다). 키가 없다 |
| S2-08 | NF-F6 | C4 → R1 | work 포인터 | LINKED | DELEGRETURN `rpc_task`를 rpciod에 제출한다 |
| S2-09 | NF-F6 | R1 → K1 | xid | LINKED | 반환 RPC가 서버 nfsd 스레드에서 실행된다 |
| S2-10 | NF-D1 | 서버 CB 소켓의 data_ready(softirq, C6가 응답을 보내는 중) → R2 | work 포인터 | LINKED | v4.0의 CB 응답은 서버의 xprtiod 수신 worker가 받는다. v4.1+는 nfsd 스레드가 받는다(K1b). 이 차이는 S3-09와 대조된다 |
| S2-11 | NF-D1 | R2 → R1 | work 포인터 | LINKED | `nfsd4_cb_done`이 rpciod에서 실행된다 |
| S2-12 | NF-D1 | K1 → K4 | 없음 | ORDERED | CB_NULL probe. v4.1에서도 같은 규칙이 통과한다 |
| S2-13 | NF-F5 | K4 → C6 | 없음 | ORDERED | 서버가 client의 callback 리스너로 새 TCP 연결을 연다. client C6이 `svc_xprt_accept`를 실행한다. v4.1에서는 `UNPAIRED`이다(측정됨) |

#### S3. NFSv4.2: 세션, 비동기 COPY, backchannel CB_OFFLOAD

전제 조건:

- 부팅 인자는 `koov.nfs_version=4.2`이다.
- 입력은 기존 `bundle/corpus/nfs-normal/async-copy-v42-tcp.prog`이다(11 호출).
- 서버는 COPY를 비동기로 결정한다. 트레이스의 `nfsd_copy_intra`가 `async=1`을 표시한다(측정됨).

```text
+- client c0 ---------------------+     +- server s ----------------------+
| C1 syz task                     |     |                                 |
|   | COPY (xid A)                |     | K2 data_ready [softirq]         |
|   +-----------------------------+---->|   v svc_xprt_enqueue            |
|                                 |     | K1 nfsd thread: nfsd4_copy      |
|                                 |     |   | kthread_create + wake       |
|                                 |     |   v                             |
|                                 |     | K10 copy thread                 |
|                                 |     |   | queue_work nfsd4_run_cb_work|
|                                 |     |   v                             |
|                                 |     | K4 kworker -> R1 rpciod         |
| C3a data_ready [softirq]        |     |   | CB_OFFLOAD (xid B), BC      |
|   v queue_work xprtiod          |<----+---+                             |
| C3 xprtiod recv worker          |     |                                 |
|   | bc_enqueue                  |     |                                 |
|   v                             |     |                                 |
| C6 NFSv4 callback thread        |     |                                 |
|   | CB reply (xid B)            |     |                                 |
|   +-----------------------------+---->| K1 nfsd thread: wakes CB task   |
|                                 |     |   v queue_work rpc_async_sched. |
|                                 |     | R1 rpciod: nfsd4_cb_done        |
+---------------------------------+     +---------------------------------+
```

범례: `BC`=세션 backchannel(서버가 fore channel 소켓으로 보낸다).
읽는 순서: 위에서 아래로. 서버가 CB를 보낸 뒤 reply가 같은 소켓으로 돌아온다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S3-01 | NF-A1 | C1 → K1 | xid | LINKED | S1-01과 같다 |
| S3-02 | NF-A1 | K2 → K1 | 소켓 주소 쌍 | LINKED | S1-02와 같다 |
| S3-03 | NF-C1 | K1 → K10 | client 주소 | LINKED | `nfsd_copy_intra`(nfsd)와 `nfsd_copy_async`(copy thread)가 같은 `client=` 값을 가진다. `kthread_create`에는 연결 키가 없어서 이 값으로 대신 연결한다 |
| S3-04 | NF-D1 | K10 → K4 | work 포인터 | LINKED | copy 스레드가 `nfsd4_run_cb_work`를 제출한다 |
| S3-05 | NF-D1 | K4 → R1 | work 포인터 | LINKED | 같은 kworker가 제출하고 실행한다 |
| S3-06 | NF-D2 | R1 → C6 | xid | LINKED | CB 요청 xid가 client `svc_process`의 xid와 같다 |
| S3-07 | NF-D2 | C3a → C3 | work 포인터 | LINKED | client 소켓 콜백이 수신 worker를 제출한다 |
| S3-08 | NF-D2 | C3 → C6 | 없음 | ORDERED | `xprt_enqueue_bc_request`가 `sv_cb_list`에 넣고 C6을 깨운다. 이 호출은 tracepoint가 없다 |
| S3-09 | NF-D1 | C6 → K1 | 없음 | ORDERED | v4.1+의 CB 응답은 nfsd 스레드가 받는다. v4.0에서는 `MISSING`이다(측정됨) |
| S3-10 | NF-D1 | K1 → R1 | work 포인터 | LINKED | nfsd 스레드가 `rpc_async_schedule`을 제출하고 rpciod가 `nfsd4_cb_done`을 실행한다 |

#### S3b. NFSv4.1: backchannel 위임 recall과 반환

전제 조건:

- 부팅 인자는 `koov.nfs_version=4.1`이다.
- 입력은 기존 `bundle/corpus/nfs-normal/delegation-recall-v41-tcp.prog`이다.

S2와 같은 사슬이 backchannel 위에서 일어난다. 아래 표는 S2와 다른 점만 설명한다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S3b-01–03 | NF-D3, NF-D1 | K1 → K9 → K4 → R1 | work 포인터 | ORDERED, LINKED, LINKED | S2-02–04와 같다 |
| S3b-04 | NF-D2 | R1 → C6 | xid | LINKED | CB 요청이 fore channel 소켓을 쓴다. 새 TCP 연결이 없다(S2-13이 v4.1에서 `UNPAIRED`) |
| S3b-05 | NF-D2 | C3a → C3 | work 포인터 | LINKED | |
| S3b-06 | NF-D2 | C3 → C6 | 없음 | ORDERED | v4.0에서는 `MISSING`이다(측정됨) |
| S3b-07 | NF-F3 | C6 → C4 | 없음 | ORDERED | S2-07과 같다 |
| S3b-08, 09 | NF-F6 | C4 → R1 → K1 | work 포인터, xid | LINKED | S2-08, 09와 같다 |
| S3b-10 | NF-D1 | C6 → K1 | 없음 | ORDERED | CB 응답을 nfsd 스레드가 받는다 |
| S3b-11 | NF-D1 | K1 → R1 | work 포인터 | LINKED | |

#### S4. 상태 수명과 정리 작업

전제 조건:

- 부팅 인자는 `koov.nfs_version=4.1`이다.
- 입력은 셸 스크립트 `tools/flow-trace/stimulus/s4-state-lifetime.sh`이다. 시드가 아니다. 이유는 manager의 허용 syscall에 `nanosleep`이 없고, client가 lease를 자동으로 갱신하기 때문이다(측정됨: `nfs4_renew_state` 주기 실행).
- 스크립트의 단계는 다음과 같다: 파일 생성·삭제, export 캐시 flush, `drop_caches`, client1 링크를 25초 끊기, 링크 복구 후 접근.
- 서버 시작에서만 일어나는 전환(S4-05)은 `--restart-fixture --settle 14` 실행에서 판정한다.

```text
 trigger                         subject chain
+-------------------------------+--------------------------------------------+
| flush caches (c0 shell)       | K1 nfsd: upcall --> L7 rpc.mountd: revisit |
| drop_caches                   | K7 shrinker work (nfsd4 wq) --> kworker    |
| timer                         | K6 laundromat, K12 cache_cleaner, C5 renewd|
| nfsd start                    | L8 nfsdcld downcall --> K14 grace complete |
| link down 25 s (client1)      | C5 renewd continues, C4 state manager runs |
| unmount / server stop         | C10 teardown work (events workqueue)       |
+-------------------------------+--------------------------------------------+
```

범례: 왼쪽은 유발 동작, 오른쪽은 실행 주체의 사슬이다.
읽는 순서: 위에서 아래로. 각 줄은 독립이다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S4-01 | NF-B1 | K1 → L7 | 없음 | ORDERED | export 캐시 flush 뒤 첫 접근에서 upcall 3개(`auth.unix.ip`, `nfsd.fh`, `nfsd.export`)가 나가고 mountd가 곧바로 `cache_revisit_request`를 실행한다(측정됨) |
| S4-02 | NF-E1 | reclaim 태스크 → kworker | work 포인터 | LINKED | `sh`의 `drop_caches`가 `nfsd4_state_shrinker_worker`를 4회 제출한다 |
| S4-03 | NF-E1 | 타이머(softirq) → kworker | work 포인터 | LINKED | 주기 작업이다. 모든 실행에서 나타나므로 음성 대조에 쓰지 않는다 |
| S4-04 | NF-E3 | K8 → K1 | 없음 | ORDERED | `s1-v3-basic`에서만 관측했다(1쌍). v4.x 실행에서는 `nfsd_file_gc_worker`가 실행되지 않았다 |
| S4-05 | NF-E4 | L8 → 제어 태스크 | 없음 | ORDERED | 새 서버는 reclaim할 기록이 없어서 grace가 시작 직후 끝난다. laundromat이 grace를 끝내지 않는다(측정됨) |
| S4-06 | NF-B2 | 타이머 → kworker | work 포인터 | LINKED | 주기 작업이다 |
| S4-07 | NF-F4 | 타이머 → kworker | work 포인터 | LINKED | 주기 작업이다 |

관측하지 못한 것:

- client1 링크를 25초 끊어도 `nfsd_mark_client_expired`, `nfsd_cb_lost` 이벤트가 0건이다(측정됨). 이 시간 동안 laundromat과 `cl_renewd`는 계속 실행했고, client state manager가 `CHECK_LEASE`를 실행했다. client 만료와 cld 제거 흐름은 관측하지 못했다. 이유는 미검증이다.
- `nfsd_file_gc_worker`는 v4.x 실행에서 관측하지 못했다. 이유는 미검증이다.

#### S5. NFSv3: NLM 잠금 충돌과 GRANTED 콜백

lane의 두 client 마운트는 `nolock`이고 lane에 `rpc.statd`가 없다. 그래서 S5는 lane의 마운트를 쓰지 않는다. S5는 lane 0 서버 키퍼 네임스페이스(사설 `/run`과 `/var/lib/nfs`, lane 0 네트워크 네임스페이스) 안에서 다음 순서로 구성한다.

1. `rpc.statd`를 시작한다. 실행 파일은 이미지의 `/opt/kcov-nfs/deps/sbin/rpc.statd`이다. 이미지를 다시 만들지 않는다.
2. lane 0 export를 `127.0.0.1`에 연다.
3. 같은 네임스페이스에서 `nolock` 없이 loopback으로 마운트한다.
4. 서버 로컬 태스크 `plock`이 export 파일에 POSIX 잠금을 건다. 이 헬퍼는 스크립트가 게스트에서 컴파일한다.
5. NFS 마운트의 `flock`이 같은 파일을 잠근다. 이 호출은 NLM `LOCK` 요청이 되므로, 서버는 `NLM_BLOCKED`로 답한다.
6. `plock`이 끝나서 잠금이 풀리면 서버가 GRANTED 콜백을 보낸다.

전제 조건:

- 부팅 인자는 `koov.nfs_version=3`이다.
- lockd grace가 끝나기 전에는 새 NLM 잠금이 승인되지 않는다. 스크립트는 `grace_end` 이벤트 4개를 기다린 뒤 잠근다. 기다린 시간은 41–44초이다(측정됨). grace 중의 `LOCK` RPC는 약 5초 간격으로 반복되었다(예비 실행 `~/flow-trace-evidence/nlm/try3`, 측정됨). 거부 상태 코드는 트레이스에 없어서 미검증이다.
- 보유자를 서버 로컬 태스크로 둔 이유는 근거 절에 있다.

```text
+- lane 0 server keeper namespaces (private /run and /var/lib/nfs) ------------+
| plock (local task)          flock task (NFS client, nlmclnt_proc)            |
|   | holds POSIX lock          | SM_MON ----------------> L5 rpc.statd (user) |
|   |                           | LOCK (xid) over loopback                     |
|   |                           v                                              |
|   |                         L1 lockd thread: nlmsvc_lock -> NLM_BLOCKED      |
|   | exits: lock released      (flock task sleeps in nlmclnt_lock)            |
|   v                                                                          |
| L4a nlmsvc_notify_blocked (runs in the plock task)                           |
|   | wakes                                                                    |
|   v                                                                          |
| L1 lockd thread: nlmsvc_retry_blocked                                        |
|   | queue_work rpc_async_schedule                                            |
|   v                                                                          |
| R1 rpciod: GRANTED_MSG (xid) ------> L1 lockd thread (NLM client side)       |
|                                        | nlmclnt_grant                       |
|                                        v wakes                               |
|                                      flock task leaves nlmclnt_lock          |
+------------------------------------------------------------------------------+
```

범례: `-->`=제출, `(user)`=사용자 공간 프로세스.
읽는 순서: 위에서 아래로. 왼쪽 줄은 보유자, 오른쪽 줄은 대기자이다. 같은 `lockd` 스레드가 서버 쪽 요청과 client 쪽 콜백을 모두 실행한다.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S5-01 | NF-G2 | L5(`rpc.statd`)의 응답 → R2 | work 포인터 | LINKED | SM_MON은 대기자 태스크가 보내는 동기 RPC이다. `rpc.statd`는 사용자 프로세스라서 커널 이벤트는 응답이 일으킨 softirq(태스크 이름 `rpc.statd`)에서만 보인다 |
| S5-02 | NF-G2 | `flock` 태스크 → L1 | xid | LINKED | `LOCK` RPC가 lockd 스레드에서 `svc_process`로 실행된다. 이 이후 `nlmsvc_lock`이 실행된다(kprobe) |
| S5-03 | NF-G2 | `plock` 태스크(L4a) → L1 | 없음 | ORDERED | lm_notify는 잠금을 푼 태스크의 문맥에서 실행되고 `svc_wake_up`으로 lockd를 깨운다. 깨움에는 tracepoint가 없다 |
| S5-04 | NF-G2 | L1 → R1 | work 포인터 | LINKED | lockd가 `GRANTED_MSG` `rpc_task`를 rpciod에 제출한다 |
| S5-05 | NF-G2 | R1 → L1(client 쪽) | xid | LINKED | rpciod가 보낸 `GRANTED_MSG`를 lockd가 `svc_process`로 실행한다(proc=GRANTED_MSG) |
| S5-06 | NF-G2 | L1 → `flock` 태스크 | 없음 | ORDERED | lockd의 `nlmclnt_grant`가 대기자를 깨운다. 대기자의 `nlmclnt_lock`이 `LCK_GRANTED`로 끝난다 |
| S5-07 | NF-G2 | R1 → L1 | xid | LINKED | client가 보낸 `GRANTED_RES`를 lockd가 `svc_process`로 실행한다 |

예외: 같은 마운트의 두 NFS 태스크로 충돌을 만들면 순서가 뒤집힌다. 첫 시도(예비 실행 `~/flow-trace-evidence/nlm/try4`)에서 보유자의 비동기 `UNLOCK`(rpciod)보다 대기자의 동기 `LOCK`이 서버에 먼저 도착했다. 이 순서에서는 서버가 `NLM_BLOCKED`로 답하고 `UNLOCK` 뒤에 GRANTED 콜백이 일어난다. 반대 순서에서는 서버가 바로 승인한다(코드상). 그래서 S5는 보유자를 서버 로컬로 둔다.

관측하지 못한 것:

- 서로 다른 두 호스트 사이의 NLM. 이 구성은 client와 server가 같은 호스트, 같은 네임스페이스, 같은 lockd 스레드이다.
- 대기자가 GRANTED 없이 타임아웃으로 깨어나는 경로.
- `nlmsvc_grant_blocked`는 인라인되어 kprobe가 불가능하다. 제출은 `rpc_async_schedule`의 `queue_work`로 관측했다.

#### S5b. NFSv3: SM_NOTIFY와 NLM reclaimer

S5와 같은 구성에서, 한 client 태스크가 잠금을 쥔 채로 둔다. 그 사이에 `rpc.statd`를 `--no-notify`로 다시 시작하고, `sm-notify`를 직접 실행한다. `sm-notify`는 `sm.bak`에 있는 호스트에 `SM_NOTIFY`를 보낸다. 이 시험은 상대 호스트의 재부팅을 흉내 낸다.

전제 조건:

- `sm-notify`는 statd 등록이 끝난 뒤에 실행해야 한다. 새로 시작한 statd가 자기 안에서 `sm-notify`를 띄우면 등록 전에 포트를 조회해서 "No statd on host"로 실패하고 120초를 기다린다(측정됨, `~/flow-trace-evidence/nlm/reboot2`).
- statd는 `sm-notify`를 절대 경로 `/sbin/sm-notify`로 찾는다. 이 이미지는 `/opt/kcov-nfs/deps/sbin/`에 둔다. 스크립트가 임시 심볼릭 링크를 만든다. 게스트는 스냅샷 모드라서 링크는 실행 뒤에 사라진다.

```text
+- lane 0 server keeper namespaces --------------------------------------------+
| sm-notify (user) --SM_NOTIFY--> L5 rpc.statd (user)                          |
|                                   | NLM downcall (callback RPC)              |
|                                   v                                          |
| L1 lockd thread: svc_process SM_NOTIFY -> nlm_host_rebooted                  |
|   | nlmclnt_recovery: kthread_run                                            |
|   v                                                                          |
| C15a <host>-reclaim kthread: reclaimer                                       |
|   | LOCK (reclaim) over loopback                                             |
|   v                                                                          |
| L1 lockd thread: svc_process LOCK -> nlmsvc_lock                             |
+------------------------------------------------------------------------------+
```

범례: `(user)`=사용자 공간 프로세스.
읽는 순서: 위에서 아래로.

| ID | 흐름 | 제출 주체 → 실행 주체 | 키 | 판정 | 조건·예외·근거 |
|---|---|---|---|---|---|
| S5b-01 | NF-G2 | L5(`rpc.statd`)의 softirq → L1 | 소켓 주소 | LINKED | statd가 `SM_NOTIFY` 콜백을 lockd의 전송 소켓으로 보낸다. 제출 이벤트의 태스크 이름은 `rpc.statd`이다 |
| S5b-02 | NF-G2 | L1 → C15a | 없음 | ORDERED | `nlmclnt_recovery`가 `kthread_run`으로 reclaimer를 만든다. 스레드 이름은 `<host>-reclaim`(15자로 잘려 `127.0.0.1-recla`)이다 |
| S5b-03 | NF-G2 | C15a → L1 | xid | LINKED | reclaimer가 재획득 `LOCK`을 동기 RPC로 보낸다. lockd가 `svc_process`로 실행한다 |

관측하지 못한 것: reclaimer가 여러 잠금을 재획득하는 경우, 서버가 grace 중에 재획득을 받아들이는 상태 코드.

### 판정 규칙

- 규칙은 `tools/flow-trace/scenarios/*.json`에 전환마다 하나씩 있다.
- 규칙은 제출 이벤트와 실행 이벤트를 이벤트 이름, 태스크 이름, 문맥(`task`/`softirq`), 상세 문자열의 정규식으로 지정한다.
- 정규식의 `k` 그룹이 연결 키이다. `link`가 `key`이면 두 이벤트의 `k`가 같아야 한다.
- `link`가 `order`이면 두 이벤트가 다른 태스크에서 나타나고 `within_us` 안에 있어야 한다. `same_task_ok`가 참이면 같은 태스크를 허용한다.
- `after`는 이전 전환의 이벤트를 기준으로 시간 창과 같은 태스크 조건을 건다. 이 조건이 무관한 이벤트와의 짝짓기를 막는다.
- 판정기는 실행 이벤트마다 가장 가까운 이전 제출 이벤트를 짝짓는다. 이미 쓴 제출 이벤트는 다시 쓰지 않는다.
- `specific`이 참인 전환은 음성 대조 실행에서 하나도 관측되면 안 된다.
- 판정기는 트레이스 헤더의 `entries-in-buffer/entries-written`을 읽는다. 두 값이 다르면 `MISSING`을 신뢰할 수 없다고 출력한다.

### 측정 도구

| 파일 | 역할 |
|---|---|
| `tools/flow-trace/capture.py` | 게스트를 부팅하고 이벤트를 켜고 자극을 실행하고 트레이스를 저장한다. `--restart-fixture`, `--stop-fixture`, `--settle` 옵션이 있다 |
| `tools/flow-trace/events.txt` | 기록할 tracepoint와 kprobe 목록 |
| `tools/flow-trace/handoffs.py` | 트레이스와 시나리오 규칙을 읽어 전환마다 판정한다 |
| `tools/flow-trace/subjects.json`, `subjects.py` | 실행 주체마다 표지 이벤트를 정의하고 트레이스별 관측 횟수를 센다 |
| `tools/flow-trace/scenarios/*.json` | 시나리오 S1, S2, S3, S3b, S4, S5, S5b의 전환 규칙 |
| `tools/flow-trace/stimulus/s4-state-lifetime.sh` | S4의 자극 |
| `tools/flow-trace/stimulus/s5-nlm-lock.sh`, `s5b-nlm-reboot.sh` | S5, S5b의 자극. `rpc.statd` 시작, loopback 잠금 마운트, 잠금 충돌과 `SM_NOTIFY`를 일으킨다 |
| `tools/flow-trace/run-all.sh`, `summarize.sh` | 모든 실행을 순서대로 수집하고, 모든 판정을 저장한다 |

증거 실행 `run2`는 `run-all.sh`가 만든 7개 실행이다. 증거는 저장소 밖 `~/flow-trace-evidence/run2/`에 있다.

| 실행 | 부팅 버전 | 자극 | 용도 |
|---|---|---|---|
| `ctl-v41-basic` | 4.1 | `basic-v41-tcp.prog` | 음성 대조(서버 재시작 없음) |
| `s1-v3-basic` | 3 | `basic-v3-tcp.prog`, 서버 재시작, 75초 대기 | S1 |
| `s2-v40-deleg` | 4.0 | `deleg-recall-v40-tcp.prog`, 서버 재시작 | S2 |
| `s3-v42-copy` | 4.2 | `async-copy-v42-tcp.prog`, 서버 재시작 | S3 |
| `s3b-v41-deleg` | 4.1 | `delegation-recall-v41-tcp.prog`, 서버 재시작 | S3b |
| `s4-v41-state` | 4.1 | `s4-state-lifetime.sh` | S4 |
| `s4b-v41-grace` | 4.1 | 서버 재시작, 14초 대기 | S4-05 |

NLM 시나리오는 `run2`와 다른 실행 묶음 `run3`(`~/flow-trace-evidence/run3/`)에 있다. `run3`의 이벤트 목록은 NLM 서버·client 진입점 kprobe 9개가 더 있다(`meta.json`이 기록한다).

| 실행 | 부팅 버전 | 자극 | 용도 |
|---|---|---|---|
| `s5-v3-nlm-lock` | 3 | `s5-nlm-lock.sh` | S5 |
| `s5b-v3-nlm-reclaim` | 3 | `s5b-nlm-reboot.sh` | S5b |

## 설계 근거

각 결정에 근거를 하나씩 붙인다.

1. **목록의 기준을 커널 전체로 한다. 각 행에 `lane` 열을 둔다.**
   근거: lane이 도달하는 범위만 쓰면 미도달 실행 주체가 문서에서 사라진다. 사라진 실행 주체의 PC 부재는 미실행으로 읽힌다. `lane` 열이 이 오독을 막는다. 사용자가 환경과 무관한 목록을 요구했다.
2. **전환 판정은 같은 연결 키를 우선한다.**
   근거: 완료 기준 2가 "제출과 실행을 같은 대상으로 연결한 관측"을 요구한다. work 포인터, xid, 소켓 주소 쌍은 커널이 이미 트레이스에 남기는 값이다. 커널 패치를 늘리지 않는다.
3. **연결 키가 없는 전환은 `ORDERED`로 구분하고 관측 수준을 낮춘다.**
   근거: kthread 생성, `sv_cb_list` 삽입, completion 깨움은 tracepoint가 값을 남기지 않는다. 이 전환을 `LINKED`로 쓰면 증거가 없는 주장이 된다.
4. **규칙에 `after` 조건(이전 전환 기준의 시간 창과 같은 태스크)을 넣는다.**
   근거: 키만 쓰면 무관한 이벤트와 짝지어진다. `rpc_async_schedule` work는 같은 포인터를 재사용한다(측정됨). 같은 kworker가 여러 workqueue의 work를 연달아 실행한다(측정됨).
5. **음성 대조와 버전 차이 검사를 판정의 일부로 한다.**
   근거: 첫 S2 규칙이 v4.1 기본 시드의 트레이스에서도 통과했다. v4.1 기본 시드가 위임 충돌을 일으키기 때문이다. 대조가 없으면 규칙이 고유한 흐름을 가리키는지 알 수 없다.
6. **추적 창 안에서 서버를 재시작한다.**
   근거: 서버 시작 이벤트(`nfsd` 스레드 생성, `rpcb_register`, grace 종료)는 시작 순간에만 발생한다. 같은 서버 주소로 두 번째 마운트를 하면 기존 `nfs_client`를 재사용할 수 있어서 EXCHANGE_ID와 SETCLIENTID가 다시 일어나지 않을 수 있다(코드상: `nfs_get_client`의 일치 검사). 단점은 4개 lane 전체를 다시 만드는 것이다.
7. **v3 시드에서 `flock`을 뺀다.**
   근거: `nolock` 마운트에서 잠금은 client 로컬이다(코드상). `basic-v41-tcp.prog`의 피어 잠금 충돌(errno 11)이 v3에서는 일어나지 않는다.
8. **lease 만료는 시드가 아니라 셸 스크립트로 일으킨다.**
   근거: manager의 허용 syscall에 `nanosleep`이 없다. client가 lease를 자동으로 갱신한다(측정됨).
9. **NLM 시나리오는 서버 키퍼 네임스페이스의 loopback 마운트로 구성한다.**
   근거: lane의 client 네임스페이스 두 개에는 rpcbind와 `rpc.statd`가 없다. 그 안에서 NLM을 켜려면 네임스페이스마다 rpcbind, statd, 사설 `/run`, `/var/lib/nfs`가 필요하다. 서버 키퍼 네임스페이스는 rpcbind와 사설 디렉터리를 이미 가진다. 거기에 statd 하나만 더 시작하면 된다. 단점은 client와 server가 같은 호스트라서 호스트 간 NLM을 관측하지 못하는 것이다.
10. **잠금 충돌의 보유자를 서버 로컬 POSIX 잠금으로 둔다.**
    근거: 같은 마운트의 두 NFS 태스크로 충돌을 만들면 서버에 도착하는 `LOCK`과 `UNLOCK`의 순서가 실행마다 달라질 수 있다. 예비 실행 `try4`에서 `LOCK`이 먼저 도착했다(측정됨). 로컬 보유자는 서버에서 항상 `NLM_BLOCKED`를 만든다. 이 구성은 `lm_notify` 경로(L4a)도 실행한다.

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| 태스크 이름·pid만으로 실행 주체 판정 | 구현이 단순하다 | kworker 하나가 여러 workqueue의 work를 실행한다. softirq는 끼어든 태스크의 이름을 표시한다 | 기각. 재검토 조건: 커널이 workqueue 이름을 태스크 이름에 넣는 경우 |
| `sched_switch`·`sched_wakeup` 전체 그래프 | 모든 전환을 포착한다 | 이벤트 양이 크고 어떤 일 때문에 깨웠는지 알 수 없다 | 기각. 재검토 조건: 제출 이벤트가 없는 전환을 보강해야 할 때 |
| function tracer | 호출 사슬 전체를 얻는다 | 오버헤드가 크다. 이번에는 시도하지 않았다 | 미채택 |
| remote KCOV 핸들로 전환을 증명 | 기존 계측을 쓴다 | 기준 커널은 `svc_process`, async COPY, softirq 관측 구간만 귀속한다. callback, rpciod, laundromat은 무소유자이다(코드상) | 대체 불가. 보완 관계이다. callback 귀속은 `report/xprtsock-remote-kcov-plan.md`(draft)가 다룬다 |
| 시나리오 하나로 통합 | 실행이 한 번이다 | v4.0의 별도 연결과 v4.1의 backchannel은 한 부팅에서 공존할 수 없다. 버전이 부팅 인자로 정해진다 | 기각 |
| 각 client 네임스페이스에 rpcbind와 `rpc.statd`를 시작 | lane의 실제 topology(veth)에서 NLM을 관측한다 | 네임스페이스마다 사설 `/run`, `/var/lib/nfs`, 데몬 둘이 필요하다. 시도하지 않았다 | 미채택. 재검토 조건: 호스트 간 NLM 전환을 관측해야 할 때 |
| 같은 마운트의 NFS 태스크 둘로 잠금 충돌 | 헬퍼 프로그램이 필요 없다 | 서버에 도착하는 순서가 달라질 수 있어 blocked 경로를 보장하지 못한다(측정됨, `try4`) | 기각 |
| 커널에 전용 tracepoint 추가 | `ORDERED` 전환이 `LINKED`가 된다 | 패치 시리즈가 늘고 포워드포트 비용이 든다 | 보류. 재검토 조건: `ORDERED` 전환이 판정의 병목이 될 때 |

## 영향

**상류**

- 커널의 tracepoint 이름, 함수 이름, workqueue 이름이 바뀌면 규칙이 깨진다. 이름이 바뀌면 판정기는 `MISSING`을 낸다.
- kprobe 대상 함수가 인라인되면 부착이 실패한다. 현재 `receive_cb_reply`, `__cld_pipe_upcall`이 실패한다. `svc_revisit_deferred` 이벤트 이름은 존재하지 않는다(`meta.json`의 `kprobe_failed`).
- `bundle/lane/lane.sh`의 마운트 옵션이나 부팅 인자가 바뀌면 시나리오의 전제 조건이 바뀐다.

**하류**

- `report/normal-flow-corpus.md`의 흐름 상태가 이 문서의 판정을 근거로 한다.
- `bundle/corpus/nfs-normal/manifest.json`의 `execution_status`가 이 문서를 가리킨다.
- LLM Agent가 시드를 만들 때 이 문서의 지원 범위를 읽는다.

**운영**

- 자극 하나에 게스트 한 대를 쓴다. 증거 실행의 자극 시간은 7.4–92초이다(`meta.json`의 `stimulus_seconds`).
- 압축한 트레이스 크기는 56–335 KB이다.
- 이벤트 전체를 켜면 타이밍이 바뀔 수 있다. lease와 grace 시간에 미치는 영향은 미검증이다.

## 신뢰성 요구

| 항목 | 내용 |
|---|---|
| 오류 방향 | 거짓 양성(무관한 이벤트를 짝지어 전환을 주장함)이 더 위험하다. 잘못된 전환 주장은 corpus 완료로 이어진다. 거짓 음성은 시드를 더 만들게 할 뿐이다 |
| 실패 방식 | fail-closed이다. `MISSING`과 `UNPAIRED`는 통과하지 않는다. 버퍼 손실이 있으면 경고한다 |
| 관측 가능성 | 판정기가 전환마다 `submits`와 `pairs`를 출력한다. `meta.json`이 부착에 실패한 이벤트를 기록한다 |
| 재현성 | 독립된 부팅 두 번(`run1`, `run2`)에서 S2, S3, S3b, S4의 41개 전환의 판정이 모두 같다. S5의 7개와 S5b의 3개도 독립된 부팅 두 번(`nlm/try5`와 `run3`, `nlm/reboot3`와 `run3`)에서 판정이 같다. 연결 키 값(포인터, xid, pid)은 매번 다르다 |

## 검증 오라클

통과 조건:

- 시나리오 S1, S2, S3, S3b, S5, S5b의 모든 전환이 `LINKED` 또는 `ORDERED`이다. 증거 실행의 결과는 S1 11/11, S2 13/13, S3 10/10, S3b 11/11, S5 7/7, S5b 3/3이다.
- S4는 전환 7개 중 6개가 S4 자극 실행(`s4-v41-state`, `s4b-v41-grace`)에서 관측된다. S4-04는 `s1-v3-basic`에서만 관측된다.
- 음성 대조: `specific` 전환이 대조 실행에서 0개이다. 대조 실행은 S1용 `ctl-v41-basic`, S2·S3b용 `s1-v3-basic`, S3용 `s1-v3-basic`과 `ctl-v41-basic`, S4용 `ctl-v41-basic`, S5·S5b용 `run2`의 `s1-v3-basic`, `s3-v42-copy`, `ctl-v41-basic`(`run3/judgement/controls-vs-run2.txt`)이다. S5b는 S5 실행(재회수 없음)에서도 0개이다. 모두 0개이다.
- 버전 차이:
  - `S1-10`(lockd)은 v4.1 서버 시작에서 `UNPAIRED`이다.
  - `S2-06`(별도 callback 연결의 softirq)은 v4.1에서 `MISSING`이다.
  - `S2-13`(별도 연결 accept)은 v4.1에서 `UNPAIRED`이다.
  - `S3b-06`, `S3b-10`(backchannel)은 v4.0에서 `MISSING`이다.
- 버퍼 손실: 모든 증거 실행에서 `entries-in-buffer`와 `entries-written`이 같다.

이 오라클이 증명하지 않는 것:

- `ORDERED` 쌍이 같은 일이라는 사실. 시간 순서와 서로 다른 태스크만 확인한다.
- 시드의 기능 결과. 새 시드의 errno는 매니페스트가 따로 기록한다(`basic-v3-tcp.prog` 25 호출, `deleg-recall-v40-tcp.prog` 16 호출, 모두 errno 0).
- KCOV 귀속. `KCOV 귀속` 열은 코드를 읽은 결과이다.
- 트레이스에 이벤트가 없다는 사실이 코드가 실행되지 않았다는 뜻은 아니다. tracepoint가 없거나 kprobe가 부착되지 않은 지점은 보이지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| 모든 전환이 `MISSING` | 이벤트가 켜지지 않았다 | `meta.json`의 `kprobe_failed`, 트레이스의 이벤트 종류 | `events.txt`의 이름을 `/sys/kernel/tracing/events/`와 대조한다 |
| 특정 전환만 `MISSING` | 그 흐름이 일어나지 않았다 | 자극 로그의 errno, 다른 전환의 판정 | 시드와 부팅 버전을 확인한다 |
| `UNPAIRED` | 제출은 있으나 실행이 `within_us` 밖이거나 키가 다르다 | 판정기의 `submits`, 이벤트의 시각과 키 | `after`와 `within_us`를 확인한다. 소켓 콜백이 송신 중에 인라인으로 실행되면 제출 이벤트의 시각이 송신 이벤트보다 앞선다(`S2-06`에서 측정됨) |
| 판정기가 `LOSS`를 출력 | 버퍼가 넘쳤다 | 트레이스 헤더 | `buffer_size_kb`를 늘리거나 이벤트를 줄인다 |
| 대조 실행에서 `specific` 전환이 관측됨 | 규칙이 고유한 흐름을 가리키지 않는다 | 대조 실행의 짝 | 규칙에 `after`나 더 좁은 정규식을 넣는다 |
| 판정이 실행마다 다름 | 타이밍 의존 규칙 | 같은 시나리오의 두 실행 | `within_us`를 넓히거나 키를 찾는다 |

## 한계와 미결 사항

| 항목 | 상태 | 내용 |
|---|---|---|
| 목록 기준, 확정 수준 세 단계 | 결정됨 | 위 설계 절 |
| NLM 잠금 대기, GRANTED, NSM, reclaimer | 결정됨(부분) | S5, S5b가 loopback 구성에서 측정했다. lane의 veth topology에서는 측정하지 않았다. lane 마운트는 `nolock`이고 lane에 `rpc.statd`가 없다 |
| 호스트 간 NLM | 미결 | client와 server가 같은 호스트, 같은 lockd 스레드인 구성만 측정했다. 재검토 조건: client 네임스페이스에 rpcbind와 `rpc.statd`를 시작할 때 |
| lockd grace 중 `LOCK` 거부 상태 코드 | 미검증 | `LOCK` RPC가 약 5초 간격으로 반복되는 것만 관측했다 |
| GSS, TLS, pNFS, RDMA, UDP | 포기 | 환경에 없다 |
| LOCALIO 읽기·쓰기 경로 | 포기 | `nfs.localio_enabled=N`이 필수이다. probe work(C2b)만 측정됨 |
| lease 만료 → client 만료 → cld 제거 | 미결 | 25초 링크 단절에서 만료 이벤트가 0건이다. 이유 미검증 |
| v4.x에서 filecache GC(K8) | 미결 | v3 실행에서만 관측했다. 이유 미검증 |
| `receive_cb_reply`, `__cld_pipe_upcall` | 미결 | 인라인되어 kprobe가 불가능하다. 다른 이벤트(K1b, `cld_down`)로 대신 관측했다 |
| `ORDERED` 전환 | 미결 | S1-08–10, S2-02, S2-07, S2-12, S2-13, S3-08, S3-09, S3b-01, S3b-06, S3b-07, S3b-10, S4-01, S4-04, S4-05, S5-03, S5-06, S5b-02는 연결 키가 없다. 같은 일이라는 증명이 없다 |
| 트레이싱이 타이밍에 주는 영향 | 미검증 | lease와 grace에 영향을 줄 수 있다 |
| 병렬 lane | 미검증 | 자극은 lane 0만 실행한다. 4개 lane을 동시에 실행했을 때 혼입은 확인하지 않았다 |
| KCOV 귀속 열 | 미검증 | 코드를 읽은 결과이다. 실측하지 않았다 |
| 증거 위치 | 결정됨 | 증거는 저장소 밖 `~/flow-trace-evidence/run2/`에 있다. 이식하려면 `run-all.sh`로 다시 만든다 |

## Agent 사용 지침

**지원 범위**

- 시드: 경로는 `nfs-lane/client0`, `nfs-lane/client1`(knfsd)을 쓴다. 허용 syscall은 `open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`, `statx`, `lseek`, `read`, `flock`, `renameat2`, `unlinkat`이다(`bundle/corpus/nfs-normal/README.md`). 기존 COPY 시드는 목록 밖 호출 3개(`pwrite64`, `ftruncate`, `copy_file_range`)를 쓴다. manager 설정과의 관계는 미검증이다.
- NFS 버전은 시드가 정하지 않는다. 부팅 인자 `koov.nfs_version`이 정한다(`3`, `4.0`, `4.1`, `4.2`).
- 시나리오: S1, S2, S3, S3b, S4, S5, S5b. 전환 규칙은 `tools/flow-trace/scenarios/`에 있다.
- NLM 잠금은 시드로 만들 수 없다. 이유는 lane 마운트가 `nolock`이기 때문이다. S5, S5b의 셸 스크립트를 쓴다.

**비지원 범위**

- v3 시드에서 `flock`을 쓰면 안 된다. client 로컬 잠금이 되어 충돌이 일어나지 않는다(코드상).
- lease 만료를 시드로 일으킬 수 없다. `nanosleep`이 허용 목록에 없다.
- lane의 veth topology에서 NLM은 지원하지 않는다. 호스트 간 NLM은 관측하지 못했다.
- GSS, TLS, pNFS, UDP, RDMA 흐름은 환경이 지원하지 않는다.

**확장 절차**

1. 새 전환 규칙: `tools/flow-trace/scenarios/<시나리오>.json`의 `transitions`에 항목을 추가한다. 필드는 `id`, `flow`, `text`, `submit`, `execute`, `link`이다. 선택 필드는 `within_us`, `same_task_ok`, `specific`이다. `submit`과 `execute`는 `event`, `comm`, `ctx`, `detail`을 가진다. `submit`은 `after`도 가진다.
2. 새 이벤트: `tools/flow-trace/events.txt`에 `event 그룹:이름` 또는 `kprobe 라벨 심볼`을 추가한다. 이름은 `/sys/kernel/tracing/events/<그룹>/`에 있어야 한다. 없으면 `meta.json`의 `kprobe_failed`에 나타난다.
3. 새 시드: `bundle/corpus/nfs-normal/`에 `.prog`를 두고 `manifest.json`에 항목을 추가한다. `tools/test-lane-inputs.py`가 해시와 `fixture_path`를 검사한다.
4. 새 실행 주체 표지: `tools/flow-trace/subjects.json`에 표지를 추가한다.

**제약**

- lane은 단독으로 점유한다.
- 서버 시작을 추적하는 실행은 4개 lane 전체를 다시 만든다.
- 추적 창 안에서 서버를 재시작하려면 fixture 서비스가 `active`여야 한다.

**검증 방법**

세 단계는 서로 다르다. 앞 단계가 통과해도 뒤 단계가 통과한 것이 아니다.

1. 파서: `env/syzkaller/bin/syz-prog2c`가 종료 코드 0을 낸다.
2. 실행: `syz-execprog`의 모든 호출이 기대한 errno를 낸다.
3. 전환 관측: `handoffs.py`가 기대한 전환을 `LINKED` 또는 `ORDERED`로 판정한다.

## 참조

- 흐름 정의와 완료 기준: `report/normal-flow-corpus.md`
- 코퍼스 운영과 시드: `bundle/corpus/nfs-normal/README.md`, `manifest.json`
- 전체 구조와 lane 귀속: `docs/design/01-overview/01-overview.md`, `docs/design/decisions/2026-10-01-lane-attribution.md`
- 서버 callback 귀속 계획(draft): `report/xprtsock-remote-kcov-plan.md`
- fixture: `bundle/lane/lane.sh`
- 도구: `tools/flow-trace/`
- 증거: `~/flow-trace-evidence/run2/`(트레이스, `judgement/summary.txt`, `judgement/subjects.txt`)와 `~/flow-trace-evidence/run1/`(재현성 비교용 이전 실행)
- 커널 소스: `env/linux`의 `25456a766`
