# 결정 기록: NFSv4.1 서버 callback을 일으킨 프로그램에 귀속 (2026-10-05)

> 종류: 결정 기록 (임시 문서)   ·   관련 패치: kernel 0004 (`bundle/patches/kernel/0004-sunrpc-attribute-NFSv4.1-server-callbacks-to-the-pro.patch`)

## 삭제 조건

이 문서는 설계 문서가 내용을 흡수할 때까지 결정과 근거를 보존하기 위한 임시 기록이다.
아래가 **모두** 참일 때 삭제한다.

1. `docs/design/04-observation/`의 귀속 계약(04b)이 `상태: reviewed` 이상이다.
2. 04b에 아래 "결정", "검토한 대안", "검증", "남은 위험"의 내용이 반영되어 있다.

삭제할 때는 삭제 커밋 메시지에 흡수한 문서 경로를 적는다.

## 용어

| 용어 | 뜻 |
|---|---|
| 프로그램 | syz-executor가 한 번 실행하는 syzkaller 프로그램. 커널에서는 generation 하나에 대응한다 |
| generation | 프로그램 한 번의 실행에 대응하는 커널 객체. 상태는 OPEN, CLOSING, COMMITTED, ABORTED, DEAD다 |
| FINISH | executor가 프로그램 실행 뒤에 generation을 닫는 호출. 커널은 진행 중인 구간이 끝나기를 기다린다 |
| 구간 | remote 수집의 시작부터 종료까지. 구간 하나마다 Token 하나와 Ticket 하나를 쓴다 |
| 소유권 객체 | callback을 일으킨 프로그램을 가리키는 객체(`sunrpc_fuzz_cb_owner`). generation 참조, owner, cookie를 가진다 |
| 늦은 구간 | 자기 generation이 OPEN이 아닐 때 시작하려는 구간 |

## 문제

- callback은 요청에 응답한 뒤에 실행된다. 실행 위치는 callback worker, rpciod, 응답을 받는 nfsd 스레드다.
  이 코드에는 요청의 remote 구간이 이어지지 않았다.
- 그래서 callback 코드의 PC가 입력별 `.extra`에 없어도 "실행되지 않음"으로 읽을 수 없었다.
- 측정됨(2026-10-05, 변경 전 커널, `async-copy-v42-tcp.prog` 1회): `.extra`에 callback 관련 함수는
  `nfsd4_run_cb`, `nfsd4_send_cb_offload`, `nfsd41_cb_referring_call`뿐이었다. 부모 쪽 함수다.
  RPC 쪽 함수(`bc_send_request`, `nfs4_xdr_enc_cb_offload`, `nfsd4_cb_done` 등)는 없었다.

## 결정

**D1. callback의 작업 수명은 generation 참조로만 유지한다. outstanding Token으로 세지 않는다.**
callback이 큐에 들어갈 때 현재 태스크가 실행 중인 구간에서 소유권 객체를 만든다. 구간을 열 때마다 이 참조에서 새 Token을 만든다.
- 근거: 코드상, callback에는 `rpc_delay(2 * HZ)` 재시도가 있다. 작업 Token을 FINISH가 기다리면 재시도만으로 FINISH가 시간을 넘겨
  generation이 abort된다. 그러면 같은 프로그램의 기존 서버 aggregate도 발행되지 않는다.
- 대가: FINISH 이후에 시작하려는 늦은 구간은 거부한다. 그 PC는 버려진다. 거부는 카운터로 센다.

**D2. 구간은 generation이 OPEN일 때만 연다.** CLOSING, COMMITTED, ABORTED에서는 거부하고 사유별 카운터를 올린다.
- 근거: CLOSING에서 새 구간을 허용하면 FINISH의 배출이 끝나지 않는다.

**D3. 같은 callback에 이벤트가 합쳐지면 최초 소유자를 유지한다.** 소유권 객체는 `cmpxchg`로 한 번만 저장한다.
- 근거: 이미 큐에 있는 callback에 후발 이벤트가 합쳐지면 한 번의 실행을 한 프로그램에만 귀속시킬 수 있다.
- 대가: 후발 이벤트의 귀속은 포기한다.

**D4. 구간은 RPC task의 `tk_action` 한 단계마다 연다.** 자원 해제와 calldata 해제도 구간으로 감싼다.
- 근거: callback 전용 XDR 인코딩과 디코딩은 `xprt_request_transmit()` 안이 아니라 task 상태 머신의 단계에서 실행된다.
  송신과 응답만 수집하면 이 코드를 놓친다.
- 근거: 구간은 `RPC_IS_QUEUED` 검사 앞에서 끝난다. 그 뒤에는 다른 worker가 task를 가져갈 수 있다.
- 조건: 호출 스레드가 같은 owner의 구간을 이미 실행 중이면 새 Ticket을 열지 않고 그 구간을 공유한다.

**D5. 응답은 `queue_lock`을 풀고 구간을 연 뒤 같은 요청인지 다시 확인한다.** `receive_cb_reply()`는 요청을 pin하고 잠금을 푼다.
- 근거: Ticket 발급은 sleep할 수 있어 spinlock 안에서 호출할 수 없다.
- 근거: 이 경로는 `svc_tcp_recvfrom()`이 lane의 현재 generation에 붙이는 WIRE work를 쓰지 않는다. 원래 generation만 쓴다.

**D6. 다음 항목은 이번에 귀속하지 않는다(결정됨, 후속).** `bc_close`, `bc_destroy`, CB_NULL probe가 실행하는 연결 설정(`xs_setup_bc_tcp`).
- 근거(측정됨, 2026-10-05, kprobe, 1회): `bc_close`는 nfsd 스레드의 `svc_recv` 경로에서, `bc_destroy`는 system workqueue에서 실행된다.
  두 곳 모두 요청 구간 밖이다. 현재 corpus의 정적 프로그램은 응답에서 얻은 clientid가 없어 세션 생성에 도달하지 못한다.
  귀속해도 fuzzer가 받는 피드백이 없다.
- 재검토 조건: 응답에서 clientid를 얻어 쓰는 입력이나 fixture가 생긴다.

## 검토한 대안

| 안 | 얻는 것 | 결과 |
|---|---|---|
| callback 실행 때 lane의 최신 generation 조회 | 코드가 짧다 | 기각. 늦은 callback이 다음 프로그램에 귀속된다 |
| callback 작업 Token을 FINISH가 기다림 | FINISH 이전 PC를 더 수집한다 | 기각(D1) |
| 송신과 응답만 수집 | 다른 task의 요청이 섞이지 않는다 | 기각(D4). XDR 코드를 놓친다 |
| RPC scheduler 전체를 한 구간으로 수집 | 범위가 넓다 | 기각. `xprt_transmit()`이 다른 task의 요청을 대신 보내므로 다른 owner의 PC가 섞인다 |
| 잠금 없이 Ticket 발급(사전 확보한 scratch pool) | `receive_cb_reply()`의 unlock이 필요 없다 | 보류. kcov에 새 발급 경로가 필요하다. D5의 재검증 경쟁이 문제가 되면 재검토한다 |

## 검증

모두 KASAN 커널, `syz-execprog`, 2026-10-05, 1회 실행의 값이다. 원시 증거는 보존하지 않았다(저장소 밖 `/tmp`에서 실행).

| 항목 | 결과 |
|---|---|
| `.extra` 비교(`async-copy-v42-tcp.prog`) | 변경 후 `bc_malloc`, `bc_send_request`, `bc_free`, `nfs4_xdr_enc_cb_offload`, `nfs4_xdr_dec_cb_offload`, `nfsd4_cb_done`, `receive_cb_reply`, `xprt_complete_rqst`, `call_encode/transmit/decode`가 추가로 나타남. 변경 전 이미지(2026-10-02 빌드)와 변경 후 커널의 소스가 이 패치 외에 같다는 것은 보장하지 않는다 |
| lane 4개 혼합(COPY와 일반 프로그램, 각 30회) | offload 전용 함수 PC가 COPY 프로그램 29/30, 일반 프로그램 0/30. KCSAN 커널 12회는 11/12, 0/12 |
| 늦은 callback(CB_OFFLOAD를 1500 ms 늦춤, 3회) | COPY 프로그램 `.extra`의 offload PC 0개, 이후 일반 프로그램 11개 모두 0개. 지연 0일 때 COPY 18개 |
| abort(실행기 종료 중 CB_OFFLOAD가 대기, 4500·6000 ms, 3회) | 이후 일반 프로그램 8개가 매번 완료, offload PC 0개, 늦은 구간 19개가 abort 사유로 거부됨 |
| 정리 | 각 실행 뒤 `live_cb_owner`, `remote_refs` 0, token 생성과 완료 수 일치 |
| 처리량(lane 4개, 기준 커널 대비) | 혼합 -7.2%, COPY만 +4.3%. 같은 구성 안의 편차가 약 ±20%라 약 10% 이하의 차이는 구분하지 못함 |

KASAN이 구현 중에 `rpc_free_task()`의 slab-use-after-free를 보고했다. NFS 클라이언트의 RPC task가 `nfs_pgio_header`에 내장되어 있어
`rpc_release_calldata()`가 task 메모리를 해제하기 때문이다. `task->tk_fuzz_owner`를 release 전에 읽도록 고쳤다.

검증이 증명하지 않는 것: 함수 PC가 있다는 사실은 그 함수 영역에 도달했다는 증거다. 같은 callback의 순서 증거가 아니다.
두 프로그램이 같은 종류의 callback을 만들면 서명 비교로 섞임을 구분하지 못한다.

## 시험용 장치와 재검증 방법

늦은 callback과 abort 시험에는 CB_OFFLOAD를 지정한 시간만큼 늦게 queue하는 시험용 장치를 썼다. 패치에는 넣지 않았다. 새 커널로 이월한 뒤
같은 시험을 하려면 다음을 다시 만든다.

1. debugfs 정수 파일(`cb_fault_delay_ms`)을 `net/sunrpc/fuzz.c`에 만든다.
2. `nfsd4_queue_cb()`에서 `cb->cb_ops->opcode == OP_CB_OFFLOAD`이고 값이 0이 아니면 `queue_delayed_work()`로 늦게 `cb_work`를 queue한다.
3. worker 안에서 `msleep()`으로 늦추지 않는다. 같은 client의 callback worker(`nfsd4_callbacks` workqueue)가 막혀 이후 프로그램의 요청이 지연되고 generation이 abort된다(측정됨, 2026-10-05).

## 남은 위험

| 위험 | 상태 |
|---|---|
| 늦은 구간의 PC 손실. 시도한 구간 중 거부 비율 | 측정됨: 실행마다 0.9%에서 12%. 편차가 커서 대표값으로 쓰지 않는다 |
| callback이 길게 막히면 그 프로그램의 generation이 FINISH 시간(`1000 × slowdown` ms) 안에 정리되지 못해 abort됨 | 시험용 장치로만 관측. 자연 상황은 미검증 |
| 구간 구조체를 스택에 두므로 모든 경로가 시작 실패나 종료로 Token을 끝내야 한다 | 코드상 확인, 모든 경로를 시험하지는 않음. RPC 할당 실패와 namespace 종료 중 callback은 미검증 |
| 처리량과 메모리 비용 | 처리량은 위 표, 메모리는 미검증(`scratch_peak`는 5, 풀에서 재사용) |
| delegation recall, CB_NULL probe, NFSv4.0 callback, `bc_close`와 `bc_destroy` | 미검증 또는 미구현(D6) |
| KCSAN 커널의 데이터 경쟁 보고 | 일반 커널 코드의 경쟁이 보고됨. 이번 변경이 건드린 함수는 읽은 범위(dmesg 앞 80줄)에 없음. 전체 호출 스택은 미확인 |
