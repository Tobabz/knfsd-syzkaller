# 결정 기록: 요청 단위 귀속에서 lane 단위 귀속으로 (2026-09-30 ~ 10-01)

> 종류: 결정 기록 (임시 문서)   ·   관련 커밋: `4075e44`, `fe294cc`

## 삭제 조건

이 문서는 설계 문서가 내용을 흡수할 때까지 결정과 근거를 보존하기 위한 임시 기록이다. 아래가 **모두** 충족되면 삭제한다.

1. `docs/design/04-observation/`의 remote KCOV 개요(04a)와 귀속 계약(04b)이 `상태: reviewed` 이상이다.
2. 04b에 아래 "결정", "검토한 대안", "실험", "남은 위험"의 내용이 반영되어 있다(요약이어도 출처가 있으면 된다).
3. `docs/design/03-execution-env/`의 lane 문서(03a)에 "lane 단독 점유가 귀속의 전제"라는 불변 조건이 반영되어 있다.

삭제할 때는 삭제 커밋 메시지에 흡수한 문서 경로를 적는다.

## 문제

- 기존 귀속(구 kernel 0001~0011)은 서버가 `accept`한 TCP 연결의 4-tuple을 클라이언트가 SYN 전에 등록한 항목과 짝짓고
  (`sunrpc_fuzz_svc_pair`), 연결별 레코드 순번(ordinal)으로 클라이언트가 남긴 `wire_work`를 찾아 소유자를 정했다.
- NFS wire 프록시는 클라이언트 연결을 끊고 백엔드로 새 연결을 연다. 4-tuple이 달라져 짝짓기가 전부 실패했다.
  측정: 프록시 경유 연결 모두 `PENDING_CONNECT`, `server_attached=0`, `.extra` 0/30, `remote_start_ok` 0.
- 프록시의 레코드 중계 자체는 1:1이었다(프록시 `c2s` 수 = 클라이언트 `c2s_tx`).
- skb에 실린 `kcov_handle`은 서버가 승인 전에 지우는 출처 정보일 뿐 승인에 쓰이지 않았다.

## 결정

**lane 단위 귀속.** lane N의 서버 netns가 받은 요청은 proc N(KCOV common handle N+1)이 지금 실행 중인 프로그램의 것으로 본다.

- 근거 1: lane은 proc 하나가 단독 점유한다. executor는 `/syz-nfs-lanes/proc-<procid>/.lane_id`가 자기 procid와
  같을 때만 lane을 가져오고, 프로그램을 하나씩 순차 실행한다. **이 조건이 깨지면(lane 공유) 이 설계는 성립하지 않는다.**
- 근거 2: executor handle은 `kcov_remote_handle(COMMON, procid + 1)`로 고정 계산되므로 커널이 `lane_id + 1`로 구할 수 있다.
- 근거 3: syzkaller 피드백(`.extra`)은 원래 프로그램 단위 집계다. 요청 단위 정밀도는 소비자가 없었다.
- 경계 차단: 소유자는 handle의 **현재 generation**이다. 닫히는 중이거나 닫힌 generation은 새 root를 거부하므로,
  프로그램이 끝난 뒤 도착한 요청은 소유자가 없어진다. 지연·비동기 작업은 원래 generation에 묶인 자식 토큰을 쓴다.
- 구현 위치: 현재 kernel 0002(`net/sunrpc/fuzz.c`의 `lane_owner_work`, `sunrpc_fuzz_svc_record_received`),
  0001(`kcov_request_current_generation`). fixture는 이미 netns를 lane domain에 등록하고 있어 변경이 없다.
- 끄는 방법: `sunrpc.lane_attribution=0`(부팅 인자 또는 `/sys/module/sunrpc/parameters/`). 끄면 귀속이 없다
  (요청 단위 장치는 제거됨).

## 검토한 대안

| 안 | 내용 | 결과 |
|---|---|---|
| A. 별칭 짝짓기 | 프록시가 백엔드 연결 4-tuple을 클라이언트 연결에 대응시켜 debugfs로 등록 | 레코드 수를 바꾸는 변조에 대응 못함. 채택 안 함 |
| C. 레코드 단위 매핑 | 연결 별칭 + 프록시가 드롭·삽입·순서 바꿈을 이벤트로 커널에 알림 | 한때 확정했으나 lane 단위 귀속이 같은 문제를 더 단순하게 풀어 철회 |
| XID 기반 대응 | RPC의 XID로 요청 대응 | 요청 단위 정밀도가 필요할 때의 대안. XID 유일성 보장과 XID 변조 처리 필요. 보류 |
| 투명 프록시 | 클라이언트 주소로 백엔드에 연결 | 서버 주소·포트가 리슨과 백엔드로 갈라져 성립하지 않음 |

## 실험 (KASAN, syz-execprog, 프로그램 30회)

원시 증거는 보존하지 않았다(작업 디렉터리 삭제). 아래 수치가 남은 기록이다.

| 실험 | 결과 |
|---|---|
| 프록시 경유 (기존 방식) | `.extra` 0/30 |
| 직접 / 프록시 경유 (lane) | 30/30 / 30/30, fs/nfsd 1,812 vs 요청 단위 1,747 (상위집합) |
| 늘어난 커버리지 | close 뒤 비동기 `DELEGRETURN`, `FREE_STATEID` 등. 요청 단위에서는 소유자가 없던 정상 흐름 |
| 줄어든 커버리지 | 대부분 계측 자신의 장부 함수(`commit_tx`, `reserve_tx`) |
| 비동기 COPY | fs/nfsd 1,413으로 동일, CB_OFFLOAD 경로 포함 |
| lane 간 혼입 | lane 2개, executor는 lane 0만, lane 1에 `LINK` 약 345회 주입 → lane 0 프로그램 0/60에서 검출. 양성 대조 60/60 |
| 경계(A/B 번갈아) | B로 누출 0/30. 프로그램 사이 도착분(약 200건)은 `lane_owner_no_generation`으로 버려짐 |
| 늦은 비동기 작업 | executor의 `close_fds()`가 generation 종료 뒤 fd를 닫는 점을 이용(A'이 파일을 닫지 않음, 열린 채 unlink). 늦은 요청 121건이 `lane_owner_failed`로 거부, B로 누출 0/30 |
| `syz-manager` 10분 (lane 4개) | fs/nfsd 2,040 PC, crash 0 (요청 단위 1,982, 1회 비교라 차이는 잡음 수준) |
| 축소 시리즈(rc5) | 직접 1,809 / 프록시 1,809 / raw 676 / COPY 1,413, KCSAN 직접 1,798, 모두 30/30, generation abort 0 |

## 제거한 장치 (`fe294cc`)

클라이언트 논리 출처 추적(`fs/nfs`, `rpc_task`), TCP 연결 짝짓기와 ordinal(`net/ipv4`, `struct sock`), raw 소켓 귀속
`TCP_SUNRPC_FUZZ`(uapi), skb 출처 handle, 클라이언트 토큰 진단, 시험용 결함 주입. 커널 시리즈 14 → 3,
rc5 대비 44개 파일 9,890줄 → 19개 파일 약 6,200줄. syzkaller 0018로 raw RPC를 일반 TCP로 전송
(`syz_send_nfs_fuzz` 인자 값 유지, `write$inet_nfs_fuzz` 추가).

## 발견한 함정

- `syz-manager` VM 부팅 인자에 `nfs.localio_enabled=N`이 없으면 이미지의 lane fixture가 시작을 거부해 NFS에 전혀 닿지 않는다
  (README에 반영, `e2b3201`).
- 2026-10-01 기준 저장소 `env/syzkaller/bin`의 `syz-manager`(74ad462)와 `syz-executor`(9316aaa+) 리비전이 달라
  manager가 실행을 거부했다. 같은 트리에서 manager를 다시 빌드해야 한다.
- 기존 A/B 하네스는 제거된 debugfs 파일(`phase3_stats` 등)을 읽으므로 새 커널에서 쓸 수 없다. 대체 검증 스크립트는
  WSL `~/prune-evidence/inputs/verify-lane.py`(저장소 밖)에 있다.
- `bundle/corpus/nfs-normal/async-copy-v42-tcp.prog`는 syzkaller 엄격 해석에서 실패한다(이 작업 이전부터). `syz-execprog`는 통과.

## 남은 위험

| 위험 | 상태 |
|---|---|
| 늦은 요청이 다음 프로그램이 이미 시작된 뒤 도착하면 다음 프로그램에 귀속 | 관측 안 됨(30회). `lane_owner_failed`로 규모 감시 |
| 같은 lane에 프로그램 밖 트래픽이 들어오면 실행 중 프로그램에 귀속 | 설계상 성질. lane에 다른 트래픽원이 없어야 함 |
| 긴 비동기 작업이 배출 대기(`1000 × slowdown` ms, executor FINISH)를 넘으면 그 프로그램 generation abort | 32 MiB COPY에서는 발생 안 함. 더 큰 작업은 미검증 |
| 레코드 수를 바꾸는 프록시 변조 | 구조상 무관하지만 미검증 |
| 전송 단계(NF-A1)와 백그라운드 분류 | lane 단위로는 다른 클라이언트 혼입 우려가 사라졌으나 미구현. `report/nfa1-kcov-feedback-design.md`의 결론은 요청 단위 전제라 재검토 필요 |
