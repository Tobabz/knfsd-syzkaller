# 재현 파이프라인 개요

> 상태: draft   ·   최종 확인: 2026-10-02   ·   기준: kernel `v7.3-rc5` / syzkaller `801f09666`
> 관련 패치: kernel 0001~0003, syzkaller 0001~0018   ·   관련 게이트: R1, R2, R4, R5

## 요약

이 도구는 LLM Agent가 식별한 NFS 취약 시나리오를 syzkaller 환경에서 실행하고, KASAN/KCSAN이
보고하는 이상으로 재현을 판정한다. Agent는 이 설계 문서를 읽고 시나리오에 필요한 syzlang과
pseudo-syscall을 만들며, 목표는 현재 퍼징 환경이 지원하는 범위 안에서 그것을 만드는 것이다.
시나리오가 의도한 서버 경로까지 도달했는지는 remote KCOV로 확인하고, 시나리오가 요구하는 변조는
프록시가 주입한다. 도달 여부를 잘못 읽으면 "재현 실패"와 "seed 오동작"을 구분할 수 없다.

> 이 문서 시리즈의 독자는 사람과 LLM Agent다. 그래서 각 문서는 "무엇이 지원되고, 무엇이 지원되지
> 않으며, 확장하려면 어디를 고쳐야 하는가"를 명시한다(`00-writing-guidelines.md` 8절).

## 해결하려는 문제

취약 시나리오를 재현한다는 것은 "sanitizer가 이상을 보고했는가"만의 문제가 아니다.
보고가 없을 때 그 이유가 취약점이 없어서인지, seed가 의도한 경로에 닿지 못해서인지 가려야 한다.
이 도구는 그 구분을 위해 다음 다섯 문제를 푼다.

| # | 문제 | 해결 요소 | 근거 |
|---|---|---|---|
| 1 | 서버 쪽 처리는 nfsd 커널 스레드에서 일어나 executor 스레드의 KCOV로는 보이지 않는다 | remote KCOV (kernel 0001~0003) | `README.md`의 Coverage model |
| 2 | 도달 여부를 알 수 없으면 PC가 없는 이유를 "미실행"으로 오독한다 | 소유권 계약과 관측 진단 카운터 | `report/nfa1-kcov-feedback-design.md` |
| 3 | syzkaller는 syscall을 변조하는데, syscall 인자로는 NFS operation 단위의 뮤테이션이 되지 않는 경우가 있다 | pseudo-syscall과 프로토콜 형태 연산 (syzkaller 0006, 0015) | 설계 의도(사용자 확인). 코드 대조는 아래 "주장 검증" 참조 |
| 4 | NFS 클라이언트를 대상으로 하는 취약점을 트리거하려면 서버의 응답을 변조해야 한다 | wire 프록시와 arm 규칙 (syzkaller 0017) | 설계 의도(사용자 확인). 프록시에 S2C 방향 변조가 구현되어 있음 (`tools/nfs-proxy/README.md`) |
| 5 | 동시 퍼징 시 프로세스 간 상태가 섞이면 결과를 해석할 수 없다 | lane과 namespace 격리 (syzkaller 0007~0014) | `tools/README.md` B절 |

여섯 번째 요소인 NFS-Ganesha는 추가 서버 대상이다. v4.1 기본 시드는 서버별로 두 개를
유지하되 하나의 syz-manager corpus에서 함께 퍼징한다. 병렬 처리량 이득과 프록시의 실행
대상 선택 확장은 후속 검토 범위이며, 이득은 미실증이다
(`tools/README.md`의 축 A "미실증").

## 구조

### 재현 흐름

```text
 +-----------+   설계 문서를 읽고 syzlang / pseudo-syscall / arm 규칙 생성
 | LLM Agent |------------------------------------------+
 +-----------+   (저장소에 구현 없음. 문서가 유일한 입력)   |
                                                          v
+------------------------- guest VM (KASAN | KCSAN) ------------------------+
|                                                                           |
|  syz-executor proc-N                                                      |
|   |  pseudo-syscall: syz_open_nfs_lane_pair, syz_arm_nfs_proxy ...        |
|   |                                                                       |
|   |--arm 규칙--> +-----------+                                            |
|   |              | nfs-proxy |(W) C2S/S2C wire 변조                       |
|   v              +-----+-----+                                            |
|  NFS client ---RPC---->|----RPC----> knfsd nfsd 스레드 (K)                |
|  (client netns)        |                    |                             |
|                        |                    | PC (remote KCOV, R)         |
|  coverage/.extra <-----------------------------+                          |
|  sanitizer 보고 (S) ---> dmesg / serial                                   |
+---------------------------------------------------------------------------+
        | coverage, sunrpc_fuzz debugfs 카운터, dmesg
        v
   [ 판정 ]   Q1: seed가 의도한 경로에 도달했는가   <- R, 카운터
              Q2: sanitizer가 이상을 보고했는가     <- S

 (K)=서버 처리 지점  (R)=remote KCOV 계측  (W)=변조 지점  (S)=sanitizer 보고
 읽는 순서: Agent에서 시작해 위에서 아래로. 기본 이미지의 NFS 마운트는 프록시를 거친다.
```

기본 이미지는 `bundle/lane/lane.sh` 하나를 사용하며 `SERVER_IMPL=both`로 두 서버를 프록시 뒤에 둔다.
NFSv3 시드와 별도 fixture는 제거했고, bake의 `--minor 1|2`는 두 서버의 마운트 버전을 선택한다.
기존 Debian Ganesha 4.3-2는 v4.2의 직접·프록시 경로에서 기존 파일과 다른
클라이언트가 쓴 파일을 0으로 읽었다. 클라이언트의 `READ_PLUS` 호출이 관측됐고,
4.3-2가 FSAL_VFS에 `read_arg->info`를 전달하지 않는 결함을 확인했다.
현재 lane은 이 경로가 수정된 Ganesha V15.6을 사용한다. V15.6의 FSAL_VFS는
`tmpfs` export를 제외하므로 Ganesha만 크기가 제한된 ext4 루프 저장소를 사용하고,
knfsd는 기존 tmpfs를 유지한다. v4.1과 v4.2 게스트에서 네 마운트의 교차 읽기·쓰기,
Ganesha 직접 연결, 정리와 루프 장치 해제를 확인했다. v4.2 프록시에서는 실제
`READ_PLUS` 호출도 계측했다.
기존 시드의 `nfs-lane/client0`·`client1`은 같은 knfsd export를 사용하는 두 클라이언트로 유지한다.
Ganesha는 `client0-ganesha`·`client1-ganesha` 경로로 선택한다. 두 서버의 저장 공간은 분리되어 있다.
`SERVER_IMPL=knfsd|ganesha` 직접 경로는 별도 비교 진단에만 사용하며 기본 이미지에는 적용하지 않는다.

<a id="backend-execution-decision"></a>

### 서버별 실행 결정 (2026-10-02)

**결정됨.** knfsd와 Ganesha는 서로 다른 34호출 시드를 하나의 syz-manager corpus에
넣어 퍼징한다. 각 시드의 두 클라이언트는 같은 서버의 export를 사용한다.
`basic-v41-tcp.prog`는 기본 knfsd 경로를, `basic-v41-ganesha-tcp.prog`는 명시적
Ganesha 경로를 쓴다. 기능 오라클 확인은 서버별 스냅샷에서 따로 수행했다.

34개 호출을 두 번 붙인 통합안은 채택하지 않는다. 고정된 syzkaller의 `prog.MaxCalls`는 40이며
`pkg/manager/seeds.go`의 `parseProg`가 초과 입력을 거부한다. 일반 변이와 최소화도 두 서버
구간의 동일성이나 보존을 보장하지 않는다. 자동으로 양쪽에 같은 입력을 재실행하는 기능은 없다.

**후속 계획.** 동일 시나리오의 실행 대상을 프록시에서 선택·관리하는 라우팅 확장은 추후 설계와
구현으로 남긴다. 기존의 고정 중계 경로와 구분하며, 실행 중인 NFS 세션을 다른 서버로 바꾸거나
요청을 양쪽에 복제하는 기능을 지원한다고 간주하지 않는다. 서버별 상태 격리와 결과 구분은
후속 설계에서 검토한다. 처리량 이득은 미검증이다. 2026-10-02 현재 KASAN v4.1
이미지에서 knfsd와 Ganesha가 각각 34개 호출의 errno 오라클을 단회 통과했다.
knfsd의 raw `.extra`에는 77,314개 PC 레코드와 1,581개의 서로 다른 `fs/nfsd`
소스 위치가 있고, Ganesha에는 로컬 클라이언트 커널 커버리지 파일만 있다.
두 시드는 syz-manager의 `corpus.db`에 수용되어 `corpus-triage`가 종료 코드 0으로
끝났다. 3분 제한 단일 매니저 퍼징은 파일 연산 syscall만 활성화한 설정에서 크래시
없이 7,791회를 실행했고, 두 시드의 정규화된 34호출 프로그램을 corpus에 유지했다.
근거는 `cache/backend-current-v41-20261002/{knfsd,ganesha}/result.json`,
`cache/manager-corpus-v41-20261002/result.json`,
`cache/manager-unified-v41-20261002/{focused-smoke,corpus-inspection}.json`이다. Ganesha 사용자 공간 커버리지와
요청별 RPC handoff는 이 실행에서 확인하지 않았다.

### 판정 논리

| Q1 도달 | Q2 sanitizer 보고 | 해석 | 다음 행동 |
|---|---|---|---|
| 아니오 | (무관) | seed 오동작 또는 환경 문제. 재현 실패가 아니다 | 어디서 막혔는지 진단 (04, 05 문서) |
| 예 | 아니오 | 시나리오는 실행됐으나 이상이 관측되지 않음 | 조건(타이밍, 변조 위치)을 재검토 |
| 예 | 예 | 재현 후보 | 보고 내용과 시나리오의 대응을 확인 |

KCSAN 보고는 치명적 오류가 아니라 발견(finding)이다. 보고 뒤에도 커널이 계속 실행되므로
러너는 `BUG: KCSAN:` 배너를 치명 판정에서 제외한다(`tools/run-reach-adapted.py`의 `FATAL_RE`).

### 요소와 구현 상태

| 요소 | 역할 | 구현 상태 | 상세 문서 |
|---|---|---|---|
| LLM Agent 연동 | 설계 문서로 syzlang, pseudo-syscall, arm 규칙을 생성 | 저장소에 코드 **없음**. 설계 문서가 입력이며, 지원 범위와 확장 절차를 02에서 정의 | 02 |
| pseudo-syscall, 기술 파일 | seed가 NFS 프로토콜을 다루게 함 | 구현됨 | 02 |
| lane, namespace | 프로세스별 격리된 NFS 환경 | 구현됨 | 03 |
| remote KCOV | 서버 경로 도달 관측 | 구현됨 (knfsd 한정) | 04 |
| nfs-proxy | wire 변조 주입 | 구현됨. 게스트 A/B 통과 | 05 |
| Ganesha 병렬 축 | 동시 퍼징 처리량 | 릴레이 검증 통과, 처리량 이득 미실증 | 06 |
| 재현 판정 | Q1, Q2 종합 | 개별 러너는 있으나 통합 판정은 **없음** | 07 |

기본 운용 방식은 `syz-manager` 퍼징이다. 이 문서의 근거로 쓴 증거는 모두 결정적 `syz-execprog` 실행에서
나왔고, `syz-manager` 기반으로 이 파이프라인을 돌린 증거는 저장소에서 **확인하지 못했다**.

### 주장 검증: 왜 프록시와 pseudo-syscall인가

설계 의도(문제 3, 4)를 코드와 대조한 결과다. 상태는 `확인` / `부분` / `미검증`으로 구분한다.

| 주장 | 상태 | 확인한 것 | 남은 검증 |
|---|---|---|---|
| syscall 인자 뮤테이션은 NFS operation의 wire 표현을 직접 바꾸지 못한다 | 부분 | `write$nfs` 등 표준 syscall 기술은 커널 NFS 클라이언트를 거쳐 RPC가 만들어진다(`fs_nfs_fuzz.txt`) | 특정 operation이 표준 syscall로 도달 불가함을 보이는 대조 실험 |
| pseudo-syscall이 이 공백을 메운다 | 부분 | `syz_send_nfs_fuzz`와 `sendmsg$inet_nfs_fuzz_*`가 RPC/XDR 메시지를 직접 전송하고, `nfs4_op_arg` 등으로 NFSv4 COMPOUND의 operation을 기술한다(`socket_inet_nfs.txt`). 즉 C2S 방향의 operation 뮤테이션은 raw 전송 경로로 가능하다 | raw 경로로 만든 요청이 클라이언트 세션 상태(세션, slot, stateid)에 의존하는 operation에 유효한지 |
| 클라이언트 취약점은 서버 응답 변조가 필요하고, 이는 프록시로만 가능하다 | 부분 | raw 경로는 C2S 전용이다. S2C 변조는 프록시의 `direction=1` arm이 유일하게 구현되어 있다. 게스트 실험에서 C2S와 S2C 양방향 변조가 적용·재생됐다 | 변조된 응답이 실제로 클라이언트 취약점을 트리거하는 사례. 현재 증거는 XID 변조의 적용까지다 |

## 설계

1. **판정을 둘로 나눈다.** 도달(Q1)과 이상 보고(Q2)를 별개의 관측으로 유지한다.
2. **도달은 remote KCOV와 카운터로 판정한다.** 서버 스레드의 PC를 시나리오 실행에 귀속한다.
   귀속 단위는 **lane**이다. lane N의 서버가 받은 요청은 proc N이 그때 실행 중인 프로그램의 것이다(kernel 0002).
3. **변조는 프록시 한 곳에서 한다.** 변조 규칙은 seed에 포함되어 프로그램과 함께 재현된다.
4. **격리는 lane 단위로 한다.** 한 프로세스의 상태가 다른 프로세스의 관측에 섞이지 않게 한다.
5. **sanitizer는 대상 서버가 실행되는 곳에 둔다.** knfsd는 커널 계측(KASAN/KCSAN)이다.
6. **실패는 조용히 하지 않는다.** 정지한 lane은 fail-closed로 처리한다(syzkaller 0008, 0013).

## 설계 근거

| 결정 | 근거 |
|---|---|
| 판정 분리 | 보고가 없을 때 원인이 취약점 부재인지 seed 오동작인지 가르려면 서로 다른 관측이 필요하다 |
| remote KCOV | knfsd는 커널 스레드가 요청을 처리해서 호출자 KCOV로는 보이지 않는다 |
| 변조 지점 단일화 | 변조가 seed 바이트에 들어 있어야 같은 입력이 같은 변조를 재현한다. 프록시에는 PRNG가 없다 |
| lane 격리 | 동시 실행 프로그램의 요청이 서로의 커버리지에 귀속되면 도달 판정이 오염된다 |
| lane 단위 귀속 | lane은 proc 하나가 단독 점유한다. 그래서 서버 netns만 보고 소유자를 정할 수 있고, TCP를 끊는 프록시나 레코드를 바꾸는 변조에도 귀속이 유지된다 |
| KCSAN 비치명 | KCSAN 보고 뒤에도 커널이 살아 있어, 치명 보고와 같이 처리하면 유효한 실행을 버린다 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 판단 |
|---|---|---|---|
| 도달 관측 없이 sanitizer 보고만 판정 | 구현이 단순함 | 미보고의 원인을 가릴 수 없음 | 기각 |
| 전역 KCOV 핸들 하나로 서버 스레드 수집 | 귀속 규칙이 필요 없음 | 동시 클라이언트의 PC가 섞임 | 기각. 전역 핸들은 진단 전용 (04c) |
| 요청 단위 귀속 (TCP 연결 짝짓기 + ordinal) | 프로그램 안의 요청 하나까지 구분 | 프록시를 거치면 짝짓기가 끊겨 `.extra` 0/30. syzkaller는 프로그램 단위 집계만 쓴다 | 기존 방식. lane 단위로 대체 (`lane_attribution=0`으로 비교 가능) |
| 레코드 단위 매핑 (프록시가 커널에 대응을 알림) | 레코드 수를 바꾸는 변조에도 대응 | 프록시와 커널 사이 프로토콜과 상태가 늘어남 | lane 단위 귀속이 같은 문제를 더 단순하게 풀어 철회 |
| 클라이언트 커널에 변조 기능 추가 | 프록시가 필요 없음 | 서버 응답 변조는 클라이언트 쪽에서 만들 수 없음 | 기각 (S2C 변조 불가) |

## 영향

- **상류.** 패치 시리즈와 커널·syzkaller 핀이 바뀌면 remote KCOV 계약과 pseudo-syscall ABI가 깨질 수 있다.
  포워드포트 파이프라인이 R1, R2, R4, R5로 이를 판정한다.
- **하류.** Q1 판정이 틀리면 재현 실패와 seed 오동작이 섞이고, 07의 재현 판정이 무의미해진다.
- **운영.** remote KCOV 활성 시 처리량 비용이 있다(R3는 환경 잡음으로 철회). Ganesha 축은 처리량 이득이
  미실증이다. 격리 fixture는 tmpfs 256 MiB 상한 등 자원 비용이 있다.

## 신뢰성 요구

이 파이프라인에서 가장 위험한 오류는 **Q1의 거짓 음성**이다. 실제로는 도달했는데 도달하지 않았다고
판정하면 시나리오를 고치는 방향으로 잘못된 수정이 이어진다. 반대로 거짓 양성은 재현이 없는데 있다고
판단하게 해서 07의 결론을 오염시킨다.

| 항목 | 요구 |
|---|---|
| 오류 방향 | Q1 거짓 음성이 가장 위험. 계측 누락(포화, 진행 중 section 폐기)을 "관측 없음"과 구분해 드러낼 것 |
| 실패 방식 | fail-closed. 정지한 lane, 죽은 서버는 정상으로 기록하지 않는다 |
| 관측 가능성 | debugfs `sunrpc_fuzz` 카운터, dmesg, 이미지 해시로 실행 후 사후 검증 |
| 재현성 | seed, arm 규칙, 픽스처 스크립트의 SHA-256을 시나리오 manifest에 고정 |

## 검증 오라클

시나리오 검증은 커널 카운터와 커버리지로 판정한다. 이를 자동화하던 러너(`tools/attr-scenario-run.py` 등)는
2026-10-01 커밋 `7833ed3`에서 제거되었다. 아래 오라클은 판정 기준으로 유지한다.

| 확인 | 오라클 |
|---|---|
| 입력 동일성 | seed와 픽스처의 SHA-256이 manifest와 일치 (불일치 시 부팅 전에 거부) |
| 도달 (Q1) | `generation_begin`, `remote_start_ok`, `aggregate_published` 등의 카운터 증가와, 서버 측 sentinel 함수의 커버리지 존재 (`fs/nfsd`는 remote KCOV ON에서만) |
| 부작용 없음 | `generation_aborted`, `scratch_overflow`가 0 (시나리오별 기대값) |
| 정리 | 참조 카운터가 0으로 배출 (`outstanding_tokens`, `remote_refs` 등) |
| 이미지 무변경 | 실행 전후 이미지 해시 동일 |

이 오라클이 증명하지 않는 것: sentinel PC의 존재는 구간 도달 증거이지 같은 요청의 순서나 handoff 증거가
아니다(`report/nfa1-kcov-feedback-design.md`). Q2와 통합한 재현 판정은 07의 범위다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| sentinel PC 없음 | 미실행, 귀속 실패, 버퍼 포화, 진행 중 section 폐기 | `scratch_overflow`, `generation_aborted`, 카운터 배출 | 04b, 04c |
| seed 실행이 시작되지 않음 | lane 정지, 마운트 실패 | lane 상태 필드, fail-closed 종료 코드 | 03 |
| 변조가 서버에 닿았는지 불명 | arm ACK는 적용 성공이 아니다 | `arm-N.delta`의 applied 횟수, 프록시 통계 | 05 |
| sanitizer 보고가 남지 않음 | 조건 불충족 또는 Q1 실패 | Q1 결과 확인 후 판정 | 07 |

## 한계와 미결 사항

| 항목 | 상태 |
|---|---|
| Agent가 넘기는 seed의 정확한 계약과 확장 절차 | 미결. 02에서 정의 |
| 재현 판정의 통합 절차 (Q1 + Q2) | 미결. 07에서 정의 |
| `syz-manager` 기반 운용 증거 | 10분 비교 실행 1회에서 동작 확인(lane 4개, fs/nfsd 2,040 PC, crash 0). 부팅 인자 `nfs.localio_enabled=N`이 필수다 |
| 프록시 경유 시 knfsd remote KCOV 귀속 | **해결** (lane 단위 귀속, 현재 kernel 0002). 아래 참조 |
| lane 귀속의 경계: 프로그램 종료 뒤 늦게 발생하는 작업 | **부분 검증**. close 뒤 지연 REMOVE와 쓰기 플러시를 만들어 A/B를 번갈아 30회씩 돌렸을 때 B로 새지 않았다. 프로그램마다 약 4건의 늦은 요청은 닫힌 generation에 거부된다(`lane_owner_failed`). 다음 프로그램이 시작된 뒤에 도착하는 경우는 관측하지 못했다 (긴 비동기 작업, 지연된 위임 반환, 임대 만료 callback, 프록시 버퍼링은 강제로 만들지 않음) |
| 프록시가 레코드 수를 바꾸는 변조 | **미검증**. 귀속이 연결·레코드 짝짓기에 의존하지 않아 구조상 무관하지만 실험하지 않았다 |
| KCSAN 변형의 lane 귀속 | 축소한 시리즈의 rc5 부트스트랩 KCSAN 커널에서 직접 경로 `.extra` 30/30 (KCSAN 보고 0) |
| 요청 단위 귀속 장치 제거 | **완료** (`fe294cc`). 아래 참조 |
| 프록시의 길이 변경 변조 (operation 추가, 가변 길이 필드 변경) | **요구사항, 미구현**. 현재는 같은 폭 덮어쓰기(최대 16바이트)만 지원. 설계는 05에서 정의 |
| 기본 이미지의 직접 마운트 경로 제거 | **완료**. 단일 lane fixture의 기본값은 `both`; NFSv3 시드와 중복 fixture 제거. 직접 경로는 비교 진단 옵션으로만 남음 |
| 프록시 변조가 서버에 도달했는지 퍼징 중에 판정하는 채널 | 진단 출력 지점은 있으나 소비자는 스모크 게이트뿐 |
| Ganesha 대상의 도달 관측 | 미구현. remote KCOV는 사용자 공간 서버에 귀속 대상이 없다 |
| 서버별 실행 방식 | **결정됨 (2026-10-02)**. 서버별 34개 호출 입력을 따로 실행; KASAN v4.1 스냅샷에서 각 1회 errno 오라클 통과 |
| 프록시의 실행 대상 선택·관리 라우팅 확장 | **후속 계획**. 기존 고정 중계와 별개이며, 자동 전환·복제는 미구현 |
| Ganesha 병렬 축의 처리량 이득 | 후속 검토, 미실증 |
| 정상 NFS 흐름 코퍼스의 지원 범위 | 부분 완료(`report/normal-flow-corpus.md`) |

### 귀속 단위: 요청에서 lane으로 (2026-09-30 ~ 10-01)

**문제.** 기존 요청 단위 귀속은 서버가 `accept`한 TCP 연결의 4-tuple을 클라이언트가 등록한 항목과 짝짓고
(`sunrpc_fuzz_svc_pair`), 연결별 레코드 순번(ordinal)으로 요청을 찾는다. 프록시는 백엔드로 새 연결을 열어
4-tuple이 달라지므로 짝짓기가 끊긴다. 실측에서 프록시 경유 연결은 모두 `PENDING_CONNECT`, `server_attached=0`이었고
`.extra`는 0/30이었다. 프록시의 레코드 중계 자체는 1:1이었다.

**해결.** lane은 proc 하나가 단독 점유하고 proc N의 KCOV handle은 N+1이다. 그래서 커널 패치(현재 0002)는 서버 netns가
등록된 lane domain에서 소유자를 계산하고, 받은 요청을 그 handle의 현재 generation에 귀속한다. 클라이언트는 요청마다
wire 토큰을 만들지 않는다. 승인, 집계, 게시, 배출 경로는 그대로다. fixture 변경은 필요 없다.

```text
  기존: client --TCP A--> [4-tuple 짝짓기 + ordinal] --> knfsd   (프록시가 A를 끊으면 실패)
  lane: client --> (프록시) --> knfsd @ lane N netns
                                      --> 소유자 = handle N+1의 현재 generation
```

| 확인 (v7.3-rc4 + 당시 0001~0014, KASAN, syz-execprog) | 결과 |
|---|---|
| 직접 경로 / 프록시 경유 `.extra` | 30/30 / 30/30 (기존 방식 프록시 경유 0/30) |
| fs/nfsd PC (요청 단위 → lane 단위) | 1747 → 1812. 늘어난 것은 close 뒤 비동기 `DELEGRETURN`, `FREE_STATEID` 등 기존에 소유자가 없던 요청 |
| 비동기 COPY | 요청 단위와 동일 (fs/nfsd 1413, CB_OFFLOAD 경로 포함) |
| 다른 lane에 `LINK` 주입 (음성 대조) | lane 0 프로그램 0/60에서 검출. 양성 대조(같은 lane 주입) 60/60 |
| A/B 번갈아 실행 (경계) | B로 새지 않음 (0/30). 프로그램 사이 도착분은 버려짐 |

**왜 netns만으로 소유자를 정할 수 있는가.** 소유자 규칙이 성립하려면 두 전제가 필요하다. (1) lane N은 proc N만 쓴다.
executor는 `/syz-nfs-lanes/proc-<procid>/.lane_id`가 자기 procid와 같을 때만 그 lane의 마운트를 가져오고, proc은
프로그램을 하나씩 순차 실행한다. (2) proc N의 KCOV handle은 `kcov_remote_handle(COMMON, procid + 1)`로 고정 계산된다.
두 전제가 있으면 "lane N의 netns에서 일어난 서버 작업"은 곧 "handle N+1의 현재 generation이 일으킨 작업"이다.
서버 작업 대부분은 netns를 얻을 수 있다(아래는 코드 조사 결과이고, 실험으로 확인한 것은 비동기 COPY의 CB_OFFLOAD와
close 뒤 DELEGRETURN, FREE_STATEID까지다).

| 서버·클라이언트 문맥 | netns 도출 | 귀속 |
|---|---|---|
| nfsd 스레드의 요청 처리, 전송 단계, 지연 요청 재처리 | `nfsd_net`, `rq_xprt->xpt_net` | 프로그램 |
| 비동기 COPY kthread, 클라이언트 rpciod/nfsiod | 요청 문맥의 클라이언트·`rpc_task`의 xprt net | 프로그램 (프로그램 경계를 넘을 수 있음) |
| callback | `clp->net` | 요청 또는 laundromat이 원인이라 혼합. 서버가 요청 없이 시작하는 callback은 소유자가 없어 버려진다. 클라이언트의 backchannel 처리(`svc_process_bc`)는 고정 handle 1로 구간을 열어 lane 귀속과의 관계를 확인하지 않았다 |
| laundromat (`nn->laundromat_work`) | net별 작업 항목 | 주기 작업이라 프로그램의 것이 아님. kworker에서 실행되어 `svc_process()` 밖이므로 remote KCOV 구간이 열리지 않고 수집되지 않는다 |
| 파일 캐시 정리 (`nfsd_filecache_laundrette`, 전역 LRU) | 불가 | 귀속 불가. 요청 단위 방식에서도 소유자가 없었다 |

귀속할 수 없는 것은 전역 파일 캐시 정리뿐이고, 이는 이전 설계에서도 같았다.

새로 생긴 성질: 같은 lane 안에서 프로그램 밖으로부터 들어온 트래픽은 그때 실행 중인 프로그램에 귀속된다.
lane 안에 다른 트래픽원이 없어야 한다.

구현은 kernel 0002의 `net/sunrpc/fuzz.c`와 0001의 `kernel/kcov.c`(`kcov_request_current_generation`)다. 실험 증거 원본은 보존하지 않았고,
위 표가 확인한 내용의 전부다.

### 요청 단위 귀속 장치 제거 (2026-10-01, `fe294cc`)

lane 귀속에서 소유자를 정하는 데 쓰이지 않는 장치를 시리즈에서 뺐다. 커널 시리즈는 14개에서 3개가 되었다.

| 새 패치 | 내용 |
|---|---|
| 0001 kcov | 요청 generation, 토큰, 승인, 집계, 중복 PC 억제, 전송 단계 관측 API (기존 내용 유지) |
| 0002 sunrpc | lane domain, lane 단위 귀속, 서버 훅, 지연 요청 이어받기 |
| 0003 nfsd | 비동기 COPY 이어받기 |

- 제거한 것: 클라이언트 논리 출처 추적(`fs/nfs`, `rpc_task`), TCP 4-tuple 연결 짝짓기와 ordinal(`net/ipv4`, `struct sock`
  수정 포함), raw 소켓 귀속 인터페이스 `TCP_SUNRPC_FUZZ`, skb 출처 handle, 클라이언트 토큰 기준 lane 진단, 시험용 결함 주입.
- rc5 대비 커널 변경: 44개 파일, 9,890줄 → 19개 파일, 약 6,200줄.
- syzkaller 0018: raw RPC를 일반 TCP로 보낸다. `syz_send_nfs_fuzz`의 인자 값은 유지해 기존 프로그램이 그대로 해석된다.
- debugfs: fixture가 쓰는 `domain`, `domain_control`은 그대로다. 카운터 파일은 `lane_stats`, `saved_work_stats`, `lane_state`로 바뀌었다.
- 확인: rc5 부트스트랩(KASAN·KCSAN) 통과, 직접·프록시·raw·비동기 COPY 모두 `.extra` 30/30, generation abort 0.

## 문서 지도

```text
 01 overview --> 02 seed-interface --> 03 execution-env
                        |                (lane, namespace, nfs-version)
                        v                          |
                 04 observation (remote KCOV)      |
                        |                          v
                        +------------------> 05 wire-mutation (proxy)
                        |                          |
                        +-----------+--------------+
                                    v
                        06 parallel-axis (Ganesha) --> 07 verdict
```

## 참조

- `README.md`: 환경 구축 절차와 게이트
- `report/design-spec.md`: 설계 계약 (Ψ, R1, R2, R4, R5)
- `report/nfa1-kcov-feedback-design.md`: 도달 관측의 간극
- `report/normal-flow-corpus.md`, `bundle/corpus/`: 정상 흐름 코퍼스와 시나리오 manifest
- `tools/nfs-proxy/README.md`: 프록시 arm 프로토콜
- `tools/README.md`: 포워드포트 파이프라인과 병렬 축
