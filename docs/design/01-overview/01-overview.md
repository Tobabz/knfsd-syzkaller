# 재현 파이프라인 개요

> 상태: draft   ·   최종 확인: 2026-10-02   ·   기준: kernel `v7.3-rc5` / syzkaller `801f09666`
> 관련 패치: kernel 0001~0003, syzkaller 0001~0019   ·   부트스트랩 검사: manifest의 빌드·부팅 결과

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
| 2 | 도달 여부를 알 수 없으면 PC가 없는 이유를 "미실행"으로 오독한다 | 소유권 규칙과 관측 진단 카운터 | `report/normal-flow-corpus.md`의 완료 기준 |
| 3 | syzkaller는 syscall을 변조하는데, syscall 인자로는 NFS operation 단위의 뮤테이션이 되지 않는 경우가 있다 | pseudo-syscall과 프로토콜 형태 연산 (syzkaller 0006, 0015) | 설계 의도(사용자 확인). 코드 대조는 아래 "주장 검증" 참조 |
| 4 | NFS 클라이언트를 대상으로 하는 취약점을 트리거하려면 서버의 응답을 변조해야 한다 | wire 프록시와 arm 규칙 (syzkaller 0017) | 설계 의도(사용자 확인). 프록시에 S2C 방향 변조가 구현되어 있음 (`tools/nfs-proxy/README.md`) |
| 5 | 동시 퍼징 시 프로세스 간 상태가 섞이면 결과를 해석할 수 없다 | lane과 namespace 격리 (syzkaller 0007~0014) | `bundle/lane/`의 fixture와 syzkaller 패치 |

여섯 번째 요소인 NFS-Ganesha는 추가 서버 대상이다. v4.1 기본 시드는 서버별로 나누고,
서로 다른 syz-manager 설정·workdir·`corpus.db`로 한 번에 한 서버씩 퍼징한다.
Ganesha는 원래 knfsd와 동시에 퍼징해 처리량을 높이는 병렬 축으로 도입했으나, 한 manager에서 두 서버를
함께 운용할 때의 상태 관리 문제 등으로 서버별 순차 캠페인으로 바꿨다(2026-10-02 결정).
병렬성은 서버 축이 아니라 한 VM 안의 lane(proc) 축이 담당한다.
프록시의 실행 대상 선택 확장은 후속 계획이다.

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
기존 NFSv3 시드와 별도 fixture는 제거했다. 현재 공통 lane은 부팅 시
`--version 3|4.0|4.1|4.2`로 두 서버의 마운트 버전을 선택한다.
현재 lane은 Ganesha V15.6을 사용한다. V15.6의 FSAL_VFS는 `tmpfs` export를
제외하므로 Ganesha는 크기가 제한된 ext4 루프 저장소를 사용하고, knfsd는 기존
tmpfs를 유지한다. v4.1과 v4.2 게스트에서 네 마운트의 교차 읽기·쓰기,
Ganesha 직접 연결, 정리와 루프 장치 해제를 확인했다.
기존 시드의 `nfs-lane/client0`·`client1`은 같은 knfsd export를 사용하는 두 클라이언트로 유지한다.
Ganesha는 `client0-ganesha`·`client1-ganesha` 경로로 선택한다. 두 서버의 저장 공간은 분리되어 있다.
`SERVER_IMPL=knfsd|ganesha` 직접 경로는 별도 비교 진단에만 사용하며 기본 이미지에는 적용하지 않는다.

<a id="backend-execution-decision"></a>

### 서버별 실행 결정 (2026-10-02)

**결정됨.** knfsd와 Ganesha는 syz-manager 설정, workdir, `corpus.db`를 각각
분리하고 한 번에 한 서버씩 퍼징한다. knfsd DB는 `basic-v41-tcp.prog`,
Ganesha DB는 `basic-v41-ganesha-tcp.prog` 하나로 초기화했다. 각 시드의 두
클라이언트는 같은 서버의 export를 사용한다. DB를 병합하거나 두 캠페인에
공유 corpus hub를 연결하지 않는다.

```text
knfsd manager   -> knfsd/workdir/corpus.db   -> client0         <-> client1
Ganesha manager -> ganesha/workdir/corpus.db -> client0-ganesha <-> client1-ganesha
                  (한 번에 한 manager 실행)
```

현재 로컬 설정은 `cache/manager-separated-v41-20261002/{knfsd,ganesha}/manager.cfg`다.
두 설정은 `procs=4`, KASAN v4.1 VM 하나, 파일 연산 syscall 범위를 쓰며 `vm.snapshot`이 켜져 있다.

**lane 병렬 운용은 필수다 (2026-10-02 결정).** lane은 한 VM 안에서 proc마다 격리된 NFS 상태를 주기 위한
설계이므로 manager는 `procs`를 lane 수(4)로 두고 **`vm.snapshot`을 끈다.** syzkaller 스냅샷 모드는 VM마다
프로그램을 하나씩 순서대로 실행하고 proc을 하나만 쓴다(`executor/snapshot.h`, `pkg/execbackend/snapshot.go`).
그래서 스냅샷 모드에서는 `procs=4`를 줘도 lane 0만 쓰이고 lane 1~3은 놀며, 프로그램마다 VM 상태가 되돌려져
lane 귀속의 프로그램 경계도 시험되지 않는다.
위 로컬 설정과 아래 분리 검증 결과는 스냅샷 모드, 즉 proc 하나로 얻은 것이다. 현재 토폴로지(서버별 캠페인,
기본 `both`)에서 `vm.snapshot`을 끄고 lane 4개를 동시에 쓰는 manager 운용은 **미검증**이다.
`experimental.remote_cover`는 knfsd에서 `true`, Ganesha에서 `false`다.
Ganesha 피드백은 로컬 클라이언트 커널 KCOV이며 사용자 공간 서버 내부 커버리지가 아니다.
실행 명령과 이미지 준비 방식은
[코퍼스 운영 문서](../../../bundle/corpus/nfs-normal/README.md#execution-scope-2026-10-02)를 따른다.

분리 검증의 `corpus-triage`는 양쪽 모두 종료 코드 0으로 끝났다. 저장된 knfsd
프로그램 100개와 Ganesha 프로그램 109개에서 상대 서버 경로 문자열은 발견되지 않았다.
기대 경로 문자열이 없는 프로그램은 각각 78개와 89개다. 근거는 분리 캠페인 디렉터리의
각 `triage.log`, `triage-unpacked/`, 루트의 `maintenance.json`이다.

이 분리는 서로 다른 서버의 코퍼스에서 프로그램을 가져와 splice하는 문제를 막는다.
일반 생성·경로 변이·최소화는 계속 적용되며, 게스트에는 두 서버의 마운트가 모두 있으므로
다른 서버 경로의 생성이나 실행까지 강제 차단하지는 않는다. 경로 문자열이 없다는
사실만으로 NFS 미실행을 단정할 수도 없다. 서버 간 동일 변이와 자동 재실행은 보장하지 않는다.

단일 매니저 통합 운영은 폐기했다. 34호출을 두 번 붙이는 통합안도 채택하지 않는다. 고정된 syzkaller의
`prog.MaxCalls`는 40이며 초과 입력은 매니저가 거부한다.

**후속 계획.** 동일 시나리오의 실행 대상을 프록시에서 선택·관리하는 라우팅 확장은
추후 설계와 구현으로 남긴다. 현재 프록시는 고정 중계 경로를 유지한다.
실행 중인 NFS 세션의 서버 전환이나 양쪽 요청 복제 기능은 구현되어 있지 않다.
서버별 상태 격리, 결과 구분과 처리량 이득은 후속 검토 대상이다.

### 판정 논리

| Q1 도달 | Q2 sanitizer 보고 | 해석 | 다음 행동 |
|---|---|---|---|
| 아니오 | (무관) | seed 오동작 또는 환경 문제. 재현 실패가 아니다 | lane 상태·NFS 응답·프록시 통계를 확인 |
| 예 | 아니오 | 시나리오는 실행됐으나 이상이 관측되지 않음 | 조건(타이밍, 변조 위치)을 재검토 |
| 예 | 예 | 재현 후보 | 보고 내용과 시나리오의 대응을 확인 |

KCSAN 보고는 반드시 커널 중단을 뜻하지 않는다. 결과를 해석할 때 보고 내용과
실제 종료 상태를 각각 확인한다.

### 요소와 구현 상태

| 요소 | 역할 | 구현 상태 | 상세 문서 |
|---|---|---|---|
| LLM Agent 연동 | 설계 문서로 syzlang, pseudo-syscall, arm 규칙을 생성 | 저장소에 생성기 **없음** | 요소별 설계 문서 미작성 |
| pseudo-syscall, 기술 파일 | seed가 NFS 프로토콜을 다루게 함 | 구현됨 | syzkaller 패치 시리즈 |
| lane, namespace | 프로세스별 격리된 NFS 환경 | 구현됨 | `bundle/lane/`, `tools/README.md` |
| remote KCOV | 서버 경로 도달 관측 | 구현됨 (knfsd 한정) | kernel 패치 0001~0003 |
| nfs-proxy | wire 변조 주입 | 고정 경로, 같은 폭 편집(v1)과 길이 변경 편집(v2, 호스트 검증만) 구현 | `tools/nfs-proxy/README.md` |
| Ganesha 백엔드 | 별도 서버 대상 | 서버별 corpus로 순차 퍼징 | `bundle/corpus/nfs-normal/README.md` |
| 재현 판정 | Q1, Q2 종합 | 통합 판정 도구 **없음** | `report/normal-flow-corpus.md` |

기본 운용 방식은 서버별 `syz-manager` 퍼징이다. 현재 실행 명령과 검증 범위는
`bundle/corpus/nfs-normal/README.md`가 소유한다.

### 주장 검증: 왜 프록시와 pseudo-syscall인가

설계 의도(문제 3, 4)를 코드와 대조한 결과다. 상태는 `확인` / `부분` / `미검증`으로 구분한다.

| 주장 | 상태 | 확인한 것 | 남은 검증 |
|---|---|---|---|
| syscall 인자 뮤테이션은 NFS operation의 wire 표현을 직접 바꾸지 못한다 | 부분 | `write$nfs` 등 표준 syscall 기술은 커널 NFS 클라이언트를 거쳐 RPC가 만들어진다(`fs_nfs_fuzz.txt`) | 특정 operation이 표준 syscall로 도달 불가함을 보이는 대조 실험 |
| pseudo-syscall이 이 공백을 메운다 | 부분 | `syz_send_nfs_fuzz`와 `write$inet_nfs_fuzz`(syzkaller 0018, 일반 TCP)가 RPC/XDR 메시지를 직접 전송하고, `nfs4_op_arg` 등으로 NFSv4 COMPOUND의 operation을 기술한다(`socket_inet_nfs.txt`). 즉 C2S 방향의 operation 뮤테이션은 raw 전송 경로로 가능하다 | raw 경로로 만든 요청이 클라이언트 세션 상태(세션, slot, stateid)에 의존하는 operation에 유효한지 |
| 클라이언트 취약점은 서버 응답 변조가 필요하고, 이는 프록시로만 가능하다 | 부분 | raw 경로는 C2S 전용이다. S2C 변조는 프록시의 `direction=1` arm이 유일하게 구현되어 있다. 게스트 실험에서 C2S와 S2C 양방향 변조가 적용·재생됐다 | 변조된 응답이 실제로 클라이언트 취약점을 트리거하는 사례. 현재 증거는 XID 변조의 적용까지다 |

## 설계

1. **판정을 둘로 나눈다.** 도달(Q1)과 이상 보고(Q2)를 별개의 관측으로 유지한다.
2. **도달은 remote KCOV와 카운터로 판정한다.** 서버 스레드의 PC를 시나리오 실행에 귀속한다.
   귀속 단위는 **lane**이다. lane N의 서버가 받은 요청은 proc N이 그때 실행 중인 프로그램의 것이다(kernel 0002).
3. **변조는 프록시 한 곳에서 한다.** 변조 규칙은 seed에 포함되어 프로그램과 함께 재현된다.
4. **격리는 lane 단위로 하고, lane은 병렬로 쓴다.** 한 프로세스의 상태가 다른 프로세스의 관측에 섞이지 않게 하고,
   manager는 proc마다 lane 하나를 동시에 쓴다(`procs` = lane 수, `vm.snapshot` 끔).
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
| 전역 KCOV 핸들 하나로 서버 스레드 수집 | 귀속 규칙이 필요 없음 | 동시 클라이언트의 PC가 섞임 | 기각. 전역 핸들을 입력별 피드백으로 사용하지 않음 |
| 클라이언트 커널에 변조 기능 추가 | 프록시가 필요 없음 | 서버 응답 변조는 클라이언트 쪽에서 만들 수 없음 | 기각 (S2C 변조 불가) |

## 영향

- **상류.** 패치 시리즈와 커널·syzkaller 핀이 바뀌면 remote KCOV 계약과 pseudo-syscall ABI가 깨질 수 있다.
  부트스트랩 manifest는 빌드·부팅을 검증하지만 시드의 도달·커버리지를 판정하지 않는다.
- **하류.** Q1 판정이 틀리면 재현 실패와 seed 오동작이 섞인다.
- **운영.** remote KCOV 활성 시 처리량 비용이 있다. 병렬 처리량은 lane(proc) 수로 얻으며, 스냅샷 모드로
  돌리면 이 이득이 사라진다. 격리 fixture는 lane마다 knfsd tmpfs 256 MiB와 Ganesha ext4 루프 이미지
  256 MiB(`KOOV_TMPFS_SIZE`) 등의 자원 비용이 있다.

## 신뢰성 요구

이 파이프라인에서 가장 위험한 오류는 **Q1의 거짓 음성**이다. 실제로는 도달했는데 도달하지 않았다고
판정하면 시나리오를 고치는 방향으로 잘못된 수정이 이어진다. 반대로 거짓 양성은 재현이 없는데 있다고
판단하게 해서 재현 결론을 오염시킨다.

| 항목 | 요구 |
|---|---|
| 오류 방향 | Q1 거짓 음성이 가장 위험. 계측 누락(포화, 진행 중 section 폐기)을 "관측 없음"과 구분해 드러낼 것 |
| 실패 방식 | fail-closed. 정지한 lane, 죽은 서버는 정상으로 기록하지 않는다 |
| 관측 가능성 | debugfs `sunrpc_fuzz` 카운터, dmesg, 이미지 해시로 실행 후 사후 검증 |
| 재현성 | seed, arm 규칙, 픽스처 스크립트의 SHA-256을 시나리오 manifest에 고정 |

## 검증 오라클

시나리오의 도달과 이상 보고는 각각 확인해야 한다. 아래 항목은 수동 검증 시의
판정 기준이며, 부트스트랩 성공이나 PC 존재만으로 충족됐다고 보지 않는다.

| 확인 | 오라클 |
|---|---|
| 입력 동일성 | seed 해시는 corpus manifest와 대조한다. 부팅 시에는 호스트 lane 스크립트 해시가 설정과 맞지 않으면 fixture가 실패한다 |
| 도달 (Q1) | `generation_begin`, `remote_start_ok`, `aggregate_published` 등의 카운터 증가와, 서버 측 sentinel 함수의 커버리지 존재 (`fs/nfsd`는 remote KCOV ON에서만) |
| 부작용 없음 | `generation_aborted`, `scratch_overflow`가 0 (시나리오별 기대값) |
| 정리 | 참조 카운터가 0으로 배출 (`outstanding_tokens`, `remote_refs` 등) |
| 이미지 무변경 | 실행 전후 이미지 해시 동일 |

sentinel PC의 존재는 구간 도달 증거이지 같은 요청의 순서나 스레드 전환 증거가 아니다.
서버의 요청 처리 이전 전송 단계 PC는 프로그램의 `.extra`에 없을 수 있다. 전역 관측 PC를
입력별 퍼징 피드백으로 쓰려면 실행별 격리·배출과 외부 트래픽 배제를 먼저 검증해야 한다.
미검증 PC를 현재 프로그램의 신호로 합치지 않는다. 정상 흐름의 완료 기준은
`report/normal-flow-corpus.md`를 따른다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| sentinel PC 없음 | 미실행, 귀속 실패, 버퍼 포화, 진행 중 section 폐기 | `scratch_overflow`, `generation_aborted`, 카운터 배출 | 요청·커버리지 진단 |
| seed 실행이 시작되지 않음 | lane 정지, 마운트 실패 | lane 상태 필드, fail-closed 종료 코드 | `bundle/lane/` 확인 |
| 변조가 서버에 닿았는지 불명 | arm ACK는 적용 성공이 아니다 | 프록시 적용 횟수와 통계 | 프록시 로그 확인 |
| sanitizer 보고가 남지 않음 | 조건 불충족 또는 Q1 실패 | Q1 결과 확인 후 판정 | 실행 결과 확인 |

## 한계와 미결 사항

| 항목 | 상태 |
|---|---|
| Agent가 넘기는 seed의 정확한 계약과 확장 절차 | 미결. 요소별 설계 문서 미작성 |
| 재현 판정의 통합 절차 (Q1 + Q2) | 미결. 통합 판정 도구·문서 없음 |
| `syz-manager` 기반 운용 | 서버별 설정·DB·재개 명령은 `bundle/corpus/nfs-normal/README.md` 참조. 부팅 인자 `nfs.localio_enabled=N`이 필수다 |
| 프록시 경유 시 knfsd remote KCOV 귀속 | lane 단위 귀속 구현. lane은 proc 하나가 단독 점유해야 한다 |
| lane 귀속의 경계: 프로그램 종료 뒤 늦게 발생하는 작업 | 다음 프로그램 시작 뒤 늦게 도착하는 요청의 오귀속 위험이 남는다 |
| 프록시가 레코드 수를 바꾸는 변조 | **미검증**. lane의 서버 netns로 소유자를 정하므로 구조상 무관하지만 실험하지 않았다 |
| KCSAN 변형의 lane 귀속 | 현재 부트스트랩은 빌드·부팅만 확인한다. 시드별 귀속은 별도 검증이 필요하다 |
| 프록시의 길이 변경 변조 (operation 추가, 가변 길이 필드 변경) | **Phase 1 구현, 게스트 미검증 (2026-10-02)**. `INSERT`/`DELETE`/`REPLACE`/`OP_APPEND`/`OP_PREPEND`를 구조 보존·raw 두 모드로 지원(`tools/nfs-proxy/src/edit.c`), arm v2(`NFSPARM2`)와 delta v2, syzkaller 0019. 호스트 단위 테스트(클랑+ASan/UBSan)는 전부 통과. lane 귀속·게스트 검증은 아직 하지 않았다. 상세는 `docs/handoff/proxy-variable-length-edits/`의 완료 보고 참조 |
| 기본 이미지의 직접 마운트 경로 제거 | **완료**. 단일 lane fixture의 기본값은 `both`; NFSv3 시드와 중복 fixture 제거. 직접 경로는 비교 진단 옵션으로만 남음 |
| 프록시 변조가 서버에 도달했는지 퍼징 중에 판정하는 채널 | 프록시 진단 출력은 있으나 syz-manager의 입력별 피드백에 미연결 |
| Ganesha 대상의 도달 관측 | 미구현. remote KCOV는 사용자 공간 서버에 귀속 대상이 없다 |
| 서버별 실행 방식 | **결정됨 (2026-10-02)**. 서버별 34개 호출 입력을 따로 실행; KASAN v4.1 스냅샷 모드(proc 1개)에서 각 1회 errno 오라클 통과 |
| lane 병렬 manager 운용 (`vm.snapshot` 끔, `procs=4`) | **필수 조건, 현재 토폴로지에서 미검증**. 검증된 로컬 설정은 스냅샷 모드라 lane 0만 사용했다 |
| lane 밖에서 생기는 요청 | knfsd lease가 10초(`nfsv4leasetime`)라 클라이언트 netns마다 수 초 간격의 lease 갱신 요청이 생기고, lane 단위 귀속에서는 그때 실행 중인 프로그램의 커버리지로 잡힌다. 프로그램과 무관한 PC가 섞이는 거짓 양성 원천이다. syzkaller의 triage 재실행이 불안정한 신호를 걸러 영향은 제한적이나 측정하지 않았다 |
| Ganesha 캠페인의 sanitizer 보고 | Ganesha export가 ext4 루프 위에 있어, 보고에 NFS가 아닌 ext4·loop 경로가 섞일 수 있다. 보고의 호출 경로로 구분한다 |
| 프록시의 실행 대상 선택·관리 라우팅 확장 | **후속 계획**. 기존 고정 중계와 별개이며, 자동 전환·복제는 미구현 |
| Ganesha 병렬 처리량 이득 | 해당 없음. Ganesha는 병렬 축에서 빠졌다(상태 관리 문제 등, 2026-10-02) |
| 정상 NFS 흐름 코퍼스의 지원 범위 | 부분 완료(`report/normal-flow-corpus.md`) |

## 문서 상태

현재 요소별 02~07 설계 문서는 작성되지 않았다. 아래 참조의 운영 문서와 구현이
현재 지원 범위를 설명한다.

## 참조

- `README.md`: 환경 구축 및 서버별 퍼징 절차
- `report/normal-flow-corpus.md`: 정상 흐름의 지원 범위·완료 기준·미검증 항목; `bundle/corpus/`: 시드와 실행 계약
- `tools/nfs-proxy/README.md`: 프록시 arm 프로토콜
- `tools/README.md`: 빌드·부트스트랩 도구와 무결성 판정
