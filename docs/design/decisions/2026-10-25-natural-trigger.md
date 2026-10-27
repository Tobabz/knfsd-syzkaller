# 결정 기록: 트리거는 NFS 클라이언트의 행위여야 한다 (2026-10-25)

> 종류: 결정 기록 (임시 문서)   ·   승인: 사용자, 2026-10-25   ·   관련 설계: `02-llm-agent/04` §3.2, §6,
> `02-llm-agent/07` §4, §5   ·   관련 결정: `2026-10-25-harness-generation-on-gap.md`   ·   관련 issue: #83

## 삭제 조건

아래가 **모두** 충족되면 삭제한다. 삭제 커밋 메시지에 흡수한 문서 경로를 적는다.

1. HCAP-11과 HCAP-12가 Agent 사용 범위에서 빠졌거나, 자연 경로로 다시 만든 capability로 대체됐다(code와
   `04`가 일치한다).
2. Harness Generation 검증(`07` §5.2)이 트리거 기준을 구현했다(issue #83).
3. 아래 "미결"이 결정돼 `04` §3.2와 `07` §5에 반영됐다.

## 문제

- HCAP-11은 실행 중에 서버 namespace의 broker가 서버 관리 인터페이스 `/proc/fs/nfsd/clients/<id>/ctl`에
  `expire`를 쓴다(`tools/nfs-proxy/src/lifecycle.c`). 서버 관리자가 클라이언트를 강제로 만료시키는 동작이며
  NFS 클라이언트가 할 수 있는 행위가 아니다.
- HCAP-12는 실행 중에 broker가 서버의 nfsdcld(서버의 클라이언트 기록 데몬)를 SIGSTOP한 뒤 SIGKILL하고
  다시 띄운다(`tools/nfs-proxy/src/cld.c`). 서버 데몬 장애를 일부러 만드는 것이다.
- 이런 트리거로 도달한 경로는 공격자가 만들 수 없는 상태에서 나온 것이므로 Q1 `REACHED`와 그 뒤의 crash가
  실제 위협을 뜻하지 않는다.
- 자연스러운 경로(예: 클라이언트가 lease 갱신을 멈춰 서버가 스스로 만료시키는 경로)가 있어도, 그 경로가
  지금의 remote-KCOV로 귀속되지 않는다는 이유로 부자연스러운 트리거를 골랐다. HCAP-11의 만료 경로는 laundromat
  workqueue에서 돌아 현재 boundary 밖이다(`04` HCAP-12 표).

## 결정

1. **트리거의 정의.** 트리거는 Q1에서 대상 커널 코드를 실행시키려고 프로그램이 실행 중에 일으키는 행위다.
   실행 전 환경 구성(fixture 설정, 포트, lease·grace 시간, 데몬 기동)은 트리거가 아니다.
2. **트리거는 NFS 클라이언트의 행위여야 한다.** 클라이언트가 보내는 요청, 클라이언트의 syscall, 요청을
   멈추거나 연결을 끊는 것처럼 클라이언트가 스스로 할 수 있는 행위다. 같은 서버에 붙은 여러 클라이언트의
   행위를 조합해도 된다.
3. **클라이언트가 유도한 서버 동작은 허용한다.** 클라이언트의 행위 때문에 서버가 하는 동작(callback, lease
   만료와 laundromat 처리, blocked lock grant, 서버 데몬으로 가는 upcall)은 적절한 시나리오다.
4. **harness가 서버를 직접 조작하는 것은 허용하지 않는다.** 실행 중에 harness나 helper가 서버에서 일으키는
   행위(서버 관리 인터페이스 쓰기, 서버 데몬 정지·종료·재시작, 서버 설정 변경)는 트리거가 아니다. 이 기준은
   사람이 만든 capability와 Harness Generation이 만든 capability에 똑같이 적용한다.
5. **자연 경로가 있으면 그 경로로 만든다.** 같은 대상에 도달하는 자연 경로가 있으면 capability와 생성 harness는
   그 경로를 쓴다.
6. **귀속되지 않는다는 이유로 자연 경로를 버리거나 멈추지 않는다.** 자연 경로가 현재 RemoteKcovSupportBoundary
   밖이면 그것은 `remote_kcov_attribution` gap이다. Harness Generation이 그 context의 계측을 생성하고 검증한다
   (`07` §5). 부자연스러운 트리거로 우회하지 않는다.
7. **HCAP-11과 HCAP-12는 이 기준을 위반한다.** HCAP-11의 만료는 클라이언트가 유도한 것이 아니라 broker가 서버 관리 인터페이스에 쓴 것이고, HCAP-12의 데몬 재시작은 클라이언트가 유도할 수 없다. Agent 사용 범위에서 빼고, 자연 경로(lease 만료와 그 귀속 계측)로
   다시 만든다. HCAP-12는 카탈로그에서 삭제했다(#98). HCAP-11은 자연 경로로 다시 만들었다(#96): client0이 자기
   lane namespace의 link를 lease보다 오래 내려 courtesy client가 되고, client1의 OPEN이 client0의 write
   delegation을 회수할 때 서버가 client0을 만료시키며, client0은 heal 뒤 새 clientid로 복구한다. laundromat의
   만료 자체는 귀속되지 않지만 delegation 회수(client1의 OPEN)와 복구(EXCHANGE_ID, CREATE_SESSION)는 nfsd
   request로 귀속된다.
8. **Proxy 변조는 공격자 역할의 메시지다.** 실제 취약점 시나리오에서 C2S 변조는 악의적인 클라이언트가, S2C
   변조는 악의적인 서버가 직접 만든다. 이 환경은 변조를 정상 시나리오와 구분하려고 클라이언트와 서버 사이에
   Proxy를 둔다. 따라서 Proxy가 만든 record는 그 방향 송신자의 protocol 메시지여야 하며, S2C 변조는 서버 응답을
   받는 kernel NFS client를 대상으로 허용한다. 서버 관리 조작은 S2C 시나리오에서도 트리거가 아니다.
9. **HCAP-13은 기준을 만족한다.** 트리거는 클라이언트의 `fcntl` 잠금과 클라이언트 namespace에서 보내는 raw NLM
   요청이고, blocked lock의 callback은 다른 클라이언트의 unlock으로 생긴다. 서버 쪽 변경은 fixture 설정뿐이다.

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| harness의 서버 직접 조작도 허용하고 결과에 표시 | 지금 귀속되는 경로로 빠르게 도달한다 | 공격자가 만들 수 없는 상태의 도달과 crash가 섞인다 | 채택 안 함 |
| 자연 경로가 귀속되지 않으면 그 대상은 지원하지 않음 | 계측을 새로 만들지 않는다 | pipeline이 대상을 포기한다. "gap은 job을 멈추지 않는다"는 결정과 어긋난다 | 채택 안 함 |
| 자연 경로 + 귀속 계측 생성 | 실제 위협 모델 안에서 도달한다 | 비동기 context(workqueue) 귀속 계측이 필요하고 검증이 어렵다 | 채택 |

## 미결

- **lease 만료 경로의 귀속.** laundromat는 여러 클라이언트를 한 번에 처리하는 주기적 workqueue다. owner를
  마지막으로 lease를 갱신한 요청의 program에서 이어받을지, generation이 닫힌 뒤 일어나는 만료를 어떻게 다룰지,
  프로그램이 lease 시간(fixture 설정, 최소 10초) 동안 실행돼야 하는 제약을 executor timeout과 어떻게 맞출지는
  생성과 검증에서 정한다. HCAP-11은 partition 프로그램에 syz-execprog `-program-timeout`을 올려 맞췄다(#96).

## 남은 위험

- HCAP-11/12를 Agent 사용 범위에서 빼면, 그 capability에 기대던 후보는 대체 capability가 생길 때까지 gap
  경로(`harness_generating`)로 간다.
- 트리거가 서버 쪽인지 판정하는 규칙을 Harness Generation 검증에 결정적으로 넣어야 한다. 그 전까지는 생성물이
  서버 namespace에서 도는 helper를 만들어 같은 위반을 반복할 수 있다.
