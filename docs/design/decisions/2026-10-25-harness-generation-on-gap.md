# 결정 기록: harness gap에서 멈추지 않고 harness를 생성한다 (2026-10-25)

> 종류: 결정 기록 (임시 문서)   ·   승인: 사용자, 2026-10-25   ·   관련 설계: `02-llm-agent/01` §2, §11.2, §12, §13,
> `02-llm-agent/07` §5–§7, `02-llm-agent/09` §3.2   ·   관련 issue: #83, #1

## 삭제 조건

아래가 **모두** 충족되면 삭제한다. 삭제 커밋 메시지에 흡수한 문서 경로를 적는다.

1. `agent_pipeline/`의 Controller가 gap을 `harness_generating`으로 보내고 Harness Generation Agent Task와 검증
   Runner task가 구현돼 있다(issue #83).
2. `02-llm-agent/07`과 `09`가 구현과 일치하고 `09`의 "설계 변경" 머리말과 "결정됨, 미구현" 항목이 지워졌다.

## 문제

- 이전 설계에서는 target candidate에 맞는 harness가 없으면 job이 `blocked_harness_gap`에서 사람을 기다렸다.
  kernel revision용 build가 없을 때(`01` §11.2), Planning이 `unsupported`를 낼 때, Q1이
  `unsupported_attribution`일 때, Mutation Strategy나 Compiler가 capability 부족을 알릴 때 모두 같았다.
- 사람이 gap마다 proposal을 읽고 capability를 구현하고 KVM evidence를 모으고 HCAP을 올려야 job이 이어졌다(#83).
  pipeline의 처리량이 사람 시간에 묶였고, "candidate마다 도달 harness를 만든다"는 pipeline의 목적(`01` §1)과
  어긋났다.

## 결정

1. **gap은 job을 멈추지 않는다.** Controller는 HarnessGapIssue를 만들거나 연결한 뒤 바로 Harness Generation을
   시작하고, job은 `harness_generating`에 들어간다(`09` §3.2). 생성한 harness가 검증을 통과하면 job을 다시
   binding하고 막혔던 지점에서 이어 간다.
2. **Harness Generation은 별도 Agent Task와 Runner 검증이다.** 생성 Agent는 staging 영역에 patch set(syzlang,
   executor, fixture, Proxy/compiler, kernel 계측, 계측 series 이식)을 쓴다. 판정은 Runner의 결정적 검증(`07` §5.2)이
   한다. Stage 1/2 Agent는 지금처럼 source를 바꾸지 않는다.
3. **kernel revision 이식과 remote-KCOV 계측도 생성 대상이다.** 이전 설계는 이것을 사람이 검토하는 유지보수로
   두었다(`01` §11.2, `07` §6). 이제 신뢰는 사전 승인이 아니라 검증(bootstrap, 알려진 target의 attribution, 기존
   capability 회귀)에서 온다. target kernel 동작을 바꾸는 patch는 계측이 아니므로 거부한다.
4. **promotion은 사람이 하되 job을 막지 않는다.** 검증을 통과한 생성물은 staged HCAP revision이 된다. 공유 HCAP으로
   올리는 promotion은 사람이 검토하고(`04` §1.1, `07` §5.3), 그동안 job은 staged revision으로 진행한다. 그 위의 모든
   verdict와 crash report는 staged revision과 patch set digest를 기록한다.
5. **검증에 인위적 crash를 쓰지 않는다.** (사용자 결정, 2026-10-25) semantic subset의 M7 crash survival은
   campaign에서 자연히 생긴 crash로만 확인한다. guest를 일부러 crash시키는 것(sysrq panic, NMI, 강제 reset)은
   인위적 동작이므로 쓰지 않는다. 그 확인이 생길 때까지 subset은 crash survival pending으로 staged revision에만
   pin되고 공유 HCAP promotion은 미룬다(`03-nfs-proxy/06` §30, `07` §5.2, §5.3). subset을 사람이 구현했는지
   생성했는지는 구분하지 않는다.
6. **`blocked_harness_gap`은 fallback이다.** 생성 Agent가 `infeasible`을 내거나 `harness_generation` budget을 다
   쓰면 job은 기존처럼 issue를 기다린다. operator는 `retry_generation`으로 생성을 다시 시작할 수 있다.

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| 이전 설계 유지(gap에서 대기) | 모든 harness 변경을 사람이 먼저 본다 | gap마다 job이 멈춘다 | 채택 안 함 |
| 생성하고 promotion도 자동 | 사람 개입이 가장 적다 | 검토되지 않은 계측이 다른 job의 결론까지 바꾼다 | 채택 안 함. staged revision으로 범위를 job과 gap key에 묶는다 |
| Stage 1/2 Agent가 직접 harness를 고친다 | Agent Task가 하나 줄어든다 | 실행 중인 harness가 바뀌어 evidence lineage와 identity가 섞인다(`01` §11.2) | 채택 안 함 |

## 남은 위험

- 생성 Agent는 gap별 git worktree에서 파일과 shell 권한을 가진다(2026-10-25 사용자 결정, `07` §5.1). container나
  VM 없이 별도 OS 사용자와 secret 없는 환경이 경계다. 그 권한 설정이 틀리면 생성 Agent가 Controller state나
  credential에 닿을 수 있다. 자원 한도와 worktree 수명은 #83에서 정한다. 판정은 Runner가 patch set만 받아 다시 build해 내므로 workspace
  안의 결과는 staged revision에 쓰이지 않는다.
- 자동 이식한 계측의 attribution 검증이 놓친 오류는 Q1을 거짓 `REACHED`나 `NOT_REACHED`로 만들 수 있다. 검증
  profile의 구체 내용(어떤 알려진 target으로 확인하는지)은 #83에서 정한다.
- crash survival이 pending인 subset으로 처음 생긴 자연 crash에서 MutationDelta가 남지 않으면, 그 crash는 replay로
  재현할 수 없다. 그 사실을 crash와 함께 기록하고 subset을 promotion에서 거부하는 것으로 처리한다.
- 생성 비용(LLM, VM 시간)이 gap 수에 비례해 는다. gap key 단위 공유와 `harness_generation` budget이 상한이다.
