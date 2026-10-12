# ReachabilityPlan Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 입력: `CandidateAnalysis` + `Harness Capability Specification`
> 목적: CandidateAnalysis의 가능한 경로 중 하나를 선택해 실제 Q1 scenario로 구체화한다.

## 1. 이 요소는 무엇인가

```text
Reachability Planning
    Type:        AGENT TASK
    Executed by: Agent SDK
    Inputs:
        CandidateAnalysis
        Harness Capability Specification
    Output:      ReachabilityPlan
```

`ReachabilityPlan`은 아직 실행 결과가 아니다.
현재 harness capability를 어떤 순서로 조합할지 나타내는 structured plan이다.

## 2. Stage 1 안에서의 위치

```text
VulnerabilityCandidate
        |
        v
Candidate Analysis
        |
        v
CandidateAnalysis
        |
        v
Harness Capability Specification
        |
        v
Reachability Planning
        |
        v
ReachabilityPlan
        |
        v
Harness Materialization
        |
        v
Runner: Build / VM / KCOV
        |
        v
Q1
```

## 3. Reachability Planning의 목표

질문은 하나다.

```text
"현재 harness가 이미 제공하는 capability만 사용해서,
 이 candidate에 도달하는 하나의 실제 scenario를 어떻게 만들 것인가?"
```

Agent는 여러 가능성 중 하나의 primary scenario를 선택한다.

## 4. ReachabilityPlan 데이터

```text
ReachabilityPlan
    candidate_id

    selected_path

    nfs_version

    scenario_steps[]

    required_capabilities[]

    q1_observation

    program_proposal              # concrete syz program 또는 기존 seed (§11)

    runtime_selection             # allowlist (§10)

    execution_constraints[]

    uncertainties[]
```

## 5. selected_path

`CandidateAnalysis.reachability_paths` 중 실제 구현할 경로 하나를 선택한다.

```text
selected_path
    entry_surface
    path_summary
    required_state[]
```

선택 기준:

```text
current harness로 표현 가능
state setup이 재현 가능
Q1 관측 가능
불필요한 mutation 없이 candidate까지 도달 가능
```

## 6. nfs_version

Scenario가 요구하는 NFS protocol version을 명시한다.

```text
3
4.0
4.1
4.2
```

이 값은 임의 execution policy가 아니라 candidate path의 semantic requirement다.

## 7. scenario_steps

Scenario는 capability를 참조하는 ordered step으로 표현한다. step은 `program_proposal`을 설명하고 검토하기
위한 구조화된 서술이며 Materializer가 펼치는 입력이 아니다(§11, issue #12).

```text
scenario_step
    capability_id
    action
    parameters
    expected_state_change
```

예:

```text
1. HCAP-01
   open lane client0/knfsd

2. HCAP-05
   establish existing normal-flow state

3. HCAP-02
   send selected NFS operation

4. HCAP-03
   collect remote KCOV
```

Agent가 arbitrary shell command를 scenario step으로 넣지 않는다.

Scenario가 target을 직접 호출할 필요는 없다.
필요한 state를 만든 뒤 kernel의 자동 실행을 기다리는 것도 유효한 reachability scenario다.

```text
state setup
    |
    v
automatic execution
    timer / workqueue / callback / lease renewal
    |
    v
candidate target
```

Q1은 이 자동 경로도 generation-attributed remote KCOV로 동일하게 판정한다.

## 8. required_capabilities

```text
required_capabilities:
    - HCAP-01
    - HCAP-03
    - ...
```

모든 ID는 machine-readable HCAP(04 §1.1)에 존재해야 하고, 그 entry의 `usable_by`에 `agent_stage1`이
있어야 한다. `validated_subset`의 scope 밖이나 `partially_validated` / `experimental` capability를 쓰면 plan에
명시한다(04 §3).

capability가 없으면 plan을 억지로 만들지 않고:

```text
unsupported_by_current_harness
```

로 판정한다.

Controller는 이 결과를 받아 `HarnessGapIssue`를 생성하거나 기존 issue에 연결하고,
candidate를 `blocked_harness_gap` 상태로 둔다.

## 9. q1_observation

Q1을 무엇으로 관측할지 계획한다.

```text
q1_observation
    target
        candidate source location

    expected_context
        selected_path가 target을 실행하는 execution context
        (RemoteKcovSupportBoundary의 context 이름, 06 §6.1)

    oracle
        HCAP-03 remote KCOV

    success_condition
        target code location mapped PC observed in
        generation-attributed remote coverage
```

`expected_context`는 Planning의 주장이며 Judge가 PC에서 추론하지 않는다. 이 값은 target이 관측되지
않았을 때 `NOT_REACHED`를 내릴 수 있는지만 정하고, 관측된 target을 걸러내지 않는다(06 §8–§10).
Planning이 support boundary 밖의 context를 고르면 실행 전에 gap으로 분류할 수 있다(07 §2).

Q1은 remote KCOV만 사용한다.
cross-thread ordering이나 handoff 분석이 필요해도 flow trace는 Q1 조건에 포함하지 않는다.
해당 정보는 Candidate Analysis/diagnostic 정보로만 사용한다.

## 10. execution_constraints

Harness가 의미를 유지하기 위한 runtime 제약만 담는다.

```text
execution_constraint
    description
```

예:

```text
knfsd remote coverage enabled
nfs.localio_enabled=N
selected NFS version fixed for the run
lane attribution enabled
manager snapshot mode (top-level snapshot) disabled
    when four-lane execution is required
    (qemu vm.snapshot is a disk-overlay setting and stays at its default)
```

CPU/RAM quota, retry 횟수, timeout 같은 운영 policy는 ReachabilityPlan에 넣지 않는다.

plan이 고를 수 있는 runtime surface는 다음 allowlist뿐이다(issue #12).

```text
runtime_selection
    selected profile / NFS version     # 실행당 하나
    fixture mode
    route / topology identity          # Stage 2용 proxied route (issue #10)
    enabled interface subset           # required capability interface의 부분집합
    seed / program artifact
    trace mode                         # 기본 off
```

sanitizer, resource limit, 반복 횟수, fuzz duration, retry budget은 trusted JobPolicy와 execution 설정이며
plan이 정하지 않는다. allowlist 밖의 환경 동작이 필요하면 `fixture_or_tool` gap이다(07 §4).

## 11. Harness Materialization

Reachability Planning(Agent)이 concrete syz program 또는 기존 seed를 제안한다. Application Component인
Harness Materializer는 이를 검증하고 실행 harness로 조립할 뿐 program을 만들지 않는다(issue #12).

```text
ReachabilityPlan
      |  program proposal / selected seed
      |  runtime_selection, required capabilities, q1_observation
      v
[COMPONENT] Harness Materializer
      |
      +-- pinned syzkaller strict parse
      +-- 모든 call이 required capability interface에 속하는지 확인
      +-- NFS root / profile acquisition 확인
      +-- profile / fixture / backend / client route 일관성 확인
      +-- 금지되거나 쓸 수 없는 call 거부
      +-- Stage 1 execution invariant 확인 (§10)
      +-- trusted fixture / runtime input bind
      +-- review manifest와 artifact hash 생성
      |
      v
ReachabilityHarness
```

Materializer는 call을 만들거나 program을 고치거나 candidate에 도달하는 방법을 추론하지 않는다. 거부는
typed reason으로 Reachability Planning에 돌려준다. capability interface의 authority는 machine-readable
HCAP이다(04 §1.1).

공통 runtime 검사는 corpus tooling과 같은 논리를 재사용할 수 있다. `tools/audit-normal-corpus.py`의 corpus
정리·admission 규칙은 harness 계약으로 따로 채택하지 않는 한 적용하지 않는다.

review manifest는 실행 전에 검증된 program과 runtime selection을 hash로 묶는다(approval binding).

현재 capability가 부족하면 Materializer가 source를 즉석에서 수정하지 않는다.
별도 Harness Extension Work에서 필요한 syzlang/pseudo-syscall/fixture/tool 확장을 구현·검증한 뒤
Capability Specification을 갱신하고 이 candidate를 재시도한다.

## 12. ReachabilityHarness

```text
ReachabilityHarness
    candidate_id
    selected profile / NFS version  # 실행당 하나 (issue #12)
    fixture mode                    # single | broad-knfsd
    route / topology identity       # Stage 2가 변조할 proxied route
    syz_program / selected seed     # Agent 제안, Materializer 검증 (§11)
    neutral control program         # ambient control (06 §11)
    fixture actions
    manager/runtime configuration
    required capability IDs
    Q1 observation configuration
    review manifest hash
```

이는 repository patch가 아니라 job-local runtime input이다.

program의 profile-open call은 선택한 profile과 맞아야 한다. mixed-profile scenario는 이후 명시적인 계약
확장으로만 허용한다(issue #12).

Stage 2로 넘길 harness는 Stage 2가 변조할 proxied route/topology에서 실행한다(issue #10). 현재 구체
값은 `SERVER_IMPL=both`이지만 계약은 기록된 route/topology identity다. identity 체계는 issue #13에서
정한다.

## 13. 실패 분류

```text
Planning failure
    no suitable reachability path
    unsupported_by_current_harness
    Q1 observability unavailable

Materialization failure (typed reason -> Reachability Planning repair)
    parse failure
    disallowed or unavailable call
    profile / fixture / route mismatch
    invalid runtime selection

Runtime failure
    build
    boot
    fixture
    KCOV collection

Q1 failure
    scenario executed but target not reached
```

각 실패는 같은 의미가 아니며 repair 위치도 다르다.

## 14. Patch와의 경계

Stage 1/2의 candidate execution과 harness extension work를 구분한다.

```text
Candidate execution
    |
    +-- current capability sufficient
    |       -> Q1 진행
    |
    +-- current capability insufficient
            -> HarnessGapIssue
            -> separate Harness Extension Work
            -> capability spec update
            -> candidate retry
```

Harness Extension Work에서는 syzlang, pseudo-syscall/executor, fixture/tool 같은
**harness patch**가 가능하다.

Linux kernel vulnerability fix patch는 Crash Report 이후 별도 phase다.
