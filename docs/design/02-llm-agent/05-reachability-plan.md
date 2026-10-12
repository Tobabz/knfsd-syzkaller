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

Scenario는 capability를 참조하는 ordered step으로 표현한다.

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

모든 ID는 Harness Capability Specification에 존재해야 한다.

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

    oracle
        HCAP-03 remote KCOV

    success_condition
        target code location mapped PC observed in
        generation-attributed remote coverage
```

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
snapshot disabled when four-lane execution is required
```

CPU/RAM quota, retry 횟수, timeout 같은 운영 policy는 ReachabilityPlan에 넣지 않는다.

## 11. Harness Materialization

ReachabilityPlan 다음에는 Application Component가 concrete runtime input을 만든다.

```text
ReachabilityPlan
      |
      v
[COMPONENT] Harness Materializer
      |
      +-- existing syzlang을 사용하는 .prog
      +-- existing corpus seed 선택/조합
      +-- existing fixture action
      +-- manager config overlay
      |
      v
ReachabilityHarness
```

Materializer는 **현재 capability를 사용하는 runtime artifact를 만든다.**

현재 capability가 부족하면 Materializer가 source를 즉석에서 수정하지 않는다.
별도 Harness Extension Work에서 필요한 syzlang/pseudo-syscall/fixture/tool 확장을 구현·검증한 뒤
Capability Specification을 갱신하고 이 candidate를 재시도한다.

## 12. ReachabilityHarness

```text
ReachabilityHarness
    candidate_id
    nfs_version
    syz_program / selected seed
    fixture actions
    manager/runtime configuration
    required capability IDs
    Q1 observation configuration
```

이는 repository patch가 아니라 job-local runtime input이다.

## 13. 실패 분류

```text
Planning failure
    no suitable reachability path
    unsupported_by_current_harness
    Q1 observability unavailable

Materialization failure
    invalid scenario parameters
    selected capability cannot render requested action

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
