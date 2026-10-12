# CandidateAnalysis Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 입력 설계: `02-vulnerability-candidate.md`
> 목적: Stage 1의 첫 Agent Task가 무엇을 분석하고 어떤 데이터를 다음 작업에 넘기는지 정의한다.

## 1. 이 요소는 무엇인가

```text
Candidate Analysis
    Type:        AGENT TASK
    Executed by: Agent SDK
    Input:       VulnerabilityCandidate
    Output:      CandidateAnalysis
    Mode:        read-only reasoning
```

`Candidate Analysis`는 작업이고, `CandidateAnalysis`는 그 작업의 결과 데이터다.

## 2. Stage 1 안에서의 위치

```text
[DATA] VulnerabilityCandidate
          |
          v
=====================================
STAGE 1 — REACHABILITY HARNESS
=====================================
          |
          v
[AGENT TASK] Candidate Analysis
          |
          v
[DATA] CandidateAnalysis
          |
          v
[AGENT TASK] Reachability Planning
          |
          v
[DATA] ReachabilityPlan
          |
          v
Harness 구현 / Build / VM / KCOV
          |
          v
Q1
```

## 3. 누가 무엇을 하는가

### Application Controller

```text
validated VulnerabilityCandidate 준비
        |
        v
Agent SDK의 Candidate Analysis 실행
        |
        v
CandidateAnalysis schema 확인
        |
        v
Reachability Planning으로 전달
```

### Agent SDK

Agent는 candidate와 repository를 읽고 다음을 분석한다.

```text
candidate code의 역할
candidate까지의 실행 경로
그 경로에 필요한 protocol/kernel state
외부에서 통제 가능한 입력
현재 knfsd-syzkaller가 가진 harness capability
부족한 capability
Q1 관측 시 주의할 점
```

Agent는 이 단계에서 repository를 수정하거나 runtime을 실행하지 않는다.

## 4. Agent가 읽을 수 있는 것

Candidate Analysis는 두 종류의 입력을 읽는다.

```text
Linux kernel source at candidate.kernel_commit

Harness Capability Specification
    docs/design/02-llm-agent/04-harness-capability-spec.md
    job에 묶인 harness의 hcap_revision (01 §11.2)
```

Agent는 harness capability discovery를 위해 매 job마다 `knfsd-syzkaller` 전체를 다시 탐색하지 않는다.
현재 지원 기능과 제약은 Harness Capability Specification을 우선 사용한다.

구현 세부가 필요한 경우에만 spec의 `source_refs`가 가리키는 파일을 read-only로 확인한다.

Kernel source에 필요한 도구의 의미는 다음과 같다.

```text
read source
find references
find callers/callees
search dispatch/operation tables
search structs/state fields
```

구현은 grep, code index, clang tooling 등으로 바뀔 수 있다.

## 5. CandidateAnalysis 데이터

최소 구조는 다음과 같다.

```text
CandidateAnalysis
    candidate_id

    code_role

    reachability_paths[]

    harness_assessment

    observability_constraints[]

    uncertainties[]
```

## 6. code_role

candidate 코드가 subsystem 안에서 어떤 역할을 하는지 설명한다.

```text
code_role
    summary
    subsystem
    relevant_objects[]
```

예:

```text
summary:
    NFSv4 state transition 처리

subsystem:
    NFSv4 state management

relevant_objects:
    client
    session
    stateid
```

## 7. reachability_paths

candidate까지 도달 가능한 path를 하나 이상 표현한다.

```text
reachability_path
    entry_surface

    steps[]
        source_path
        symbol
        role

    required_state[]

    controllable_inputs[]
```

### entry_surface

외부 또는 상위 실행의 시작점을 표현한다.

```text
nfs_request
rpc_callback
client_vfs_operation
background_work
timer
cleanup
reclaim
```

`background_work`, `timer`, callback 같은 자동 실행 경로도 1급 reachability path다.
외부 입력이 target을 직접 호출할 필요는 없으며, 외부 입력이 필요한 state를 만든 뒤
kernel의 자동 작업이 target에 도달하는 경로를 분석할 수 있다.

### required_state

candidate에 도달하기 전에 필요한 상태를 표현한다.

```text
required_state
    category
    description
    setup_condition
```

category 예:

```text
client
session
slot
stateid
open_state
lock_state
delegation
lease
file_state
callback
grace/reclaim
async_work
```

### controllable_inputs

harness가 해당 path에서 영향을 줄 수 있는 입력을 표현한다.

```text
controllable_input
    direction
    surface
    semantic_target
    available_control
```

direction 예:

```text
C2S
S2C
local_client_action
timing/concurrency
```

available_control 예:

```text
existing syscall
existing syzlang
raw NFS/RPC send
proxy
fixture action
concurrency/order
```

## 8. harness_assessment

현재 knfsd-syzkaller가 이 path를 얼마나 표현할 수 있는지 정리한다.

```text
harness_assessment
    reusable[]
    gaps[]
```

### reusable

```text
reusable_capability
    capability_id
    purpose
```

예:

```text
HCAP-01
HCAP-02
HCAP-03
HCAP-05
```

### gaps

```text
harness_gap
    kind
    description
```

kind 예:

```text
syzlang
pseudo_syscall
seed/scenario
fixture
state_setup
observability
unsupported
```

Candidate Analysis은 gap을 찾기만 한다.
현재 capability에 없는 기능이 필요하면 `unsupported_by_current_harness` 가능성을 명시한다.
이 단계에서 harness를 확장하는 source patch를 제안하지 않는다.

## 9. observability_constraints

Q1 설계에 영향을 주는 관측 조건을 기록한다.

```text
observability_constraint
    description
```

예:

```text
worker thread에서 실행됨
remote KCOV attribution 필요
cross-thread handoff 존재
target이 inline될 가능성 있음
PC만으로 ordering을 증명할 수 없음
현재 generation-attributed remote KCOV 범위 밖일 수 있음
```

이 값은 Q1 판정 결과가 아니다.
flow trace나 tracepoint가 path 이해에 도움을 줄 수는 있지만 Q1 oracle에는 참여하지 않는다.

## 10. uncertainties

source만으로 확정할 수 없는 점을 명시한다.

```text
uncertainty
    description
    impact_on_reachability
```

Reachability Planning은 이 uncertainty가 실제 harness 설계를 막는지 판단한다.

## 11. 이 작업의 출력 예시

```text
CandidateAnalysis
    candidate_id: VC-001

    code_role:
        subsystem: NFSv4 state management
        summary: <analysis result>
        relevant_objects:
            - session
            - stateid

    reachability_paths:
        - entry_surface: nfs_request
          steps:
              - <RPC/NFS dispatch>
              - <intermediate function>
              - <candidate>
          required_state:
              - <required session/state>
          controllable_inputs:
              - direction: C2S
                surface: <NFS operation>
                available_control: existing syzlang

    harness_assessment:
        reusable:
            - <existing capability>
        gaps:
            - <missing capability>

    observability_constraints:
        - remote KCOV attribution required

    uncertainties:
        - <remaining unknown>
```

## 12. 이 작업에서 하지 않는 것

```text
source 수정
syz program 생성
syzlang/pseudo-syscall 구현
kernel instrumentation 구현
manager config 생성
build
VM 실행
KCOV 판정
mutation rule 생성
fuzz 실행
crash 판정
```

## 13. Reachability Planning으로의 handoff

```text
CandidateAnalysis
        |
        +-- code role
        +-- reachability paths
        +-- required state
        +-- controllable inputs
        +-- reusable harness capability
        +-- harness gaps
        +-- observability constraints
        +-- uncertainties
        |
        v
Reachability Planning
```

Reachability Planning은 여기서 **하나의 실제 Q1 scenario**를 선택하고,
필요한 harness artifact를 구체화한다.

## 14. 언제 Candidate Analysis를 다시 하나

Q1 실패 원인이 분석 자체에 있을 때만 다시 수행한다.

```text
Q1 실패
   |
   +-- build/fixture/artifact 구현 문제
   |      -> Candidate Analysis 재실행 안 함
   |
   +-- 선택한 call/state path가 틀림
   |      -> Candidate Analysis 재실행 가능
   |
   +-- 중요한 state dependency를 놓침
          -> Candidate Analysis 재실행 가능
```
