# 2-Stage Vulnerability Agent Architecture

> 상태: **current design baseline**
> 기준일: 2026-10-09
> 목적: 0-Day 가능성이 있는 취약 함수/코드 지점을 입력으로 받아,
> (1) KCOV 도달성을 증명하는 fuzzing harness를 만들고,
> (2) Mutation Engine 규칙으로 취약 상태를 유도하여 crash evidence를 만드는 Agent 구조를 정의한다.
> 이 문서는 현재 Agent 구현의 유일한 architecture baseline이다.

## 1. 핵심 정의

이 설계에서 `VulnerabilityCandidate`는 **조사할 정확한 kernel code location**이다.

```text
VulnerabilityCandidate
    = exact kernel commit
      + source path
      + function or source range
```

Candidate에는 CVE, crash, patch, report 또는 다른 외부 evidence를 넣지 않는다.
왜 취약할 수 있는지, 어떤 path로 도달하는지, 어떤 NFS/RPC 상태가 필요한지는
`CandidateAnalysis`가 이후에 만든다.

Agent의 목표는 두 단계다.

```text
Stage 1: Reachability
    candidate 지점까지 도달 가능한 fuzzing harness를 knfsd-syzkaller에 맞게 만든다.
    remote KCOV/lane evidence로 target PC 도달을 판정한다.

Stage 2: Trigger
    Stage 1에서 확보한 시나리오를 유지하면서 Mutation Engine 규칙을 만든다.
    실제 mutation 적용 여부를 확인하고, syzkaller fuzzing에서 sanitizer/crash를 탐색한다.
```

Stage 2는 Stage 1의 Q1이 증명되기 전에는 시작하지 않는다.

## 2. 전체 흐름

### 2.1 요소의 종류

이 문서에서 이름은 네 종류로 구분한다.

| 종류 | 의미 | 예 |
|---|---|---|
| **Data** | 저장·전달되는 구조화 데이터 | `VulnerabilityCandidate`, `CandidateAnalysis`, `ReachabilityPlan` |
| **Repository Design Data** | 저장소 capability를 정리한 정적 명세 | `Harness Capability Specification` |
| **Component** | application code | Controller, Rule Compiler, Judges |
| **Agent Task** | Agent SDK가 reasoning을 수행하는 작업 | Candidate Analysis, Reachability Planning, Mutation Strategy |
| **Runner Task** | 격리된 실행 환경에서 실제 코드를 실행하는 작업 | build, VM, KCOV, fuzz |

즉 Candidate는 실행 주체가 아니라 **데이터 객체**다.

### 2.2 Stage 1 전 준비 구간

Stage 1 전에는 Controller의 intake/validation만 있다.

```text
1. Intake / Validation
   외부 caller가 VulnerabilityCandidate를 제출한다.
   Controller는 exact commit/path/symbol-or-range가 실제 source tree와 일치하는지만 검증한다.
```

Candidate가 승인되면 Agent는 Stage 1을 시작한다.

### 2.3 Actor 중심 전체 흐름

```text
EXTERNAL CALLER
    |
    |  [DATA] VulnerabilityCandidate
    v

APPLICATION CONTROLLER
    |
    | validate exact commit/path/location
    | store candidate
             =====================================
             STAGE 1 — REACHABILITY HARNESS
             =====================================
              |
              v
+-----------------------------+
| [AGENT TASK]                |
| Candidate Analysis          |
|                             |
| code role                   |
| call/state path             |
| NFS/RPC surface             |
| capability-spec matching    |
+-------------+---------------+
              |
              | [DATA] CandidateAnalysis
              v

+-----------------------------+
| [AGENT TASK]                |
| Reachability Planning       |
|                             |
| existing model reuse?       |
| capability composition      |
| missing capability?         |
+-------------+---------------+
              |
              +-- supported --> [DATA] ReachabilityPlan
              |                        |
              |                        v
              |
              +-- unsupported --> HarnessGapIssue
                                   |
                                   v
                            blocked_harness_gap
                                   |
                                   v
                         Harness Extension Work
                                   |
                                   v
                         capability spec update
                                   |
                                   +----> retry Stage 1

              [supported path]
              |
              v

+-----------------------------+
| [COMPONENT]                 |
| Harness Materializer        |
|                             |
| plan -> concrete artifacts  |
+-------------+---------------+
              |
              | [DATA] ReachabilityHarness
              v

+-----------------------------+
| [RUNNER TASK]               |
| Isolated Build / VM / KCOV  |
+-------------+---------------+
              |
              | [DATA] ReachabilityEvidence
              v

+-----------------------------+
| [COMPONENT] Q1 Judge        |
+-------------+---------------+
              |
         reached?
          /     \
        NO       YES
        |         |
        v         v
 Agent repair    Stage 2
                  |
             =====================================
             STAGE 2 — MUTATION / CRASH TRIGGER
             =====================================
                  |
                  v
+-----------------------------+
| [AGENT TASK]                |
| Mutation Strategy           |
+-------------+---------------+
              |
              | [DATA] MutationRuleSet
              v

+-----------------------------+
| [COMPONENT]                 |
| Mutation Rule Compiler      |
+-------------+---------------+
              |
              | [DATA] CompiledMutationRule
              v

+-----------------------------+
| [RUNNER TASK]               |
| Proxy + syz-manager fuzz    |
+-------------+---------------+
              |
              +--> [DATA] MutationEvidence
              |          |
              |          v
              |    [COMPONENT] M1 Judge
              |
              +--> [DATA] CrashEvidence
                         |
                         v
                   [COMPONENT] Q2 Judge
                         |
                         v
                   Final Evidence
                         |
                         v
                   Crash Report
                         |
                         v
                   Human Review
                         |
                         v
               POST-CRASH PHASE
               patch / fix analysis
```

## 3. 세 가지 독립 oracle

기존 Q1/Q2만으로는 Stage 2 실패를 충분히 진단하기 어렵다. 따라서 실제 runtime에서는 세 개의
관측을 분리한다.

```text
Q1 — Reachability
    Stage 1 harness가 candidate 함수/코드 지점에 도달했는가?

M1 — Mutation Application
    의도한 Mutation Engine rule이 의도한 RPC/NFS record에 실제 적용됐는가?

Q2 — Vulnerability Signal
    mutation이 적용된 fuzz execution에서 sanitizer/crash signal이 관측됐는가?
```

의미는 다음과 같다.

| Q1 | M1 | Q2 | 해석 |
|---|---|---|---|
| no | n/a | n/a | harness/시나리오가 candidate에 도달하지 못함 |
| yes | no | no | mutation rule 또는 matching/stream 문제 |
| yes | yes | no | mutation은 적용됐으나 현재 조건에서는 crash 없음 |
| yes | yes | yes | vulnerability signal; evidence freeze + replay + human review |

`Q2=no`는 `M1=no`와 절대 같은 결과로 취급하지 않는다.

## 4. Stage 1 — Reachability Harness

### 4.1 입력

```text
VulnerabilityCandidate
    candidate_id
    exact kernel revision
    source path
    function or exact source range
```

Candidate identity에는 execution policy, sanitizer, retry budget, requested outputs를 넣지 않는다.
그 값은 별도의 trusted `JobPolicy`가 소유한다.

### 4.2 Stage 1의 첫 Agent Task: Candidate Analysis

Candidate Analysis의 상세 계약은
[`03-candidate-analysis.md`](03-candidate-analysis.md)에 정의한다.

그 출력인 `CandidateAnalysis`를 Reachability Planning이 입력으로 사용한다.
Harness capability 판단은
[`04-harness-capability-spec.md`](04-harness-capability-spec.md)를 참조한다.

### 4.3 Reachability Planning

상세 계약은
[`05-reachability-plan.md`](05-reachability-plan.md)에 정의한다.

Agent SDK는 다음 reasoning을 수행한다.

```text
CandidateAnalysis
      -> select one reachability path
      -> match Harness Capability Specification
      -> choose existing capability sequence
      -> ReachabilityPlan
```

Agent는 build, VM, KCOV PASS를 주장하지 않는다.

### 4.4 ReachabilityPlan

`ReachabilityPlan`은 실행 가능한 shell script가 아니라 semantic plan이다.

예시 필드:

```text
ReachabilityPlan
    candidate_id
    target_oracle
        exact symbol / code location / build identity
    selected_path
    nfs_version
    scenario_steps[]
        capability_id
        action
        parameters
    required_capabilities[]
    q1_observation
    execution_constraints[]
    uncertainties[]
```

### 4.5 Harness artifact

Stage 1의 채택 가능한 산출물은 `ReachabilityHarness`다.

```text
ReachabilityHarness
    syz program / selected existing seed
    existing fixture actions
    manager/runtime config
    required capability IDs
    Q1 observation config
    exact source/build identities
```

ReachabilityHarness는 job-local runtime input이다.
Stage 1은 새 syzlang, pseudo-syscall, kernel instrumentation 또는 repository patch를 생성하지 않는다.
현재 capability로 candidate에 도달할 수 없으면 `unsupported_by_current_harness`로 남긴다.

### 4.6 Q1 판정

상세 계약은
[`06-reachability-evidence-q1.md`](06-reachability-evidence-q1.md)에 정의한다.

Q1 target hit/miss는 **현재 program generation에 귀속된 remote KCOV만**으로 판정한다.
global NFSD observer, local KCOV, flow trace, tracepoint, kprobe는 Q1 oracle이 아니다.
fixture 상태와 debugfs counter는 remote KCOV 실행의 유효성을 확인하는 health gate로만 사용한다.

target이 직접 syscall/RPC 처리에서 실행되든 timer, workqueue, callback, lease renewal 같은
자동 kernel execution에서 실행되든 구분하지 않는다. 현재 program generation에 귀속된
remote KCOV에서 target이 관측되면 Q1의 reachability 조건은 충족한다.
Q1은 특정 stimulus와 target 사이의 causal ordering을 증명하는 oracle이 아니다.

최소 evidence는 다음을 포함해야 한다.

```text
candidate target PC/symbol mapping
kernel build identity
seed/scenario artifact identity
lane identity
generation_begin / remote_start_ok / aggregate_published
remote .extra coverage
target PC hit result
generation_aborted / scratch_overflow
fixture/lane health
```

단순 `.extra != empty`는 candidate target 도달을 증명하지 않는다.

## 5. Stage 2 — Mutation / Trigger

### 5.1 Stage 2 진입 조건

Stage 2 input은 임의 candidate가 아니라 Q1이 증명된 Stage 1 package다.

```text
Stage2Input
    VulnerabilityCandidate
    CandidateAnalysis
    ReachabilityPlan
    ReachabilityHarness
    ReachabilityEvidence
    Q1Result = reached
```

따라서 Stage 2 repair가 Stage 1의 도달성을 우연히 깨뜨리는 것을 검출할 수 있어야 한다.

### 5.2 Agent SDK 책임

상세 계약은
[`08-mutation-rule-set.md`](08-mutation-rule-set.md)에 정의한다.

Mutation Strategy Agent는 다음을 분석한다.

```text
candidate weakness hypothesis
      -> vulnerable state/value
      -> responsible RPC/NFS message
      -> direction: C2S / S2C
      -> operation/message predicate
      -> semantic field/region
      -> mutation family
```

Agent 출력은 raw host command가 아니라 `MutationRuleSet`이다.

### 5.3 MutationRuleSet

```text
MutationRuleSet
    candidate_id
    intents[]
        direction
        traffic_scope
        record_match
        edit
        expected_effect
        constraints[]
    uncertainties[]
```

Agent는 semantic field/operation을 선택한다.
Mutation Rule Compiler는 이 intent를 검증·정규화해 `CompiledMutationRule`로 낮추고,
live offset/current value/original bytes는 Proxy가 실제 RPC record를 decode한 뒤 runtime에 resolve한다.

목표 Proxy architecture는
[`../03-nfs-proxy/01-architecture.md`](../03-nfs-proxy/01-architecture.md)에 정의한다.
semantic decoder/resolver 또는 concrete mutation capability가 없어 intent를 실행할 수 없으면
`unsupported_by_current_harness`로 처리하고
`HarnessGapIssue(gap_class=mutation_engine)`를 생성/연결한다.

## 6. Mutation Engine 연결

`tools/nfs-proxy`는 Stage 2 Proxy의 현재 구현 기반이다.
목표 architecture는 current NFSPARM ABI보다 상위의 semantic runtime resolution을 정의한다.

```text
NFSPARM1
    same-width fixed replacement

NFSPARM2
    REPLACE
    INSERT
    DELETE
    OP_APPEND
    OP_PREPEND
```

현재 구현에서 재사용할 가치가 있는 invariant는 다음과 같다.

```text
content-addressed predicate
verify-before-patch
apply-to-all matching semantics
same live/replay apply implementation
durable arm-N.delta
```

목표 architecture에서도 ordinal/Nth-message 방식의 불안정한 replay identity는 허용하지 않는다.
현재 NFSPARM1/2의 precomputed offset/original-byte 요구는 목표 architecture의 제약이 아니다.

## 7. M1 — Mutation Application Evidence

Proxy ACK는 rule registration만 증명하고 실제 적용을 증명하지 않는다.

따라서 M1은 별도 evidence로 판정한다.

```text
MutationEvidence
    mutation_rule_id
    compiled arm artifact identity
    delta artifact identity
    predicate_hits
    applied
    refused_orig_diff
    refused_out_of_range
    replay application result
    lane/backend/client identity
```

`M1=applied`가 아니면 `Q2=not_observed`라는 결론을 내리지 않는다.

## 8. Q2 — Crash / Sanitizer Evidence

Stage 2 fuzzing은 `syz-manager`의 ordinary program mutation과 candidate-specific mutation rule을 함께
사용할 수 있다. 최종 Q2는 단순 "crash file exists"가 아니라 reviewed sanitizer/crash oracle로 판정한다.

```text
CrashEvidence
    candidate identity
    Q1 evidence id
    M1 mutation evidence id
    syz program / seed artifact identity
    mutation delta artifact identity
    kernel/syzkaller/image identities
    sanitizer report
    dmesg / stack trace
    coverage evidence
    crash signature
    replay result
```

## 9. Reproduction identity

Mutation-driven crash의 재현 단위는 syz program 하나가 아니다.

```text
CrashReproducer
    = syz program
    + mutation delta
    + ReachabilityHarness identity
    + kernel/syzkaller source pins
    + fixture/image identity
```

현재 proxy의 durable delta는 mutation이 실제 어떤 bytes에 적용됐는지를 self-contained하게 남기는
reproduction contract로 사용한다.

## 10. Agent SDK와 deterministic boundary

Agent SDK는 reasoning runtime으로 사용한다.

```text
Agent SDK owns
    candidate/path analysis
    reachability planning
    harness-gap reasoning
    mutation strategy
    semantic mutation intents
    scenario/rule refinement

Agent SDK does NOT own
    source pin resolution authority
    security policy
    shell command authority
    build PASS
    VM/KVM execution
    KCOV Q1 verdict
    mutation M1 verdict
    sanitizer/crash Q2 verdict
    approval state
    publish credentials
```

가능한 초기 형태는 한 SDK 안에 두 specialist를 두는 것이다.

```text
                    Main Agent
                        |
             +----------+----------+
             |                     |
             v                     v
    Reachability Agent       Mutation Agent
             |                     |
             v                     v
    ReachabilityPlan        MutationRuleSet
```

필요해질 때만 kernel-path analyst, NFS protocol analyst, harness analyst 같은 specialist를 추가한다.

## 11. Controller / Runner 책임

Agent SDK 밖의 application controller는 다음을 소유한다.

```text
candidate/job durable state
stage transition
Q1-before-Stage2 invariant
policy / approval
artifact hashes
failure routing
repair budgets
evidence lineage
```

isolated Linux/KVM runner는 다음을 소유한다.

```text
prepared syzkaller/kernel environment use
VM/fixture
remote KCOV collection
Q1 deterministic judge
proxy mutation execution/replay
M1 deterministic judge
bounded syz-manager fuzz
sanitizer/crash collection
Q2 deterministic judge
```

## 12. Repair boundaries

실패 원인에 따라 돌아갈 단계가 다르다.

```text
Q1 not reached
    -> ReachabilityPlan / harness repair

Reachability Planning unsupported
    -> HarnessGapIssue
    -> blocked_harness_gap
    -> Harness Extension Work
    -> capability spec update
    -> Stage 1 retry

Q1 reached, M1 not applied
    -> MutationRuleSet / rule compiler repair

Q1 reached, M1 applied, Q2 not observed
    -> mutation strategy/search-space refinement
       또는 valid non-trigger result

Q1 reached, M1 applied, Q2 observed
    -> stop autonomous mutation repair
       freeze evidence
       replay
       final human review
```

build dependency, broken fixture, image/config mismatch는 LLM source repair로 보내지 않는다.

## 13. Crash Report 이후 Patch 경계

Stage 1과 Stage 2는 crash report 생성까지를 책임진다.

```text
Stage 1
    Q1 reachability
        |
        v
Stage 2
    M1 mutation + Q2 crash
        |
        v
Crash Report
        |
        v
Post-Crash Phase
    root-cause / patch / fix validation
```

따라서 Stage 1/2 Agent는 vulnerability fix patch를 만들지 않는다.
현재 harness capability 자체가 부족한 경우에도 campaign 안에서 syzkaller/kernel source patch를 만들어
즉석에서 기능을 확장하지 않는다. 대신 `HarnessGapIssue`를 생성/연결하고 candidate를
`blocked_harness_gap`으로 둔다.

Harness gap은 별도 Harness Extension Work에서 해결한다. 이 workflow는 syzlang, pseudo-syscall/executor,
fixture/tool, mutation-engine patch를 만들 수 있다. 해결 후 Harness Capability Specification을 갱신하고
blocked candidate를 재시도한다.

Linux kernel source observability patch는 pre-crash 자동 대상이 아니다. 필요 시 human-decision issue로
관리한다.

## 14. 다음 상세 설계 순서

아래 순서로 한 요소씩 고정한다.

1. [`VulnerabilityCandidate`](02-vulnerability-candidate.md) — detailed contract fixed
2. [`CandidateAnalysis`](03-candidate-analysis.md) — detailed contract fixed
3. [`Harness Capability Specification`](04-harness-capability-spec.md) — detailed contract fixed
4. [`ReachabilityPlan`](05-reachability-plan.md) — detailed contract fixed
5. [`ReachabilityEvidence / Q1 Judge`](06-reachability-evidence-q1.md) — detailed contract fixed
6. [`Harness Gap Issue`](07-harness-gap-issue.md) — detailed contract fixed
7. [`MutationRuleSet`](08-mutation-rule-set.md) — detailed contract fixed
8. [`NFS Proxy target architecture`](../03-nfs-proxy/01-architecture.md) — draft
9. Mutation Rule Compiler
10. `MutationEvidence` / M1 judge
11. `CrashEvidence` / Q2 judge
12. repair/state graph
13. Agent SDK concrete selection and agent/tool definitions
