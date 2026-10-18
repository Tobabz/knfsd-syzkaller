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

이 문서에서 이름은 다섯 종류로 구분한다.

| 종류 | 의미 | 예 |
|---|---|---|
| **Data** | 저장·전달되는 구조화 데이터 | `VulnerabilityCandidate`, `CandidateAnalysis`, `ReachabilityPlan` |
| **Repository Design Data** | 저장소에 버전과 함께 두는 정적 명세 | `Harness Capability Specification`, `JudgeProfile`, `RemoteKcovSupportBoundary` |
| **Component** | application code | Controller, Rule Compiler, Judges |
| **Agent Task** | Agent SDK가 reasoning을 수행하는 작업 | Candidate Analysis, Reachability Planning, Mutation Strategy |
| **Runner Task** | 격리된 실행 환경에서 실제 코드를 실행하는 작업 | build, VM, KCOV, fuzz |

즉 Candidate는 실행 주체가 아니라 **데이터 객체**다.

용어: NFS Proxy(`tools/nfs-proxy`)는 운영 문서의 NFS 특화 Mutation Engine과 같은 컴포넌트이고,
**Edit Applier**는 그 내부에서 resolve된 concrete edit를 검증하고 적용하는 단계다(`03-nfs-proxy/01` §10).

### 2.2 Stage 1 전 준비 구간

Stage 1 전에는 Controller의 intake/validation만 있다.

```text
1. Intake / Validation
   외부 caller가 VulnerabilityCandidate를 제출한다.
   Controller는 exact commit/path/symbol-or-range가 실제 source tree와 일치하는지만 검증한다.

2. Harness binding
   Controller는 candidate.kernel_commit용으로 검증된 harness build를 job에 묶는다(§11.2).
   없으면 HarnessGapIssue를 연결하고 job을 blocked_harness_gap으로 둔다.
```

harness가 묶이면 Agent는 Stage 1을 시작한다.

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
    | bind validated harness build for kernel_commit (§11.2)
    |     none -> HarnessGapIssue -> blocked_harness_gap
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
| validate / assemble program |
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
| baseline-with-rules gate    |
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
    harness 실행이 candidate 함수/코드 지점에 도달했는가?

M1 — Mutation Application
    rule별로, 의도한 semantic mutation이 실제 record에 적용됐는가?

Q2 — Vulnerability Signal
    Stage 2 execution에서 sanitizer/crash signal이 관측됐는가?
```

세 관측은 서로를 대신하지 않는다. Q2는 sanitizer/crash 신호만 판정하는 oracle이며 crash와 candidate의
연관은 판정하지 않는다(§8). M1 판정 계약은 §7이 소유한다.

Stage 2의 실행 단위는 둘로 나눈다(issue #2).

```text
Stage2Campaign
    한 candidate / harness / rule set의 fuzz campaign.
    여러 program execution, lane, VM instance에 걸친다.
    ExecutionHarnessIdentity는 campaign 전체에서 하나다 (§11.2).

ProgramGenerationExecution
    한 lane에서 remote-KCOV generation 하나로 실행한 syz program 하나.
    M1 evidence와 ReplayResult 비교의 단위다.
```

fatal sanitizer report로 VM이 죽은 generation은 FINISH 전에 끝나 remote coverage를 publish하지 못한다
(syzkaller 0001은 generation coverage를 FINISH 성공 전까지 격리한다). 그 generation의 Stage 2 Q1은
`unavailable`로 기록하며 crash 해석의 조건으로 요구하지 않는다.

해석은 다음 세 표를 따른다(issue #4).

**baseline-with-rules gate.** fuzz campaign 전에 Stage 1 시나리오를 rule set을 설치한 상태로 실행한다.
같은 조건의 neutral program도 실행한다(아래 ambient control).
반복 횟수는 job policy가 정한다. 여러 번 반복하면 반복마다 아래 표를 적용하고, 가장 위의 행을 gate 결과로 한다
(`09` §4).

| Q1 (target mode/rules) | rule별 M1 | 경로 |
|---|---|---|
| NOT_REACHED | any | gate 실패. target mode, rule, runtime 중 어디서 도달성이 퇴행했는지 진단한다. NOT_REACHED는 `06` §9의 조건을 만족할 때만 나온다(issue #9) |
| INCONCLUSIVE | any | runtime/evidence repair 후 gate 재실행. reason이 `unsupported_attribution`이면 `06` §13의 gap 경로 |
| REACHED | gate가 평가한 rule 중 하나라도 INCONCLUSIVE | runtime/evidence repair 후 gate 재실행. mutation evidence 경로가 확정되기 전에는 fuzz campaign을 시작하지 않는다 |
| REACHED | `targets_baseline_traffic=true`인 intent의 M1(§7.1)이 NOT_APPLIED | fuzzing 전에 rule/strategy repair |
| REACHED | 그 밖 | fuzz campaign 시작 |

표는 위에서부터 처음 맞는 행을 적용한다.

**ambient control (issue #10).** Stage 1과 gate는 같은 harness identity, fixture mode, NFS version,
route/topology, lease 설정, trace mode에서 scenario NFS operation이 없는 neutral program도 실행한다(`06` §11).
gate의 neutral run에도 rule set을 설치한다. 결과는 oracle이 아니며 위 표의 경로와 Q1/M1/Q2 판정을
바꾸지 않는다.

- neutral run에서 target이 관측되면 `q1_preservation_unverifiable`을 기록한다. Q1만으로는 scenario
  퇴행과 ambient hit를 구분할 수 없으므로 scenario 도달성이 유지됐다고 주장하지 않는다. 이것만으로 Q1을
  `INCONCLUSIVE`로 바꾸거나 campaign을 막지 않는다.
- gate의 neutral run에서 `APPLIED`인 rule은 `ambient_applied`로 기록한다. M1 판정은 바뀌지 않는다.
- 관측되지 않음은 그 control window에서 보지 못했다는 뜻일 뿐이다. scenario가 Q1이나 M1을 일으켰다는
  증명이 아니다.
- control evidence가 invalid하거나 control을 실행하지 못했으면 `ambient_control_unavailable`을 기록한다
  (`06` §11, issue #18 F6). 관측되지 않음으로도, scenario 도달성이 유지됐다는 확인으로도 바꾸지 않는다. gate의
  neutral run에서 M1이 `INCONCLUSIVE`인 rule은 `ambient_applied`도 알 수 없다고 기록한다. 이 경우도 위 표의
  경로와 Q1/M1/Q2 판정을 바꾸지 않는다.
- neutral program은 Agent가 아니라 repository의 trusted catalog에서 Materializer가 고르고 검증한다(`05` §11).
- 두 flag는 인과 해석만 한정한다. scenario traffic을 주장하는 hypothesis에는 그 traffic을 구분하는 typed
  selector/predicate나 matched-control evidence가 필요하다. background traffic을 의도한 strategy에서는
  `ambient_applied` rule도 hypothesis에 남을 수 있다. campaign 경로는 §7.1의 hypothesis 집계를
  따른다(issue #5).

**FINISH를 마친 fuzz generation** (rule별)

| Stage 2 Q1 | M1 | 의미 |
|---|---|---|
| REACHED | APPLIED | 도달한 generation에서 mutation이 실행됐다. 취약점이 없다는 결론은 내리지 않는다 |
| REACHED | NOT_APPLIED | 도달한 generation에서 rule이 match되지 않았다. campaign 단위 진단에 쓴다 |
| REACHED | INCONCLUSIVE | evidence 공백. 반복되면 infrastructure repair |
| NOT_REACHED / INCONCLUSIVE | any | 정상 fuzzing data. 개별 generation을 harness 실패로 보내지 않는다 |

**crash (Q2 관측).** rule별로 §8의 `CrashContextWindow` 전체에 대해 평가한다.

| `M1(rule_id, CrashContextWindow)` | 그 rule에 대한 의미 |
|---|---|
| window의 한 generation 이상에서 APPLIED | crash 전 또는 crash 중에 그 rule의 mutation이 적용됐다. evidence를 freeze하고 window를 순서대로 replay한 뒤 human review로 보낸다. delivery state가 연관의 강도를 한정한다 |
| window의 모든 generation에서 NOT_APPLIED | 그 rule은 window 안에서 적용되지 않았다 |
| APPLIED가 없고 INCONCLUSIVE가 하나 이상 | 그 rule에 대해 미해결. evidence/replay를 조사한다 |

CrashEvidence는 rule별·intent별·generation별 vector 전체를 보존한다. hypothesis 단위 결론은 §7.1의
`HypothesisM1(CrashContextWindow)`로 내린다(issue #5).

`Q2=NOT_OBSERVED`는 `M1=NOT_APPLIED`와 절대 같은 결과로 취급하지 않는다. `M1=APPLIED`이고 `Q2=NOT_OBSERVED`여도
"유효한 non-trigger"라는 결론은 내리지 않는다.

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

`ReachabilityPlan`은 실행 가능한 shell script가 아니라 semantic plan이다. field와 의미는 `05` §4가 소유하며
여기에 다시 쓰지 않는다. Q1 target은 `q1_observation`(`05` §9)에 있고, build별 PC mapping은 Q1 Judge가
evidence의 identity로 한다(`06` §5).

### 4.5 Harness artifact

Stage 1의 채택 가능한 산출물은 `ReachabilityHarness`다.

```text
ReachabilityHarness
    syz program / selected existing seed      # Agent 제안, Materializer 검증 (05 §11)
    existing fixture actions
    manager/runtime config
    required capability IDs
    Q1 observation config
    ExecutionHarnessIdentity                  # materialize 대상 (§11.2)
```

ReachabilityHarness는 job-local runtime input이다.
Stage 1은 새 syzlang, pseudo-syscall, kernel instrumentation 또는 repository patch를 생성하지 않는다.
현재 capability로 candidate에 도달할 수 없으면 `unsupported_by_current_harness`로 남긴다.
기존 capability로 표현되는 새 sequence는 gap이 아니며 Agent가 job-local program으로 쓴다(issue #12).

### 4.6 Q1 판정

상세 계약은
[`06-reachability-evidence-q1.md`](06-reachability-evidence-q1.md)에 정의한다.

Q1 target hit/miss는 **현재 program generation에 귀속된 remote KCOV만**으로 판정한다.
global NFSD observer, local KCOV, flow trace, tracepoint, kprobe는 Q1 oracle이 아니다.
fixture 상태와 debugfs counter는 remote KCOV 실행의 유효성을 확인하는 health gate로만 사용한다.
plan의 `expected_context`와 `RemoteKcovSupportBoundary`는 target이 관측되지 않았을 때 `NOT_REACHED`를
내릴 수 있는지만 정한다(`06` §8–§10, issue #9).

target이 직접 syscall/RPC 처리에서 실행되든 timer, workqueue, callback, lease renewal 같은
자동 kernel execution에서 실행되든 구분하지 않는다. 현재 program generation에 귀속된
remote KCOV에서 target이 관측되면 Q1의 reachability 조건은 충족한다.
Q1은 특정 stimulus와 target 사이의 causal ordering을 증명하는 oracle이 아니다.

최소 evidence는 다음을 포함해야 한다.

```text
candidate target PC/symbol mapping
ExecutionHarnessIdentity (host-stamped, §11.2)
seed/scenario artifact identity
lane identity
generation_begin / remote_start_ok / aggregate_published
remote .extra coverage
target PC hit result
generation_aborted / scratch_overflow
context별 loss / rejection counter delta
lane trace mode
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

Q1 evidence의 ExecutionHarnessIdentity는 Stage 2가 실행할 identity와 같아야 한다. 다르면 이 package는 Stage 2
입력이 아니며, Controller가 Stage 1 harness를 새 identity에서 다시 실행한다(§11.2).

따라서 Stage 2 repair가 Stage 1의 도달성을 우연히 깨뜨리는 것을 검출할 수 있어야 한다.
이 검출은 fuzz campaign 전에 실행하는 baseline-with-rules gate(§3)가 맡는다. target이 ambient
control에서도 관측되면 이 검출은 불가능하며 gate는 `q1_preservation_unverifiable`을 기록한다.

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
    intents[]                  # typed MutationIntent (08 §5)
        intent_id
        traffic_scope
        selector
        mutation
        targets_baseline_traffic
        expected_effect          # 실행하지 않는 설명
    hypotheses[]
    uncertainties[]
```

Agent는 runtime의 typed vocabulary로 intent를 쓴다. prose는 실행하지 않는다(issue #5).
Mutation Rule Compiler는 이 intent를 결정적으로 검증·bind해 `CompiledMutationRule`로 낮추고,
live offset/current value/original bytes는 Proxy가 실제 RPC record를 decode한 뒤 runtime에 resolve한다.

목표 Proxy architecture는
[`../03-nfs-proxy/01-architecture.md`](../03-nfs-proxy/01-architecture.md)에 정의한다.
semantic decoder/resolver 또는 concrete mutation capability가 없어 intent를 실행할 수 없으면
`unsupported_by_current_harness`로 처리하고
`HarnessGapIssue(gap_class=mutation_engine)`를 생성/연결한다.
Agent는 M7 promotion을 통과한 semantic capability subset만 쓰며, intent를 legacy NFSPARM capability
(HCAP-07/08/09)로 낮추지 않는다(issue #8).

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
semantic / content-addressed selection
verify-before-apply
apply-to-all matching semantics
same live/replay semantic path
durable write-ahead mutation evidence before exposure
```

`arm-N.delta`는 이 성질의 legacy 구현이며 target invariant가 아니다. NFSPARM/NFSPDLT는 사람이 작성한
legacy/manual campaign 전용이며 Agent pipeline은 이를 쓰지 않는다(issue #8). 한 lane에서 legacy arm과
target mode는 동시에 활성화되지 않는다(issue #2).

목표 architecture에서도 ordinal/Nth-message 방식의 불안정한 replay identity는 허용하지 않는다.
현재 NFSPARM1/2의 precomputed offset/original-byte 요구는 목표 architecture의 제약이 아니다.

## 7. M1 — Mutation Application Evidence

Proxy ACK는 rule registration만 증명하고 실제 적용을 증명하지 않는다.

따라서 M1은 별도 evidence로 판정한다. 이 절의 계약은 issue #4에서 합의했으며 Proxy 구현 M4/M5의
선행 조건이다.

### 7.1 M1 판정

M1은 `ProgramGenerationExecution`(§3)마다 `rule_id`별로 판정한다.

```text
M1Status
    APPLIED
    NOT_APPLIED
    INCONCLUSIVE
```

| 판정 | 조건 |
|---|---|
| `APPLIED` | 그 generation에 그 rule의 유효한 host-durable `EXPOSURE_INTENT`가 있다 |
| `NOT_APPLIED` | activation과 deactivation barrier가 모두 ACK됐고, 그 rule에 대해 clean인 closure를 가진 durable `GENERATION_COMPLETE`가 있으며(`03-nfs-proxy/05` §21), 그 rule의 `EXPOSURE_INTENT`가 없다 |
| `INCONCLUSIVE` | 그 밖의 모든 경우. crash 뒤 summary가 없는 경우, barrier 실패, 그 rule에 clean이 아닌 closure, summary 뒤의 G event나 sink의 post-close 거부 기록(§11.1의 내부 불일치)을 포함한다 |

crash 뒤 `EXPOSURE_INTENT`가 없다는 사실만으로 `NOT_APPLIED`를 추론하지 않는다. deactivation ACK는
CALL admission 종료만 뜻하며 G의 application evidence 종료가 아니다. 종료는 Proxy가 closure 뒤 남기는
`GENERATION_COMPLETE`가 정한다(`03-nfs-proxy/01` §16, issue #18 F1).

rule M1은 intent와 hypothesis로 집계한다(issue #5). intent 하나는 Compiler가 만든 rule 하나 이상을 가진다
(`08` §12).

```text
IntentM1(generation)
    APPLIED        child rule 중 하나라도 APPLIED
    NOT_APPLIED    모든 child rule이 NOT_APPLIED
    INCONCLUSIVE   그 밖

HypothesisM1(generation)                 # requirement: all
    APPLIED        모든 member intent가 이 generation에서 APPLIED
    NOT_APPLIED    member intent 중 하나라도 NOT_APPLIED
    INCONCLUSIVE   그 밖

HypothesisM1(CrashContextWindow)
    APPLIED        HypothesisM1(generation)이 APPLIED인 generation이 하나 이상
    NOT_APPLIED    모든 generation에서 NOT_APPLIED
    INCONCLUSIVE   그 밖
```

member intent가 서로 다른 generation에서 적용된 것은 joint 적용으로 보지 않는다. generation을 넘는 joint
trigger는 replay와 review로 다루며, 결정적으로 주장하려면 이후의 typed ordering/state 계약이 필요하다
(issue #6). intent별·generation별 vector는 항상 보존한다.

`APPLIED`는 그 generation에서 matching record가 변조됐다는 뜻이다. 그 record가 시나리오가 만든
traffic인지 ambient traffic인지는 구분하지 않는다(issue #10). neutral run에서도 적용되는지는 gate가
`ambient_applied`로 따로 기록한다(§3).

### 7.2 delivery는 별도 차원이다

M1은 적용(application)을 판정하고 전달(delivery)은 판정하지 않는다. 적용된 batch마다 delivery state를
필수 evidence로 남긴다.

```text
delivery_state
    complete   # EXPOSURE_INTENT + FORWARD_COMPLETE
    failed     # EXPOSURE_INTENT + FORWARD_FAILED
    unknown    # EXPOSURE_INTENT만 있고 forward 종료 event가 없음
```

`unknown`은 `APPLIED`로 세지만 확인된 delivery로 세지 않는다. `failed`는 그 batch의 완전한 forward가
성립하지 않았다는 뜻이다. host append가 끝났지만 ACK가 유실된 `EXPOSURE_INTENT`도 적용 evidence로
남으며, forward event 없이 delivery로 승격하지 않는다.

### 7.3 non-application evidence

normal non-match를 하나씩 durable하게 기록하지 않는다. generation마다 terminal summary
`GENERATION_COMPLETE`를 남긴다. field와 closure 규칙은 `03-nfs-proxy/05` §21이 소유한다. summary에는
rule_id별 resolver taxonomy count(`03-nfs-proxy/04` §31)와 closure reason이 있다.

### 7.4 MutationEvidence

```text
MutationEvidence                 # Runner가 수집하고 봉인한다 (§11.1)
    program_generation_correlation
        vm_instance_id           # host-stamped
        lane_id / proc_id
        kcov_generation
        rule_set_id
        program_digest           # cross-check
    candidate_id
    execution_harness_identity   # host-stamped (§11.2)
    barrier_results              # activation / deactivation ACK 여부
    journal_identity
    journal_integrity
    terminal_summary_present
    generation_closure?          # summary의 closure (03-nfs-proxy/05 §21)
    resolver_summary[]
    applied_batches[]
        batch_id
        semantic_signature
        exposure_intent_ref
        delivery_state
        forward_event_ref?

M1Result                         # M1 Judge 출력 (§11.1)
    evidence_manifest_sha256
    judge_profile_id
    m1[]                         # rule별
        rule_id
        intent_id
        status
        reason?
    intent_m1[]                  # §7.1 집계
    hypothesis_m1[]
```

concrete byte snapshot은 `03-nfs-proxy/05`의 batch journal evidence에 두고 MutationEvidence에 복제하지 않는다.

Q2 판정은 M1과 독립적으로 기록한다. 다만 `M1≠APPLIED`일 때 `Q2=NOT_OBSERVED`를
"mutation이 trigger하지 못했다"는 결론이나 취약점이 없다는 음성 증거로 해석하지 않는다.

## 8. Q2 — Crash / Sanitizer Evidence

Stage 2 fuzzing은 `syz-manager`의 ordinary program mutation과 candidate-specific mutation rule을 함께
사용한다. rule set은 Runner가 설치하고 executor가 program generation마다 활성화하므로
(`03-nfs-proxy/01` §16), syzkaller는 program을 변이시키지만 rule 내용은 변이시키지 않는다.

Q2는 sanitizer/crash 신호만 판정하는 oracle이다. 단순 "crash file exists"가 아니라 reviewed
sanitizer/crash oracle로 판정하되, crash site나 stack이 candidate 경로 안에 있는지를 Q2의 조건으로
삼지 않는다. candidate와의 연관은 Stage 1 Q1, rule별 M1과 delivery state, crash report, replay,
human/root-cause review를 묶어 나중에 평가한다. "stack에 candidate symbol이 있음" 같은 deterministic
heuristic은 triage metadata로만 기록하며 oracle verdict가 아니다.

### 8.1 CrashContextWindow

lane의 knfsd state(client, session, open/lock state)는 program 사이에 유지된다. generation G의
mutation이 G+1에서 crash를 일으킬 수 있으므로 crash evidence를 crashing generation 하나로 한정하지
않는다(issue #2).

```text
CrashContextWindow
    Runner가 host 측에 보관하는 lane별 순서 있는 execution history
    entry
        ProgramGenerationExecution identity (host-stamped)
        original lane_id / proc_id
        exact program artifact / digest
        generation의 MutationDelta 참조
        activation / deactivation barrier 결과
    bound
        job policy에 명시하고 evidence에 기록한다
```

- crash evidence는 이 history에 실제로 보존된 entry만 고른다.
- 필요한 선행 program이나 evidence artifact가 없으면 multi-generation mutation attribution은
  `INCONCLUSIVE`다. crashing program만 replay하는 것으로 대신하지 않는다.
- window는 VM instance 경계를 넘지 않는다. VM이 재시작되면 lane state도 새로 만들어진다.
- 구현은 syz-manager `pkg/rpcserver`의 `LastExecuting`(pinned commit 기준 proc별 6개)을 확장한다.
  `Hanged()`가 `ExecRecord.Proc`를 synthetic 값으로 바꾸므로 lane은 별도 host-known 필드로 보존한다.
  ring 크기는 구현 세부이며 계약상 bound는 job policy가 정한다.

```text
CrashEvidence
    candidate identity
    Stage 1 Q1 evidence id
    crashing generation Stage 2 Q1        # fatal report면 unavailable
    CrashContextWindow
    M1(rule_id, CrashContextWindow) vector + delivery state
    intent / hypothesis M1 집계            # §7.1
    rule_set_id
    ExecutionHarnessIdentity                 # §11.2
    sanitizer report
    dmesg / stack trace
    crash signature
    candidate association triage metadata?   # oracle 아님
    ambient control flags                    # target_ambient_observed, ambient_applied[],
                                             # q1_preservation_unverifiable,
                                             # ambient_control_unavailable (§3)
    replay result
```

### 8.2 Q2 판정

이 절은 issue #18 F7에서 고정했다. Q2 Judge는 Controller 측 validation layer에서 실행하고(§11.1), Runner가
봉인한 bundle만 읽는다. 단위는 Stage 2 execution 하나(baseline gate 실행, fuzz VM instance의 실행 구간, replay
실행)다.

```text
Q2Status
    OBSERVED
    NOT_OBSERVED
    INCONCLUSIVE
```

Judge 입력(Runner가 수집하고 봉인한다):

```text
Q2Evidence
    execution_harness_identity       # host-stamped. sanitizer variant config 포함 (§11.2)
    console_log_ref                  # host가 캡처한 guest console
    console_log_completeness         # complete | truncated | missing (host가 기록)
    manager_crash_reports[]          # syz-manager가 만든 report 원문
    vm_termination                   # host-observed: runner_stopped | guest_crashed | lost | unknown
    collection_window                # 수집 시작 / 끝 marker
```

Q2 JudgeProfile은 다음을 정한다. 바꾸면 새 profile version이며, 같은 봉인 bundle에 새 verdict를 만든다.
기존 evidence와 verdict는 고치지 않는다(§11.1).

```text
JudgeProfile(Q2)
    signal_classes[]       # 신호로 세는 report 종류. 예: KASAN, KMSAN, UBSAN, KCSAN, WARNING,
                           # BUG, panic, hang. 각 class에 fatal / nonfatal 표시
    parse_rules            # report를 class로 분류하는 규칙, 잘린 report의 처리
    completeness_rule      # NOT_OBSERVED에 필요한 관측 완료 조건
    termination_rules      # vm_termination 값별 해석
```

판정 순서. 위에서부터 처음 맞는 행을 적용한다.

| 순서 | 조건 | 결과 |
|---|---|---|
| 1 | manifest 검증 실패, correlation 불일치, 내부 모순(§11.1) | `INCONCLUSIVE(invalid_evidence)` |
| 2 | profile의 `signal_classes`로 분류된 report가 하나 이상 있다 | `OBSERVED` |
| 3 | report가 없고 `completeness_rule`을 만족한다. 기본: console log `complete`, `collection_window`가 닫힘, `vm_termination = runner_stopped` | `NOT_OBSERVED` |
| 4 | 그 밖. 예: log `truncated` / `missing`, `vm_termination`이 `lost` / `unknown`, 분류할 수 없는 report, report 없이 `guest_crashed` | `INCONCLUSIVE(reason)` |

```text
Q2Result                         # Q2 Judge 출력
    evidence_manifest_sha256
    judge_profile_id
    status
    reason?
    signals[]
        class
        fatal                    # report class의 성질. VM 종료 여부와 별개다
        report_ref
    vm_termination
    candidate_association?       # triage metadata. 판정에 쓰지 않는다 (§8)
```

- nonfatal report(VM이 계속 실행된 WARNING, 복구된 sanitizer report)도 `OBSERVED`다. VM 종료는 별도 field이며
  신호의 조건이 아니다.
- 유효한 신호는 crash site나 stack에 candidate symbol이 없다는 이유로 거부하지 않는다. candidate 연관은
  `candidate_association` triage와 이후 review가 다룬다.
- 로그 유실, 잘림, 수집 실패를 관측 완료 증거 없이 `NOT_OBSERVED`로 합성하지 않는다.
- `OBSERVED`는 candidate 원인성이나 semantic replay equivalence를 주장하지 않는다. 그 판단은 §3의 표와
  `03-nfs-proxy/05` §29가 한다.

## 9. Reproduction identity

Mutation-driven crash의 재현 단위는 syz program 하나가 아니다.

```text
CrashReproducer
    = CrashContextWindow의 순서 있는 ProgramGenerationExecution 목록
        각 entry의 syz program
        각 entry의 MutationDelta (generation 단위 semantic batch evidence)
    + recorded rule set (rule_set_id, CompiledMutationRule[])
    + ReachabilityHarness identity
    + ExecutionHarnessIdentity (§11.2)
        kernel / syzkaller pin과 build, image, guest command line, proxy build
```

target semantic 경로의 replay는 recorded rule set을 다시 설치하고 program을 순서대로 실행한 뒤
위치별로 semantic batch를 비교한다(`03-nfs-proxy/05`). numeric generation id는 correlation 값이며
replay identity가 아니다. production concrete bytes는 evidence로 보존한다.

legacy NFSPDLT replay는 legacy/manual campaign의 재현 계약으로만 남는다. Agent pipeline은 legacy 경로를
쓰지 않는다(issue #8).

## 10. Agent SDK와 deterministic boundary

Agent SDK는 reasoning runtime으로 사용한다. 이 문서의 "Agent SDK"는 특정 제품이 아니라 그 runtime을 가리킨다.
구체 선택(여러 provider를 쓰는 PydanticAI)과 근거는 `../decisions/2026-10-13-agent-implementation-stack.md`가
기록한다.

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
    judge profile / job policy
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
evidence manifest 검증
Q1/M1/Q2 deterministic judge, replay 비교 (§11.1)
```

isolated Linux/KVM runner는 다음을 소유한다.

```text
prepared syzkaller/kernel environment use
VM/fixture
remote KCOV collection
proxy rule-set installation (proxy session마다)
proxy mutation execution/replay
host-side mutation journal sink (durable ACK, issue #3)
CrashContextWindow execution history (issue #2)
bounded syz-manager fuzz
sanitizer/crash collection
evidence 수집과 봉인 (EvidenceManifest, §11.1)
operational health check (verdict 아님)
Controller와의 task 계약 (task_id당 실행 하나, status, cancel. 09 §8)
```

### 11.1 Judge 위치와 evidence 신뢰 경계

이 절은 issue #11에서 합의했다.

Runner는 evidence를 수집하고 봉인하지만 Q1/M1/Q2 verdict와 replay 비교 verdict(`REPLAY_*`)를 내리지 않는다.
Runner의 health check와 protocol 동작(generation ABORT, lane quarantine 등)은 실행을 멈추거나 격리하는
운영 판단이며, 그 결과는 evidence에 사실로 기록한다. Runner와 Proxy runtime은 `CrashContextWindow`
replay를 실행하고 replay journal을 봉인할 뿐이다(`03-nfs-proxy/05` §27–§29).

```text
EvidenceManifest                 # Runner가 수집 시점에 작성하고 전송 전에 봉인한다
    artifacts[]
        identity
        sha256
        size / type
    host-stamped execution correlation
    collection / sealing metadata
```

Q1/M1/Q2 Judge와 replay comparator는 Controller 측 validation layer에서 실행하는 결정적 함수다.

```text
verdict = Judge(봉인된 evidence bundle, JudgeProfile, plan / rule set)
```

- Controller는 받은 artifact의 SHA-256을 manifest와 대조한 뒤 Judge에 넘긴다.
- Judge는 판정 중 guest에 추가 사실을 묻지 않고 봉인된 bundle만 읽는다.
- verdict record는 `judge_profile_id`, `evidence_manifest_sha256`, 판정에 쓴 plan / rule set identity를
  기록한다. Q1 verdict는 사용한 `RemoteKcovSupportBoundary` 버전도 기록한다(`06` §6.1). execution
  identity와 평가 identity는 §11.2가 정한다.
- verdict record는 불변이다. 새 JudgeProfile로 다시 판정하면 같은 봉인 bundle에 대해 새 verdict를
  만든다. bundle에 필요한 evidence가 모두 있으면 VM을 다시 실행하지 않는다(무효화 규칙은 §11.2).

판정 의미와 실행 정책은 분리한다.

```text
JudgeProfile                     # 버전이 있는 Repository Design Data
    Q1    Q1AdmissibilityProfile: generation integrity, context별 loss 규칙 (`06` §6.1)
    M1    §7 판정 의미, journal / evidence 유효성 규칙
    Q2    signal class, report 분류, 관측 완료 조건, 종료 해석 (§8.2)
    Replay  batch-signature / delivery 비교 의미, schema·runtime 호환 확인, evidence 유효성 규칙,
            refusal 분류(normal non-match / hard refusal / incompatibility), refusal evidence
            완전성, 판정 순서 (`03-nfs-proxy/05` §29, issue #18 F2)

JobPolicy                        # trusted control-plane policy (§4.1)
    baseline 반복 횟수
    fuzz / execution budget
    campaign repair 임계값
    retry / repair budget
```

JobPolicy는 실행 횟수와 경로 전환을 정할 뿐 개별 verdict의 의미를 바꾸지 않는다. JobPolicy identity는
`judge_profile_id`에 넣지 않고 execution/job record에 기록한다. 여러 verdict를 모아 경로를 정하는 결정
(§3 gate, §12 campaign repair)은 사용한 JobPolicy identity와 소비한 verdict를 함께 기록한다. delivery
state(§7.2)는 M1과 분리된 evidence이며 어떤 policy도 M1 판정을 바꾸지 않는다.

**신뢰 규칙.** guest에서 온 evidence는 untrusted data다.

- identity의 기준은 host-stamped 값이다. guest가 보낸 correlation이 host-stamped 값과 다르면 host 값으로
  바꿔 판정을 계속하지 않고 evidence 불일치로 처리한다.
- manifest hash가 맞지 않는 bundle은 invalid evidence다.
- invalid evidence, 내부 불일치(서로 모순인 counter, sequence가 끊긴 journal), correlation 불일치로는 확정
  verdict(REACHED / NOT_REACHED, APPLIED / NOT_APPLIED)를 내리지 않는다. 그 Judge는 `INCONCLUSIVE`와
  reason을 기록한다. Q2는 §8.2의 순서 1에서 같은 규칙을 따른다.
- replay 비교도 같다. 검증에 실패한 bundle로는 비교 verdict를 내지 않는다. `REPLAY_INVALID`는 유효하게
  봉인된 replay에서 비교 전제가 성립하지 않을 때만 쓴다(`03-nfs-proxy/05` §29).
- evidence가 repair 입력으로 Agent에 전달될 때도 data로만 다루며 지시로 해석하지 않는다.

### 11.2 Harness identity와 무효화

이 절은 issue #13에서 합의했다. 네 identity는 서로 다른 질문에 답하며, 하나가 바뀌었다고 다른 것을
무효로 만들지 않는다.

```text
Candidate identity          무엇을 조사하는가
    kernel_commit + location (02 §4)

ExecutionHarnessIdentity    어떤 계측·실행 시스템이 관측을 만들었는가
    harness build           harness binding이 고른다
        kernel     source commit, 계측 series digest,
                   sanitizer variant의 config digest, bzImage / vmlinux digest
        syzkaller  commit, 적용한 series digest, build identity
        image      VM image digest (baked fixture 포함)
        proxy      build id. semantic runtime을 쓰면 schema_id,
                   semantic_runtime_version, build가 생성한 registry digest
    runtime configuration   plan의 runtime_selection(05 §10)과 harness 설정
        guest kernel command line 전체
        route / topology identity

EvaluationIdentity          봉인된 관측을 어떤 결정적 규칙으로 해석했는가
    hcap_revision, RemoteKcovSupportBoundary 버전, judge_profile_id

JobPolicy identity          Controller가 왜, 몇 번 실행했는가 (§11.1)
```

- `execution_harness_id`는 ExecutionHarnessIdentity의 canonical digest다.
- command line은 `koov.*`만이 아니라 전체를 넣는다. `sunrpc.lane_attribution=0`은 lane attribution을 끄고,
  `nfs.localio_enabled`는 실행되는 NFS code path를 바꾸며, KASLR 설정(`nokaslr`)은 runtime PC를 vmlinux
  주소로 읽을 수 있는지를 정한다. lane script digest(`koov.lane_sha256`)도 command line에 들어 있다.
- kernel의 결정적 식별자는 vmlinux digest다. source와 config가 같아도 toolchain이 다르면 PC가 달라진다.
- sanitizer는 JobPolicy가 고르지만(`05` §10) variant마다 config와 vmlinux가 다르므로 고른 variant는
  identity의 일부다. 한 variant에서 세운 Q1은 다른 variant의 Stage 2 입력이 아니다.
- promotion된 semantic scope는 identity가 아니라 HCAP(`hcap_revision`)에 있다(`04` §4). build를 바꾸지 않는
  promotion은 execution identity를 바꾸지 않는다.
- program과 seed(ReachabilityHarness가 기록), rule set(Stage 2 입력), 실행마다 새로 붙는 `vm_instance_id`
  (evidence correlation), 실행 방식과 budget(program을 실행하는 lane 수, procs, syz-execprog / syz-manager)은
  identity가 아니다. 그래서 Stage 1의 단일 lane Q1 실행과 Stage 2의 manager 실행이 같은 identity를 쓴다.
- Runner는 실제로 띄운 artifact와 설정에서 identity를 host-stamped로 기록한다. guest가 보고한 값(lane script
  hash, `lane_attribution` 상태 등)은 cross-check이며, 다르면 §11.1의 evidence 불일치다.

**Harness binding.** intake 직후, Agent task 전에 Controller가 한다.

```text
accepted Candidate
    |
    v
harness binding (Controller)
    |
    +-- candidate.kernel_commit용 검증된 harness build 있음
    |       -> job에 harness build와 같은 repository revision의 hcap_revision을 묶는다
    |       -> Stage 1 (Candidate Analysis부터)
    |
    +-- 없음
            -> HarnessGapIssue(remote_kcov_attribution,
                   remote_kcov.kernel_revision.<commit>)        (07 §2)
            -> blocked_harness_gap
```

- intake는 candidate의 source identity만 검증한다(`02` §3). harness가 없다고 candidate를 거부하지 않는다.
- BASE harness로 다른 commit의 candidate를 대신 실행하지 않는다. 그 build의 PC는 candidate commit의 source와
  대응하지 않는다.
- binding이 Candidate Analysis 앞에 있는 이유는 Candidate Analysis(`03` §8)와 Reachability Planning이 읽는
  HCAP이 특정 harness를 기술하기 때문이다. 묶인 harness가 없으면 읽을 HCAP도 없다.
- 검증된 harness build란 계측 series를 그 commit에 적용해 build와 bootstrap 검증을 통과했고, 같은 repository
  revision의 HCAP(HCAP-03의 boundary 포함)이 그 계측을 기술하는 build다. JobPolicy가 고른 sanitizer variant의
  build를 묶는다.
- harness를 다른 kernel revision으로 옮기는 일(`tools/bump-kernel.py`, `tools/fport-apply.sh`)은 사람이 검토하는
  harness 유지보수이며 candidate마다 자동으로 하지 않는다. 검토 없이 옮긴 계측으로는 Q1을 믿을 수 없다.

**기록 위치.**

```text
ReachabilityPlan        hcap_revision
ReachabilityHarness     ExecutionHarnessIdentity (materialize 대상, manifest 포함)
ReachabilityEvidence    ExecutionHarnessIdentity (host-stamped)
MutationEvidence        ExecutionHarnessIdentity (host-stamped)
verdict                 evidence_manifest_sha256, 판정에 쓴 EvaluationIdentity
job / execution record  JobPolicy identity
```

plan은 build identity를 pin하지 않는다. target의 build별 PC mapping은 Q1 Judge가 evidence의 identity로
한다(`06` §5). 그래서 같은 plan을 다른 execution identity에서 다시 쓸 수 있다.

**무효화.**

```text
ExecutionHarnessIdentity 변경
    -> 이전 Q1은 새 identity의 Stage 2 입력 자격이 없다
    -> Controller가 저장된 plan을 새 hcap_revision으로 다시 검증한다
           통과: plan 재사용        실패: Reachability Planning repair
    -> 새 identity로 harness를 다시 materialize하고 Stage 1을 다시 실행한다

EvaluationIdentity만 변경
    hcap_revision
        -> plan과 evidence를 새 HCAP으로 결정적으로 다시 검증한다
    JudgeProfile / RemoteKcovSupportBoundary 버전
        -> 봉인 bundle에 새 규칙이 요구하는 evidence가 모두 있으면 새 verdict만 만든다
        -> 없으면 다시 실행한다

JobPolicy 변경
    -> 이후 scheduling / routing에만 영향. 기존 verdict를 다시 쓰지 않는다
```

- boundary 버전을 바꿔 다시 판정할 때도 boundary는 evidence의 kernel 계측과 맞아야 한다(`06` §6.1).
- 같은 execution position을 주장하는 evidence를 서로 다른 ExecutionHarnessIdentity 사이에서 합치지 않는다.
  Stage2Campaign은 identity가 같으면 VM 교체를 넘어 이어진다(§3, issue #2). 실행마다 host-stamped
  `vm_instance_id`가 남고, `CrashContextWindow`는 VM instance를 넘지 않는다(§8.1).
- identity가 바뀌면 새 identity에서 Stage 1 evidence lineage를 다시 세운 뒤 Stage 2로 간다.

## 12. Repair boundaries

실패 원인에 따라 돌아갈 단계가 다르다.

```text
Q1 not reached
    -> ReachabilityPlan repair (Agent가 program을 고친다)

Harness Materializer 거부 (typed reason)
    -> Reachability Planning repair

Q1 INCONCLUSIVE(unsupported_attribution)
    -> HarnessGapSignal
    -> HarnessGapIssue(remote_kcov_attribution)

harness binding 실패 (kernel_commit용 검증된 harness build 없음, §11.2)
    -> HarnessGapIssue(remote_kcov_attribution)
    -> blocked_harness_gap

Reachability Planning unsupported
    -> HarnessGapIssue
    -> blocked_harness_gap
    -> Harness Extension Work
    -> capability spec update
    -> Stage 1 retry

Stage 2 baseline-with-rules gate (§3)
    Q1 NOT_REACHED
        -> target mode / rule / runtime 도달성 퇴행 진단
    Q1 INCONCLUSIVE, 또는 Q1 REACHED이고 평가한 rule 중 M1 INCONCLUSIVE가 있음
        -> runtime / evidence path repair
        -> gate 재실행 (그 전에는 fuzz campaign을 시작하지 않는다)
    targets_baseline_traffic=true인 intent가 NOT_APPLIED
        -> MutationRuleSet / rule compiler repair

Stage 2 fuzz campaign (campaign 단위 evidence, 임계값은 policy)
    도달한 generation에서 hypothesis가 계속 NOT_APPLIED (§7.1)
        -> MutationRuleSet / rule compiler repair
    도달한 generation에서 APPLIED, Q2 미관측
        -> mutation strategy/search-space refinement
           취약점이 없다는 결론은 내리지 않는다

Q2 observed
    CrashContextWindow에서 APPLIED인 rule이 있음
        -> stop autonomous mutation repair
           freeze evidence
               (CrashContextWindow, rule별 M1 vector, delivery state)
           replay
           final human review
    APPLIED인 rule이 없음
        -> crash evidence 보존, 별도 triage
           hypothesis 단위 결론은 §7.1의 window 집계로 내린다
```

gap으로 막힌 job의 상태 전이(`retry_pending`, `parked`, `closed_unsupported`)는 `07` §7이 정한다(issue #13).
위 경로를 job 상태, 전이, repair budget, 재시작 규칙으로 옮긴 상태 기계는 [`09-job-state-graph.md`](09-job-state-graph.md)가
소유한다. 경로의 의미는 이 절과 각 계약 문서가 소유한다.

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
§11.2의 무효화 규칙에 따라 blocked candidate를 재시도한다.

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
10. `MutationEvidence` / M1 judge — 판정 계약은 §7(issue #4), judge 실행 위치와 evidence 신뢰 경계는
    §11.1(issue #11)에 고정
11. `CrashEvidence` / Q2 judge — Q2 경계와 `CrashContextWindow`는 §8(issue #2, #4), judge 실행 위치는
    §11.1(issue #11), 입력·상태·판정 순서·`Q2Result`는 §8.2(issue #18 F7)에 고정. 첫 `JudgeProfile(Q2)`의
    `signal_classes`와 `parse_rules` 내용은 Q2 Judge 구현에서 정한다. Q2 Judge 통합은 Proxy milestone과 별개의
    acceptance gate를 가진다. Proxy replay 완료가 이 gate를 대신하지 않는다.
    - stack에 candidate symbol이 없는 유효한 sanitizer report fixture가 `OBSERVED`다.
    - nonfatal report fixture가 VM 종료 없이 `OBSERVED`다.
    - log를 자르거나 지운 bundle은 `NOT_OBSERVED`가 아니라 `INCONCLUSIVE`다.
    - complete log, 닫힌 collection window, `runner_stopped`이고 report가 없을 때만 `NOT_OBSERVED`다.
    - profile을 바꾼 재판정은 기존 verdict를 고치지 않고 새 verdict를 만든다.
12. [`repair/state graph`](09-job-state-graph.md) — draft (2026-10-13). job 상태, 전이, budget, 재시작 규칙
13. Agent SDK concrete selection and agent/tool definitions — 선택은
    [`decisions/2026-10-13-agent-implementation-stack.md`](../decisions/2026-10-13-agent-implementation-stack.md)에
    기록했다(PydanticAI). agent/tool definitions는 첫 Stage 1 구현에서 정한다
14. Runner task 실행 — Controller task 계약([`09`](09-job-state-graph.md) §8)의 Runner 쪽 구현. task·cancel 기록의
    durable 저장, Runner 재시작 뒤 실행 복원, campaign evidence의 봉인 단위
