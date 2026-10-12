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

ProgramGenerationExecution
    한 lane에서 remote-KCOV generation 하나로 실행한 syz program 하나.
    M1 evidence와 ReplayResult 비교의 단위다.
```

fatal sanitizer report로 VM이 죽은 generation은 FINISH 전에 끝나 remote coverage를 publish하지 못한다
(syzkaller 0001은 generation coverage를 FINISH 성공 전까지 격리한다). 그 generation의 Stage 2 Q1은
`unavailable`로 기록하며 crash 해석의 조건으로 요구하지 않는다.

해석은 다음 세 표를 따른다(issue #4).

**baseline-with-rules gate.** fuzz campaign 전에 Stage 1 시나리오를 rule set을 설치한 상태로 실행한다.
반복 횟수는 job policy가 정한다.

| Q1 (target mode/rules) | rule별 M1 | 경로 |
|---|---|---|
| NOT_REACHED | any | gate 실패. target mode, rule, runtime 중 어디서 도달성이 퇴행했는지 진단한다. NOT_REACHED는 `06` §9의 조건을 만족할 때만 나온다(issue #9) |
| INCONCLUSIVE | any | runtime/evidence repair 후 gate 재실행. reason이 `unsupported_attribution`이면 `06` §13의 gap 경로 |
| REACHED | gate가 평가한 rule 중 하나라도 INCONCLUSIVE | runtime/evidence repair 후 gate 재실행. mutation evidence 경로가 확정되기 전에는 fuzz campaign을 시작하지 않는다 |
| REACHED | baseline traffic 대상으로 표시한 intent의 rule이 NOT_APPLIED (표시는 issue #5) | fuzzing 전에 rule/strategy repair |
| REACHED | 그 밖 | fuzz campaign 시작 |

표는 위에서부터 처음 맞는 행을 적용한다.

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

CrashEvidence는 rule별 vector 전체를 보존한다. rule set 전체에 대한 "target mutation 없는 crash" 결론은
issue #5의 typed hypothesis/group semantics가 정해지거나 rule별 검토를 거친 뒤에만 내린다.

`Q2=no`는 `M1=NOT_APPLIED`와 절대 같은 결과로 취급하지 않는다. `M1=APPLIED`이고 `Q2=no`여도
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
plan의 `expected_context`와 `RemoteKcovSupportBoundary`는 target이 관측되지 않았을 때 `NOT_REACHED`를
내릴 수 있는지만 정한다(`06` §8–§10, issue #9).

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

따라서 Stage 2 repair가 Stage 1의 도달성을 우연히 깨뜨리는 것을 검출할 수 있어야 한다.
이 검출은 fuzz campaign 전에 실행하는 baseline-with-rules gate(§3)가 맡는다.

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
| `NOT_APPLIED` | activation과 deactivation barrier가 모두 ACK됐고, clean durable `GENERATION_COMPLETE`가 있으며, 그 rule의 `EXPOSURE_INTENT`가 없다 |
| `INCONCLUSIVE` | 그 밖의 모든 경우. crash 뒤 summary가 없는 경우와 barrier 실패를 포함한다 |

crash 뒤 `EXPOSURE_INTENT`가 없다는 사실만으로 `NOT_APPLIED`를 추론하지 않는다.
여러 rule을 묶는 group 판정은 issue #5의 typed vocabulary가 정해진 뒤 추가한다.

`APPLIED`는 그 generation에서 matching record가 변조됐다는 뜻이다. 그 record가 시나리오가 만든
traffic인지 ambient traffic인지는 구분하지 않는다(issue #10).

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

normal non-match를 하나씩 durable하게 기록하지 않는다. generation마다 terminal summary를 남긴다
(`03-nfs-proxy/05` §21).

```text
GENERATION_COMPLETE
    program_generation_correlation   # §7.4, issue #2
    rule_set_id
    records_seen
    exposure_batch_count
    outside_activation_window
    evidence_path_failures
    resolver_summary[]           # rule_id별 03-nfs-proxy/04 §31 taxonomy count
```

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
    barrier_results              # activation / deactivation ACK 여부
    journal_identity
    journal_integrity
    terminal_summary_present
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
    m1[]
        rule_id
        status
        reason?
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
    rule_set_id
    kernel/syzkaller/image identities
    sanitizer report
    dmesg / stack trace
    crash signature
    candidate association triage metadata?   # oracle 아님
    replay result
```

## 9. Reproduction identity

Mutation-driven crash의 재현 단위는 syz program 하나가 아니다.

```text
CrashReproducer
    = CrashContextWindow의 순서 있는 ProgramGenerationExecution 목록
        각 entry의 syz program
        각 entry의 MutationDelta (generation 단위 semantic batch evidence)
    + recorded rule set (rule_set_id, CompiledMutationRule[])
    + ReachabilityHarness identity
    + kernel/syzkaller source pins
    + fixture/image identity
```

target semantic 경로의 replay는 recorded rule set을 다시 설치하고 program을 순서대로 실행한 뒤
위치별로 semantic batch를 비교한다(`03-nfs-proxy/05`). numeric generation id는 correlation 값이며
replay identity가 아니다. production concrete bytes는 evidence로 보존한다.

legacy NFSPARM/NFSPDLT 경로의 재현 단위와 migration 중 사용 여부는 issue #8에서 정한다.

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
Q1/M1/Q2 deterministic judge (§11.1)
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
```

### 11.1 Judge 위치와 evidence 신뢰 경계

이 절은 issue #11에서 합의했다.

Runner는 evidence를 수집하고 봉인하지만 Q1/M1/Q2 verdict를 내리지 않는다. Runner의 health check와
protocol 동작(generation ABORT, lane quarantine 등)은 실행을 멈추거나 격리하는 운영 판단이며, 그 결과는
evidence에 사실로 기록한다.

```text
EvidenceManifest                 # Runner가 수집 시점에 작성하고 전송 전에 봉인한다
    artifacts[]
        identity
        sha256
        size / type
    host-stamped execution correlation
    collection / sealing metadata
```

Q1/M1/Q2 Judge는 Controller 측 validation layer에서 실행하는 결정적 함수다.

```text
verdict = Judge(봉인된 evidence bundle, JudgeProfile, plan / rule set)
```

- Controller는 받은 artifact의 SHA-256을 manifest와 대조한 뒤 Judge에 넘긴다.
- Judge는 판정 중 guest에 추가 사실을 묻지 않고 봉인된 bundle만 읽는다.
- verdict record는 `judge_profile_id`, `evidence_manifest_sha256`, 판정에 쓴 plan / rule set identity를
  기록한다. Q1 verdict는 사용한 `RemoteKcovSupportBoundary` 버전도 기록한다(`06` §6.1). plan과
  execution identity 체계는 issue #13에서 정한다.
- verdict record는 불변이다. 새 JudgeProfile로 다시 판정하면 같은 봉인 bundle에 대해 새 verdict를
  만든다. bundle에 필요한 evidence가 모두 있으면 VM을 다시 실행하지 않는다(무효화 규칙은 issue #13).

판정 의미와 실행 정책은 분리한다.

```text
JudgeProfile                     # 버전이 있는 Repository Design Data
    Q1    Q1AdmissibilityProfile: generation integrity, context별 loss 규칙 (`06` §6.1)
    M1    §7 판정 의미, journal / evidence 유효성 규칙
    Q2    sanitizer / crash report 분류 규칙

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
  reason을 기록한다. Q2 상태 집합은 Q2 judge 세부에서 정하되 같은 규칙을 따른다.
- evidence가 repair 입력으로 Agent에 전달될 때도 data로만 다루며 지시로 해석하지 않는다.

## 12. Repair boundaries

실패 원인에 따라 돌아갈 단계가 다르다.

```text
Q1 not reached
    -> ReachabilityPlan / harness repair

Q1 INCONCLUSIVE(unsupported_attribution)
    -> HarnessGapSignal
    -> HarnessGapIssue(remote_kcov_attribution)

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
    baseline traffic 대상 rule이 NOT_APPLIED
        -> MutationRuleSet / rule compiler repair

Stage 2 fuzz campaign (campaign 단위 evidence, 임계값은 policy)
    도달한 generation에서 hypothesis rule이 계속 NOT_APPLIED
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
           rule set 전체 결론은 issue #5 또는 rule별 검토 뒤에만 내린다
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
10. `MutationEvidence` / M1 judge — 판정 계약은 §7(issue #4), judge 실행 위치와 evidence 신뢰 경계는
    §11.1(issue #11)에 고정
11. `CrashEvidence` / Q2 judge — Q2 경계와 `CrashContextWindow`는 §8(issue #2, #4), judge 실행 위치는
    §11.1(issue #11)에 고정. Q2 분류 규칙(`JudgeProfile` Q2)은 미정
12. repair/state graph
13. Agent SDK concrete selection and agent/tool definitions
