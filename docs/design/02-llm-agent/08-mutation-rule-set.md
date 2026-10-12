# MutationRuleSet Contract

> 상태: current detailed design
> 상위 설계: `01-two-stage-agent-architecture.md`
> 입력: Q1이 `REACHED`인 Stage 1 package
> 목적: Stage 2에서 어떤 NFS/RPC record를 어떤 의미로 변조할지 Agent와 Mutation Engine 사이의 계약을 정의한다.

## 1. 이 요소는 무엇인가

```text
Mutation Strategy
    Type:        AGENT TASK
    Executed by: Agent SDK
    Output:      MutationRuleSet

MutationRuleSet
    Type:        DATA
    Written by:  Mutation Strategy
    Read by:     Mutation Rule Compiler
```

`Mutation Strategy`는 reasoning 작업이고,
`MutationRuleSet`은 그 reasoning 결과를 담은 구조화 데이터다.

## 2. Stage 2 안에서의 위치

```text
Q1Result(REACHED)
        |
        v
========================================
STAGE 2 — MUTATION / CRASH TRIGGER
========================================
        |
        v
[AGENT TASK] Mutation Strategy
        |
        v
[DATA] MutationRuleSet
        |
        v
[COMPONENT] Mutation Rule Compiler
        |
        v
[DATA] CompiledMutationRule
        |
        v
[RUNNER TASK] baseline-with-rules gate (§16), then proxy + syz-manager fuzz
        |
        v
MutationEvidence / CrashEvidence
```

Stage 2는 Q1이 증명된 Stage 1 scenario를 baseline으로 사용한다.

## 3. Mutation Strategy가 읽는 것

```text
VulnerabilityCandidate
CandidateAnalysis
ReachabilityPlan
ReachabilityHarness
ReachabilityEvidence
Q1Result(REACHED)
Harness Capability Specification
candidate.kernel_commit의 Linux source
```

Q1은 target이 실행됐다는 사실만 증명한다.
특정 syscall/RPC가 target의 직접 원인이었다거나 어떤 field가 취약 상태를 만든다는 것은 증명하지 않는다.

따라서 Mutation Strategy는 kernel source와 Stage 1 path/state를 다시 해석해
mutation 대상 message/field/state를 선택한다.

## 4. Mutation Strategy의 질문

```text
1. target code에서 어떤 값/state가 취약 조건이 될 수 있는가?

2. 그 값/state에 영향을 줄 수 있는 NFS/RPC traffic은 무엇인가?

3. request(C2S)인가 response(S2C)인가?

4. Stage 1 scenario의 어떤 connection/operation/message를 대상으로 해야 하는가?

5. 어떤 semantic change가 그 조건을 만들 수 있는가?

6. 현재 Harness Capability Specification으로 그 semantic change를 표현·실행할 수 있는가?
```

## 5. MutationRuleSet 최소 구조

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

다음은 넣지 않는다.

```text
raw host command
raw NFSPARM packet
anchor byte offset
literal anchor bytes
patch/edit byte offset
recorded original bytes
artifact hash
retry budget
fuzz duration
```

semantic rule validation/normalization은 Mutation Rule Compiler의 책임이다.
live target byte offset과 current original bytes는 Proxy runtime resolver의 책임이다.
retry/fuzz budget은 Controller의 JobPolicy 책임이다.

## 6. direction

```text
C2S
S2C
```

예:

```text
C2S
    client request를 서버에 도달하기 전에 변경

S2C
    server response를 client가 처리하기 전에 변경
```

## 7. traffic_scope

Stage 1 scenario에 이미 존재하는 traffic route 중 어떤 것을 변조할지 지정한다.

```text
traffic_scope
    backend
    client
```

이 값은 새로운 topology를 만드는 지시가 아니다.
ReachabilityHarness가 이미 사용하는 backend/client route를 참조한다.

Mutation Rule Compiler는 이를 `CompiledMutationRule.traffic_scope`의 canonical
`backend` / `client` 값으로 bind한다. Current proxy ABI mapping은 구현 adapter 책임이다.

## 8. record_match

어떤 RPC/NFS record가 mutation 대상인지 semantic predicate로 표현한다.

```text
record_match
    operation?
    conditions[]
```

예:

```text
operation: NFS4_OP_OPEN

conditions:
    stateid belongs to the selected open state
    response status is NFS4_OK
```

`conditions`는 Agent가 의도하는 의미를 표현한다.
Compiler는 target Proxy schema가 이 selector를 표현할 수 있는지 검증하고 정규화한다.
실제 live record matching과 field resolution은 Proxy Semantic Rule Resolver가 수행한다.

ordinal identity는 사용하지 않는다.

```text
금지:
    3번째 OPEN
    N번째 matching reply
    프로그램 실행 후 두 번째 RPC
```

proxy rule은 content-addressed predicate와 apply-to-all semantics를 유지한다.

## 9. edit

```text
edit
    kind
    target
    value?
    structure_mode?
```

`kind`은 현재 Mutation Engine capability에 맞춘다.

```text
replace
insert
delete
op_append
op_prepend
```

### target

무엇을 바꿀지 semantic하게 지정한다.

예:

```text
OPEN argument field
stateid field
NFS status
XDR length field
COMPOUND operation array
```

Agent가 original-message byte offset을 직접 지정하지 않는다.

### value

원하는 의미상의 새 값 또는 삽입할 operation을 표현한다.

예:

```text
status = NFS4ERR_*
length = <semantic value>
stateid = <chosen malformed/stale semantic value>
append operation = GETATTR(...)
```

Compiler는 semantic value/transform을 검증·정규화한다.
Live target field의 concrete XDR bytes와 current value는 Proxy가 runtime에 resolve한다.

### structure_mode

`op_append` / `op_prepend`에서 구조 보존 여부 자체가 mutation 의미일 때만 사용한다.

```text
preserve
raw
```

`preserve`는 COMPOUND op count를 함께 맞춘다.
`raw`는 op count와 실제 op array의 의도적인 불일치를 허용한다.

## 10. expected_effect

Agent가 이 mutation을 선택한 이유를 짧게 구조화한다.

```text
expected_effect
    target_state
    rationale
```

예:

```text
target_state:
    stale stateid reaches candidate validation path

rationale:
    candidate dereferences state derived from the reply before ...
```

이는 Q2 verdict가 아니다.
Agent의 trigger hypothesis다.

## 11. constraints

mutation이 의미를 유지하기 위해 반드시 지켜야 하는 조건만 담는다.

예:

```text
keep RPC record framing valid
preserve XID
do not change operation ordering before OPEN
mutation must apply to S2C only
```

CPU/RAM/time/retry budget은 여기에 넣지 않는다.

## 12. Mutation Rule Compiler / Proxy 경계

Agent의 semantic intent는 바로 proxy byte rule이 아니다.

```text
MutationRuleSet
        |
        v
[COMPONENT] Mutation Rule Compiler
        |
        +-- semantic validation
        +-- traffic scope binding
        +-- schema target validation
        +-- rule normalization
        +-- capability validation
        |
        v
[DATA] CompiledMutationRule
        |
        v
[COMPONENT] Proxy Semantic Rule Resolver
        |
        +-- decode live RPC/NFS record
        +-- match semantic selector
        +-- resolve live field span/current value
        +-- build concrete edit
        |
        v
[DATA] ResolvedMutation
```

Compiler는 live field offset, current original bytes, runtime XID 또는 Nth-message identity를
계산하지 않는다. 이 값들은 Proxy가 실제 live record를 해석하면서 runtime에 resolve한다.

상세 Proxy runtime 계약은
[`../03-nfs-proxy/04-semantic-mutation-runtime.md`](../03-nfs-proxy/04-semantic-mutation-runtime.md)에
정의한다. 전체 Proxy 경계는
[`../03-nfs-proxy/01-architecture.md`](../03-nfs-proxy/01-architecture.md)가 소유한다.

## 13. wire record capture의 위치

Raw wire capture는 Compiler의 mandatory input이 아니다.

```text
normal path:
    CompiledMutationRule
        + live RPC record
        -> Proxy runtime semantic resolution

optional:
    WireCapture
        -> decoder/schema validation
        -> debugging / evidence
```

Kernel-generated C2S request나 S2C response의 dynamic state는 baseline bytes를 다음 run에
재사용하는 대신 live semantic field에서 resolve한다.

## 14. 현재 구현 capability와 target architecture

현재 Harness Capability Specification에는 concrete Layer 0 기능이 등록돼 있다.

```text
HCAP-07 -> NFSPARM1 fixed-width mutation
HCAP-08 -> NFSPARM2 variable-length mutation
HCAP-09 -> current delta replay
```

이 capability들은 target semantic Proxy architecture와 동일한 뜻이 아니다.
Semantic decoder/resolver가 구현·검증되기 전에는 Agent가 현재 HCAP 지원 범위를 넘어선
semantic mutation을 실행 가능하다고 가정하지 않는다.

HCAP-08은 partially validated 상태이므로 미검증 조합은 그대로 미검증으로 남긴다.

## 15. 표현할 수 없는 mutation

다음 경우 Agent가 raw workaround를 만들지 않는다.

```text
semantic target schema/decoder가 없음
semantic selector를 stable하게 표현할 수 없음
required live-value transform을 Proxy가 지원하지 않음
resolved concrete edit를 Mutation Engine이 표현할 수 없음
reproduction delta를 요구된 의미로 기록할 수 없음
```

결과:

```text
unsupported_by_current_harness
        |
        v
HarnessGapIssue
    stage: stage2_mutation
    gap_class: mutation_engine
```

Harness Extension Work가 해결된 뒤 Stage 2를 다시 실행한다.

## 16. Q1 baseline 보존

MutationRuleSet에 `preserve_q1=true` 같은 필드는 넣지 않는다.
이는 데이터 선택사항이 아니라 Stage 2 전체 invariant다.

Q1 보존을 fuzz program마다 확인하지 않는다. fuzz program 대부분이 candidate에 도달하지 않는 것은
정상이다. 대신 fuzz campaign 전에 baseline-with-rules gate를 실행한다(`01` §3, issue #4).

```text
baseline-with-rules gate
    Stage 1 ReachabilityHarness program
        + 설치된 rule set
        + target mode activation
    |
    +-- Q1이 여전히 REACHED인가?     (gate pass/fail)
    +-- rule별 M1은 무엇인가?         (routing 입력)
```

반복 횟수는 job policy가 정한다. gate의 Q1이 `NOT_REACHED`이면 gate 실패로 기록하고 target mode,
rule, runtime 중 어디서 도달성이 퇴행했는지 진단한다. rule이 도달성을 깨뜨렸다고 바로 단정하지
않는다. `NOT_REACHED`가 건전한 음성이 되는 조건은 issue #9에서 정한다.

gate의 Q1이 `REACHED`여도 gate가 평가한 rule 중 하나라도 M1이 `INCONCLUSIVE`이면 runtime/evidence
path를 고친 뒤 gate를 다시 실행한다. mutation evidence 경로가 확정되기 전에는 fuzz campaign을 시작하지
않는다.

baseline traffic을 대상으로 한다고 표시한 intent의 rule이 gate에서 `NOT_APPLIED`이면 fuzz budget을
쓰기 전에 rule/strategy repair로 보낸다. 이 표시는 issue #5의 typed vocabulary에서 정한다.

fuzz campaign 동안 개별 generation의 Q1 miss는 정상 data다. repair/search routing은 campaign 단위
evidence로 판단하며 임계값은 policy가 소유한다. fatal crash generation은 remote coverage를 publish하지
못하므로 그 Stage 2 Q1은 `unavailable`로 기록한다.

Stage 2 runtime evidence는 Q1, M1, Q2를 계속 분리해서 보존한다.

## 17. 이 작업에서 하지 않는 것

```text
NFSPARM packet serialization
raw byte offset 계산
original bytes 추측
proxy rule registration
mutation 적용 판정(M1)
fuzz execution
crash 판정(Q2)
vulnerability fix patch
```

이 경계를 유지하면 Agent reasoning 실패, compiler 실패, proxy application 실패, crash non-trigger를
각각 다른 문제로 분리할 수 있다.
