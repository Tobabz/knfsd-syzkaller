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

Stage 2는 Q1이 증명된 Stage 1 scenario를 baseline으로 사용한다. target이 ambient control에서도
관측되면 이 baseline은 scenario 경로의 보존을 증명하지 못한다(`01` §3, issue #10).

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

Agent는 runtime의 typed vocabulary로 intent를 쓴다. Mutation Rule Compiler는 이를 검증·bind·lower할 뿐
prose에서 의미를 추론하지 않는다(issue #5).

```text
MutationRuleSet
    candidate_id
    intents[]                        # MutationIntent
    hypotheses[]
        hypothesis_id
        intents[]                    # member intent_id
        requirement: all
    uncertainties[]

MutationIntent
    intent_id                        # rule set 안에서 유일
    traffic_scope                    # §6–§7
        direction
        backend
        client
    selector                         # §8
        rpc {message_type, program, version, procedure?}
        protocol {family, nfs_version?, minor_version?}
        operation?
        target {kind, path, part?}
        predicates[] {lhs: ValueRef, op, rhs: TypedLiteral | ValueRef}
    mutation                         # §9
        kind
        transform?
        structure_policy
    targets_baseline_traffic         # bool. 필수이며 기본값이 없다 (§16)
    expected_effect                  # §10. 실행하지 않는 설명
        target_state
        rationale
```

실행되는 필드의 의미는 `../03-nfs-proxy/04-semantic-mutation-runtime.md` §2–§17이 소유한다. prose는
`expected_effect`와 `uncertainties`에만 둔다.

hypothesis는 함께 적용돼야 trigger 가설이 되는 intent 묶음이다. 어느 hypothesis에도 속하지 않은 intent는
보조 intent다. M1 집계는 `01` §7.1이 정한다.

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

## 6. direction과 message_type

`traffic_scope.direction`은 record가 흐르는 방향이다.

```text
C2S
    client에서 server로 가는 record를 변경

S2C
    server에서 client로 가는 record를 변경
```

`selector.rpc.message_type`(`call` | `reply`)은 direction과 독립이며 Agent가 명시한다. backchannel에는
S2C CALL과 C2S REPLY가 있으므로 Compiler는 message_type을 direction에서 추론하지 않는다
(`../03-nfs-proxy/04-semantic-mutation-runtime.md` §3–§4).

## 7. traffic_scope

Stage 1 scenario에 이미 존재하는 traffic route 중 어떤 것을 변조할지 지정한다.

```text
traffic_scope
    direction
    backend
    client
```

이 값은 새로운 topology를 만드는 지시가 아니다.
ReachabilityHarness가 이미 사용하는 backend/client route를 참조한다.

Mutation Rule Compiler는 이를 `CompiledMutationRule.traffic_scope`의 canonical
`backend` / `client` 값으로 bind한다. Current proxy ABI mapping은 구현 adapter 책임이다.

## 8. selector

어떤 RPC/NFS record와 그 안의 어떤 대상을 변조할지 typed selector로 지정한다. 필드 의미는
`../03-nfs-proxy/04-semantic-mutation-runtime.md` §4–§9가 소유한다.

예:

```text
selector
    rpc
        message_type: reply
        program: 100003
        version: 4
    protocol
        family: nfs4
        minor_version: 1
    operation: OPEN
    target
        kind: field
        path: nfs4.response.OPEN.result.ok.stateid
        part: value
    predicates[]
        lhs: {source: current_message, path: nfs4.response.OPEN.result.status}
        op:  eq
        rhs: NFS4_OK

        lhs: {source: request_forwarded, path: nfs4.request.OPEN.args.claim.null.filename}
        op:  eq
        rhs: "scenario-file"
```

operation과 path는 ProtocolSchema annotation 이름을 쓴다(`../03-nfs-proxy/02-semantic-decoder.md` §9).
`NFS4_OP_OPEN` 같은 구현 상수나 annotation에 없는 alias는 쓰지 않는다. predicate는 typed 비교의 AND다.
같은 RPC transaction 밖의 값을 기억해야 하는 조건(예: "file X를 연 OPEN의 stateid를 쓰는 WRITE")은
초기 runtime에서 표현할 수 없다(§15, issue #6).

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

## 9. mutation

```text
mutation
    kind               # replace | insert | delete | op_append | op_prepend
    transform?         # literal | copy | builtin
    structure_policy   # preserve | raw. 모든 kind에서 필수
```

`kind`은 현재 Mutation Engine capability에 맞춘다.

무엇을 바꿀지는 `selector.target`(§8)이 지정한다. Agent가 original-message byte offset을 직접 지정하지 않는다.

### transform

새 값은 typed transform으로 표현한다(`../03-nfs-proxy/04-semantic-mutation-runtime.md` §12–§16).

```text
literal    value: TypedLiteral          예: status = NFS4ERR_BAD_STATEID
copy       source: ValueRef             예: 같은 message의 다른 field 값
builtin    transform_id, args[]         예: stateid.other에 integer_xor

op_append / op_prepend의 value는 typed operation object다. 예: GETATTR(...)
```

현재 field에 대한 transform은 위조·변형 값을 만든다. 이전 transaction에서 받은 값을 다시 쓰는 stale
값(예: CLOSE 전에 받은 stateid)은 state lineage가 필요하며 초기 runtime 범위 밖이다(§15, issue #6).

Compiler는 semantic value/transform을 검증·정규화한다.
Live target field의 concrete XDR bytes와 current value는 Proxy가 runtime에 resolve한다.

### structure_policy

```text
preserve
raw
```

`preserve`는 mutation 대상 container의 XDR structure를 유지한다. length, count, COMPOUND op count, padding을
live state에서 다시 계산한다. `raw`는 요청한 edit 외의 structural metadata를 보정하지 않는다. 예를 들어
op count와 실제 op array의 의도적인 불일치를 허용한다.

구조 보존 여부는 mutation 의미의 일부이므로 기본값을 두지 않고 모든 kind에서 명시한다.

## 10. expected_effect

Agent가 이 mutation을 선택한 이유를 짧게 구조화한다. 이 필드는 실행하지 않는다.

```text
expected_effect
    target_state
    rationale
```

예:

```text
target_state:
    forged stateid reaches candidate validation path

rationale:
    candidate dereferences state derived from the reply before ...
```

이는 Q2 verdict가 아니다.
Agent의 trigger hypothesis다.

## 11. constraints를 두지 않는다

`constraints[]`는 실행 필드로 두지 않는다(issue #5). 실행에 영향을 주는 조건은 typed field로 표현한다.

```text
keep RPC record framing valid                 -> structure_policy (outer framing은 raw에서도 재생성)
mutation must apply to S2C only               -> traffic_scope.direction
do not change operation ordering before OPEN  -> mutation kind / target 선택
```

typed field로 표현할 수 없는 조건은 `expected_effect.rationale`에 설명으로 남긴다. 실행에 꼭 필요한데 표현할
수 없으면 Compiler가 typed reason으로 거부한다(§12).

CPU/RAM/time/retry budget은 여기에 넣지 않는다. RPC envelope(xid, cred/verf, prog/vers/proc)는 target
runtime의 mutation 대상이 아니므로 그 보존을 조건으로 적지 않는다(issue #7).

## 12. Mutation Rule Compiler / Proxy 경계

Agent의 semantic intent는 바로 proxy byte rule이 아니다.

```text
MutationRuleSet
        |
        v
[COMPONENT] Mutation Rule Compiler
        |
        +-- ProtocolSchema(schema_id)로 name / path / type 검증
        +-- promoted semantic registry scope 확인 (04 §4)
        +-- traffic scope binding
        +-- context_dependencies 도출
        +-- typed value bind / 정규화
        +-- 지원되는 alternative의 결정적 lowering
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

Compiler는 결정적 component이며 prose에서 빠진 의미를 추론하지 않는다. intent 하나는 rule 하나 이상으로
낮아지고, 각 rule은 Compiler가 정한 `rule_id`와 부모 `intent_id`를 가진다
(`../03-nfs-proxy/04-semantic-mutation-runtime.md` §2). alternative의 순서와 이름은 결정적이며 packet
ordinal을 쓰지 않는다.

거부는 typed reason으로 돌려주고 원인에 따라 경로를 나눈다.

```text
Agent가 고칠 수 있는 입력
    unknown_path, type_mismatch, message_type_inconsistent,
    selector_mismatch (예: NFSv3 READ rule이 WRITE argument를 읽음.
                       NFSv4 operation은 모두 COMPOUND 안이라 이 예에 해당하지 않음),
    missing_required_field (예: targets_baseline_traffic)
        -> Mutation Strategy repair

schema상 유효하지만 runtime이 지원하지 않는 기능
    unsupported_capability, requires_state_lineage
        -> HarnessGapIssue(gap_class=mutation_engine)
        -> Harness Generation (07 §5) -> 저장된 rule set 다시 compile
```

Compiler는 live field offset, current original bytes, runtime XID 또는 Nth-message identity를
계산하지 않는다. 이 값들은 Proxy가 실제 live record를 해석하면서 runtime에 resolve한다.

상세 Proxy runtime 계약은
[`../03-nfs-proxy/04-semantic-mutation-runtime.md`](../03-nfs-proxy/04-semantic-mutation-runtime.md)에
정의한다. 전체 Proxy 경계는
[`../03-nfs-proxy/01-architecture.md`](../03-nfs-proxy/01-architecture.md)가 소유한다.

### 구현

`agent_pipeline/rule_compiler.py`의 `ArtifactMutationRuleCompiler`가 `components.MutationRuleCompiler`를 구현한다.
한 rule set에 대해 다음 순서로 일한다.

1. `binding.hcap_revision`의 promoted semantic registry(HCAP-10)를 읽는다. binding이 Harness Generation의 staged
   revision이어도 같다. 그 revision에 M7 gate를 통과해 pin된 registry가 있으면 쓴다(`04` §4, `07` §5.2). 없으면
   `unsupported_capability`(`semantic_mutation.unpromoted`)다.
2. 받은 Proxy binary가 binding한 revision이 pin한 build와 정확히 같아야 한다(`04` §7.1). 다르거나, schema가 없거나, runtime이
   Compiler가 쓴 형식을 거부하면 `CompilerUnavailable`을 던진다. rule set을 고쳐서 풀리는 문제가 아니다.
3. intent마다 bind한다. `traffic_scope`는 Stage 1 harness가 여는 lane profile(`syz_open_nfs_lane_profile$<client>_<backend>_v<N>`)
   중 하나여야 하고, backend는 `knfsd`=0·`ganesha`=1, client는 `client0`=0·`client1`=1로 낮춘다. ProtocolSchema는
   harness NFS version의 schema다. enum 이름은 비교·기록 대상 node의 enum 안에서 wire word로 바꾼다(같은 word를
   가진 다른 enum 이름은 `type_mismatch`). context dependency는 `../03-nfs-proxy/04` §35대로 유도한다. path 해석은
   `agent_pipeline/protocol_schema.py`가 normalizer 출력으로 `src/schema.c`와 같은 규칙을 따른다.
4. intent마다 낮춘 rule 하나를 `nfs-proxy --check-rules`로 runtime loader에 넣는다. 거부 status는 위 사유로 바꾼다
   (`ambiguous_path` → `unknown_path`, `part_unavailable`·`mutation_invalid` → `type_mismatch`). intent 순서에서
   첫 Agent 수정 가능 거부가 답이고, 없으면 첫 `unsupported_capability`가 답이다.
5. `semantic_promotion.rule_set_scope`로 set 전체가 promoted subset 하나에 맞는지 본다. 안 맞으면
   `unsupported_capability`(`semantic_mutation.unpromoted`)다.
6. set 전체를 한 번 더 loader에 넣고, NFSPRUL1 bytes와 `CompiledMutationRuleSet`(rule별 `rule_id`·`intent_id`,
   subset, build, schema)을 저장한다. `CompiledRuleSet.compiled_ref`가 그 record다.

intent 하나는 rule 하나가 된다(OR가 없어 alternative가 생기지 않는다). `rule_id`는 intent 순서의 `r000`, `r001`, ...이다.
`requires_state_lineage`는 지금 vocabulary에서 생기지 않는다. 이전 transaction을 읽는 ValueRef source가 없기 때문이다.

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

이 capability들은 manual/legacy campaign 전용이며 Agent의 MutationRuleSet이 쓰는 capability가 아니다
(issue #8). Compiler는 intent를 NFSPARM anchor/offset/original bytes로 낮추지 않는다.

Agent가 쓸 수 있는 semantic mutation capability는 M7 promotion gate를 통과한 subset뿐이다
(`../03-nfs-proxy/06-implementation-gap-analysis.md` §30). 그런 subset이 없으면 Stage 2 intent는
`unsupported_by_current_harness`로 처리하고 `HarnessGapIssue(gap_class=mutation_engine)`를 semantic
runtime 구현·검증 작업에 연결한다. 세부 지원 범위의 authority는 promoted semantic capability
registry다(`04-harness-capability-spec.md` §4, issue #14).

HCAP-08은 partially validated 상태이므로 미검증 조합은 그대로 미검증으로 남긴다.

## 15. 표현할 수 없는 mutation

다음 경우 Agent가 raw workaround를 만들지 않는다.

```text
semantic target schema/decoder가 없음
semantic selector를 stable하게 표현할 수 없음
required live-value transform을 Proxy가 지원하지 않음
resolved concrete edit를 Edit Applier가 표현할 수 없음
reproduction delta를 요구된 의미로 기록할 수 없음
이전 transaction의 값이나 identity가 필요함 (state lineage)
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

state lineage가 필요한 intent는 Compiler가 `requires_state_lineage`로 거부하고, Controller가
`HarnessGapIssue(gap_class=mutation_engine)`에 missing capability `state_lineage`로 연결한다(issue #6).
Agent가 직접 `unsupported`를 낼 때 missing capability는 HCAP vocabulary의 id다. 맞는 id가 없으면
`mutation_engine.unlisted`를 쓰고 `CapabilityProposal`(layer `semantic_subset`, `proxy`, `compiler_lowering`)을
함께 낸다. 빈 id는 출력 형식 결함으로 executor가 거부한다(#81 D5). proposal은 capability를 만들거나 promotion하지
않는다.
초기 runtime(M0–M7)은 다음을 표현하지 않는다.

```text
file X를 연 OPEN의 stateid를 쓰는 WRITE의 stateid 변조
CLOSE 뒤에 그 stateid 재사용
client0의 stateid를 client1 요청에 사용
이전 transaction에서 받은 sessionid / clientid 참조
```

Harness Generation(`07` §5)이 그 capability를 생성·검증하면 Stage 2를 이어 간다. 생성이 실패하면 job은
`blocked_harness_gap`에서 기다린다.

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

neutral program (같은 harness identity, scenario NFS operation 없음)
        + 설치된 rule set
        + target mode activation
    |
    +-- target이 관측되는가?          (q1_preservation_unverifiable)
    +-- rule별로 APPLIED인가?         (ambient_applied)
```

neutral run 결과는 gate 경로를 바꾸지 않고 인과 해석만 한정한다(`01` §3, issue #10).

반복 횟수는 job policy가 정한다. gate의 Q1이 `NOT_REACHED`이면 gate 실패로 기록하고 target mode,
rule, runtime 중 어디서 도달성이 퇴행했는지 진단한다. rule이 도달성을 깨뜨렸다고 바로 단정하지
않는다. `NOT_REACHED`는 `06` §9의 조건을 만족할 때만 나온다(issue #9).

gate의 Q1이 `REACHED`여도 gate가 평가한 rule 중 하나라도 M1이 `INCONCLUSIVE`이면 runtime/evidence
path를 고친 뒤 gate를 다시 실행한다. mutation evidence 경로가 확정되기 전에는 fuzz campaign을 시작하지
않는다.

`targets_baseline_traffic=true`인 intent의 M1이 gate에서 `NOT_APPLIED`이면 fuzz budget을 쓰기 전에
rule/strategy repair로 보낸다. `false`이면 baseline에서 적용되지 않은 것만으로 오류가 아니다. 이 필드는
필수이며 기본값이 없다(§5, issue #5). #10의 ambient flag는 이 선언을 바꾸지 않는다.

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
