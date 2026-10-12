# NFS Proxy Semantic Mutation Runtime Contract

> 상태: draft · 최종 확인: 2026-10-12
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82
> 상위 설계: `01-architecture.md`
> 선행 계약: `02-semantic-decoder.md`, `03-transaction-context.md`
> 상위 Agent 계약: `../02-llm-agent/08-mutation-rule-set.md`
> 관련 구현: `tools/nfs-proxy/src/control.c`, `edit.c`, `edit.h`
> 관련 게이트: Stage 2 M1 target resolution

## 요약

Semantic Mutation Runtime은 `CompiledMutationRule`을 live decoded RPC/NFS record에
적용 가능한 `ResolvedMutation`으로 바꾸는 Proxy runtime 계약이다. Selector와
predicate는 semantic field/context만 참조하고 transform은 deterministic하게 현재
record와 Transaction Context에서 값을 계산한다. Rule 등록 순서나 precomputed byte
offset에 의미가 생기면 replay와 M1이 불안정해지므로 모든 rule은 동일한
pre-mutation snapshot에서 resolve하고 conflict를 apply 전에 명시적으로 거부한다.

## 해결하려는 문제

Current NFSPARM1/2는 concrete predicate와 byte edit를 한 object에 담는다.

```text
direction / backend / client
first opcode / literal anchor
byte offset / original / replacement
```

또한 current `nfsp_control_record`는 fixed-width v1 rule을 먼저 적용한 뒤
variable-length v2 pass가 그 modified buffer를 입력으로 사용한다.

```text
original record
    |
    v
v1 edits
    |
    v
v1-mutated buffer
    |
    v
v2 predicate / edits
```

이 구조를 target semantic runtime으로 그대로 사용하면 두 문제가 생긴다.

첫째, live dynamic field의 offset/original을 registration 전에 알아야 한다.

둘째, 뒤 rule이 앞 rule의 결과를 보면 registration/application order가 mutation
의미를 바꾼다.

Target runtime은 이 두 문제를 다음처럼 분리한다.

```text
CompiledMutationRule[]
        +
pre-mutation DecodedRpcMessage
        +
TransactionEntry?
        |
        v
[Semantic Rule Resolver]
        |
        +--> selector/predicate evaluation
        +--> typed transform evaluation
        +--> live WireRef resolution
        |
        v
ResolvedMutation[]
        |
        v
conflict / structure preflight
        |
        v
[Mutation Engine]
```

모든 selector, predicate, transform input은 같은 pre-mutation snapshot을 본다.

## 구조

```text
  +---------------- compiler boundary --------------------+
  |  MutationRuleSet                                     |
  |        | semantic intent                             |
  |        v                                             |
  |  [Mutation Rule Compiler]                            |
  |        | CompiledMutationRule[]                      |
  +--------|---------------------------------------------+
           v
  +---------------- NFS Proxy runtime --------------------+
  |  RpcRecord + DecodedRpcMessage + TransactionEntry?   |
  |        | pre-mutation snapshot                       |
  |        v                                             |
  |  [Semantic Rule Resolver] (R)                        |
  |        | ResolvedMutation[]                          |
  |        v                                             |
  |  [Conflict / Structure Preflight]                    |
  |        | conflict-free concrete edits                |
  |        v                                             |
  |  [Mutation Engine]                                   |
  +--------|---------------------------------------------+
           | mutated record
           v
       Delta / forwarding
```

`(R)`=semantic match/resolve 관측 지점.
아래 단계는 위 단계의 output만 읽고 rule-order side effect를 만들지 않는다.

## 설계

### 1. 요소 분류와 소유권

```text
[DATA] CompiledMutationRule
    Produced by:   Mutation Rule Compiler
    Consumed by:   Semantic Rule Resolver
    Meaning:       executable semantic rule, not byte patch

[DATA] SemanticSelector
    Produced by:   Mutation Rule Compiler
    Consumed by:   Semantic Rule Resolver

[DATA] SemanticPredicate
    Produced by:   Mutation Rule Compiler
    Consumed by:   Semantic Rule Resolver

[DATA] MutationTransform
    Produced by:   Mutation Rule Compiler
    Consumed by:   Semantic Rule Resolver

[DATA] ResolvedMutation
    Produced by:   Semantic Rule Resolver
    Consumed by:   Mutation Engine / evidence

[COMPONENT] Semantic Rule Resolver
    Runs at:       Proxy runtime
    Input:         rules + decoded live record + transaction context
    Output:        zero or more ResolvedMutation
    Mutates wire:  NO
```

Mutation Engine만 실제 bytes를 바꾼다.

### 2. CompiledMutationRule

```text
CompiledMutationRule
    identity
        rule_id
        candidate_id
        schema_id

    traffic_scope
        direction
        backend
        client

    selector
        rpc
        protocol
        operation?
        target
        predicates[]

    mutation
        kind
        transform?
        structure_policy

    context_dependencies[]

    application
        mode: all_matches
```

`rule_id`는 job/evidence lineage용 logical ID다.
content hash이거나 replay selector일 필요는 없다.

`schema_id`는 Compiler가 검증한 ProtocolSchema와 runtime Decoder가 사용한 schema가
같은 contract인지 확인하는 데 사용한다.

### 3. traffic_scope

```text
traffic_scope
    direction: C2S | S2C
    backend
    client
```

이 값은 Stage 1 route를 bind한다.

다음을 의미하지 않는다.

```text
RPC caller
RPC CALL/REPLY type
connection_id
runtime XID
```

특히 backchannel 때문에 direction과 RPC message type은 독립이다.

### 4. SemanticSelector

Normalized selector:

```text
SemanticSelector
    rpc
        message_type: call | reply
        program
        version
        procedure?

    protocol
        family
        nfs_version?
        minor_version?

    operation?

    target
        kind
            field
            operation_array
        path
        part?

    predicates[]
```

`message_type`은 direction에서 추론하지 않는다.

`procedure`가 REPLY에서 필요하면 Transaction Context dependency가 자동으로 생긴다.

### 5. SemanticTarget

Field target:

```text
target
    kind: field
    path: nfs4.response.OPEN.result.ok.stateid
    part: value
```

Structural target:

```text
target
    kind: operation_array
    path: nfs4.request.COMPOUND.operations
```

`part`는 Decoder의 `WireRef` 의미를 사용한다.

```text
value
encoded
metadata:length
metadata:count
metadata:discriminant
metadata:padding
```

기본은 `value`다.

Metadata part는 deliberate structural corruption처럼 그 metadata 자체가 semantic
target일 때만 선택한다.

### 6. target path와 occurrence

Semantic path는 stream ordinal이 아니다.

한 record에 같은 operation이 여러 번 있을 수 있다.

```text
OPEN
PUTFH
OPEN
```

Selector가 두 OPEN을 semantic predicate로 구분하지 못하면 `all_matches`는 둘 다
eligible하게 만든다.

다음은 금지한다.

```text
second OPEN
operation sequence_index == 2
Nth stateid in the program
```

특정 occurrence가 필요하면 같은 operation의 sibling field나 request context를
semantic predicate로 사용한다.

### 7. SemanticPredicate

Predicate는 typed comparison의 conjunction이다.

```text
SemanticPredicate
    lhs: ValueRef
    op
        eq
        ne
        lt
        le
        gt
        ge
    rhs
        TypedLiteral
        ValueRef
```

모든 `predicates[]`는 AND로 평가한다.

초기 contract는 general-purpose boolean expression language를 만들지 않는다.
OR가 필요하면 Compiler가 non-overlapping alternative rule로 낮출 수 있는지
검증하고, 그렇지 않으면 unsupported로 처리한다.

### 8. ValueRef

```text
ValueRef
    source
        target
        current_message
        request_context
    path?
```

`target`:
- 현재 target occurrence의 logical value.

`current_message`:
- 같은 decoded message의 semantic field.
- 같은 operation type이 반복되면 target occurrence와 같은 operation context에
  상대적으로 resolve하는 것이 기본이다.
- message-wide reference가 유일하지 않으면 ambiguous다.

`request_context`:
- matching TransactionEntry에 보존된 request-side semantic value.
- response target에서 request-side selector/transform에 사용한다.

### 9. predicate type rules

Compiler는 predicate를 runtime 전에 type-check한다.

```text
eq / ne
    scalar, enum, opaque, string 등 equality가 정의된 type

lt / le / gt / ge
    ordered numeric type만

ValueRef vs ValueRef
    compatible logical type만
```

Implicit byte reinterpretation은 없다.

예:

```text
stateid == u32
    -> compile error

status == NFS4_OK
    -> valid enum comparison
```

Bitmask, set membership 같은 추가 operator는 별도 typed operator로 확장할 수 있지만
구현/HCAP에 등록되기 전에는 지원한다고 가정하지 않는다.

### 10. context_dependencies

Compiler는 selector/predicate/transform이 request context에서 읽어야 하는 값을
명시적으로 dependency set으로 만든다.

```text
context_dependencies[]
    rpc_procedure?
    request_operation_sequence?
    request_fields[]
```

Transaction Context는 이 dependency set을 보고 bounded typed metadata를 보존할 수 있다.

Compiler가 dependency를 선언하지 않았는데 runtime transform이 임의로 request packet을
조회하는 구조는 허용하지 않는다.

### 11. mutation kind

Target semantic contract의 mutation family:

```text
replace
insert
delete
op_append
op_prepend
```

Current NFSPARM2 names과 같지만 의미는 raw offset edit가 아니다.

지원되지 않는 schema position에 arbitrary insert/delete를 허용하지 않는다.

### 12. MutationTransform

```text
MutationTransform
    kind
        literal
        copy
        builtin

    value?
    source?
    transform_id?
    args[]
```

Transform은 deterministic하고 side-effect free여야 한다.

Runtime transform이 wall clock, random generator, global mutable identifier pool,
another rule's mutated output, future record를 읽는 것은 금지한다.

동적 값은 live current record와 matching TransactionEntry에서만 명시적으로 가져온다.

### 13. literal transform

```text
kind: literal
value: TypedLiteral
```

TypedLiteral은 ProtocolSchema type과 함께 검증한다. Literal은 semantic value다.
record byte offset이나 recorded original bytes를 제공하는 것이 아니다.

### 14. copy transform

```text
kind: copy
source: ValueRef
```

Source와 target type은 Compiler가 compatible하다고 증명해야 한다.

### 15. builtin transform

```text
kind: builtin
transform_id
args[]
```

`transform_id`는 implementation이 명시적으로 지원하는 deterministic typed
transform을 가리킨다. 예를 들어 zero_value, integer_add, integer_xor,
truncate_value 같은 category가 가능하지만 이 예시가 current support를 뜻하지 않는다.

각 builtin은 input/output/argument type, overflow/error semantics와 versioned
deterministic meaning을 가져야 한다.

Arbitrary script, shell, Python expression 같은 executable transform은 허용하지 않는다.

### 16. operation value

`op_append` / `op_prepend`의 value는 raw XDR bytes가 아니라 typed operation object다.
Runtime schema encoder가 live ProtocolSchema에 맞춰 concrete XDR bytes를 만든다.
지원하지 않는 operation/version 조합은 Compiler가 거부한다.

### 17. structure_policy

```text
structure_policy
    preserve
    raw
```

`preserve`는 mutation 대상 container의 XDR structure를 일관되게 유지한다.
필요하면 `WireRef.metadata_spans`를 이용해 length, count, COMPOUND op count,
padding을 live state에서 재계산한다.

`raw`는 semantic target selection은 schema-proven path로 수행하되 요청한 edit 외의
structural metadata 자동 보정을 하지 않는다.

Outer SunRPC record framing은 raw에서도 실제 transmitted record length에 맞게
재생성한다.

### 18. raw policy의 경계

`raw`는 arbitrary byte offset permission이 아니다.

```text
allowed:
    schema-proven field/container + selected WireRef part

forbidden:
    literal byte offset
    magic-byte scan
    unknown region patch
```

Malformed output을 만들더라도 mutation 전 target boundary는 확실해야 한다.

### 19. Compiler static validation

Mutation Rule Compiler는 Proxy 실행 전에 최소 다음을 검증한다.

```text
schema_id available
traffic route valid
direction / rpc message type consistent
rpc program/version/procedure valid
nfs version/minor valid
operation valid
target semantic path exists
target WireRef part exists
predicate types compatible
transform types compatible
structure_policy valid for mutation kind
context dependencies derivable
application mode == all_matches
runtime capability advertised
```

Compiler는 live record가 아직 없으므로 actual selector match, current field value,
current WireRef offset, current TransactionEntry presence, runtime rule conflict를
검증하지 않는다.

### 20. schema_id compatibility

Runtime Decoder의 `DecodedRpcMessage.schema_id`와 rule의 `schema_id`가 다르면
semantic path가 같은 문자열이어도 rule을 적용하지 않는다.

```text
compiled schema A
runtime schema B
    -> schema_mismatch
```

Implicit best-effort path remapping은 없다.

### 21. runtime resolution pipeline

한 complete RPC record에 대한 Resolver 순서는 다음과 같다.

```text
1. traffic_scope match
2. RPC selector match
3. schema_id / decode_status check
4. protocol / operation match
5. required TransactionEntry lookup
6. semantic target occurrence enumeration
7. predicate evaluation
8. deterministic transform evaluation
9. concrete edit + original precondition 생성
10. cross-rule conflict / structure preflight
```

앞 단계가 실패하면 뒤 단계로 추측해서 진행하지 않는다.

### 22. target occurrence enumeration

Decoder output에서 target path에 해당하는 occurrence를 모두 찾는다.
각 occurrence는 같은 record 안에서 독립 candidate다.

Predicate는 각 target candidate의 semantic context에 상대적으로 평가한다.

### 23. predicate binding

같은 operation에 속한 `current_message` ValueRef는 현재 target occurrence와 같은
operation occurrence를 우선 bind한다.

Message-wide ValueRef가 여러 값으로 resolve되어 의미를 결정할 수 없으면
`predicate_reference_ambiguous`로 거부한다.

Transaction request field도 request/result correspondence가 증명된 occurrence에만 bind한다.

### 24. application = all_matches

현재 target contract의 application mode는 하나다.

```text
application.mode = all_matches
```

모든 matching record와 그 record 안의 모든 matching semantic occurrence가 eligible하다.

다음 mode는 지원하지 않는다.

```text
first_match
once
Nth_match
after_N_messages
```

하나만 필요하지만 content predicate로 구분할 수 없다면 ordinal fallback을 쓰지 않는다.

### 25. pre-mutation snapshot invariant

한 record의 모든 semantic rule은 동일한 original live snapshot에서 resolve한다.

```text
record R0
   |
   +--> rule A match/transform --+
   +--> rule B match/transform --+--> conflict preflight
   +--> rule C match/transform --+
```

금지:

```text
R0 -> apply A -> R1 -> match B against R1
```

따라서 registration order가 predicate나 transform input을 바꾸지 않는다.

앞 mutation 결과를 다음 mutation의 입력으로 써야 한다면 여러 독립 rule 순서에
의존하지 않고 하나의 explicit composite mutation으로 표현해야 한다. Initial contract에
그 form이 없으면 unsupported다.

### 26. ResolvedMutation

```text
ResolvedMutation
    rule_id
    target
        semantic_path
        occurrence_context
        wire_ref
    observed
        current_value
        predicate_values[]
        transaction_context_summary?
    output
        semantic_value?
        concrete_edits[]
    preconditions
        original_bytes[]
        structural_assumptions[]
```

`original_bytes[]`는 live record에서 runtime에 snapshot한 verify-before-apply data다.
Agent나 Compiler 입력이 아니다.

### 27. concrete edit generation

Resolver는 SemanticTarget의 WireRef와 transform output을 이용해 concrete edit를 만든다.

```text
semantic field + live WireRef
        |
        v
typed transform output
        |
        v
schema encoder
        |
        v
offset / expected original / replacement
```

`preserve` policy의 structural fix-up은 user edit와 구분된 derived edit다.

### 28. cross-rule conflict policy

한 record에 대해 모든 ResolvedMutation을 수집한 뒤 apply 전에 conflict를 검사한다.

```text
overlapping remove/replace spans
independent inserts at same semantic boundary
raw/preserve rules with incompatible metadata
one edit removes a container another edit targets
derived metadata that cannot compose deterministically
```

Conflict가 있으면 registration order로 승자를 고르지 않는다.

### 29. derived metadata aggregation

Structure-preserving derived metadata는 의미가 명확한 경우에만 합친다.

```text
two non-conflicting operation insertions
    -> final op count = live count + 2
```

Count/length를 rule별 literal patch로 순차 적용하지 않고 final structure에서 재계산한다.

같은 insertion boundary의 ordering은 registration order로 정하지 않는다.

### 30. Mutation Engine boundary

Semantic Rule Resolver는 bytes를 쓰지 않는다.
Mutation Engine은 original RpcRecord와 conflict-free ResolvedMutation[]을 받아
verify/apply/rebuild를 수행한다. Mutation Engine은 selector를 다시 해석하지 않는다.

### 31. resolver result taxonomy

```text
scope_miss
rpc_selector_miss
schema_mismatch
decode_unavailable
transaction_context_missing
target_not_found
target_ambiguous
predicate_false
predicate_reference_ambiguous
transform_unsupported
transform_failed
resolved
conflict
structure_constraint_failed
```

`predicate_false`와 `target_not_found`는 정상 non-match일 수 있다.
semantic refusal은 mutation이 실행되지 않은 이유로 별도 evidence에 남긴다.

이 결과는 record마다 journal event로 쓰지 않는다. rule별로 집계해 program generation마다
`GENERATION_COMPLETE` summary에 남긴다(`05-mutation-delta-replay.md` §21, issue #4).
activation 창 밖의 record는 Resolver에 들어가지 않으며 `outside_activation_window`로 센다
(`01-architecture.md` §16).

### 32. current NFSPARM1/2와의 관계

Current NFSPARM1/2는 concrete Layer 0 ABI다.

Target runtime에서는 semantic resolution 이후 만들어진 concrete edit를 기존 engine으로
내릴 수는 있지만 Agent-facing/Compiler-facing rule을 current offset/anchor 형식으로
제한하지 않는다.

### 33. current sequential behavior는 target invariant가 아님

Current `nfsp_control_record`는 v1 edit 후 v2 edit를 수행하고 v2가 v1-mutated buffer를
본다. Current variable edit engine은 equal-offset ordering에 rule/edit order tie-break를
사용한다.

Target은 같은 pre-mutation snapshot, order-independent evaluation, explicit conflict
refusal, one final rebuild를 요구한다.

### 34. M1 경계

`ResolvedMutation` 생성 성공은 M1이 아니다.

```text
selector matched + target resolved + transform evaluated
    -> resolution success only

Mutation Engine applied + durable evidence + forwarding result
    -> M1 Judge input
```

M1의 verdict 계약은 `../02-llm-agent/01-two-stage-agent-architecture.md` §7이 소유한다
(issue #4).

## 설계 근거

| 결정 | 근거 |
|---|---|
| semantic selector와 byte edit 분리 | dynamic offset을 registration 전에 알 필요가 없음 |
| direction과 RPC message type 분리 | backchannel은 S2C CALL / C2S REPLY 가능 |
| typed predicate 사용 | byte reinterpretation과 invalid comparison 차단 |
| context dependency 명시 | Transaction Context retention을 bounded하게 유지 |
| deterministic transform만 허용 | replay가 RNG/time에 의존하지 않게 함 |
| raw도 schema-proven target에서 시작 | malformed output과 wrong-field mutation을 분리 |
| all_matches만 지원 | ordinal replay identity 제거 |
| same snapshot에서 모든 rule resolve | registration order 영향 제거 |
| conflict를 apply 전에 거부 | silent overlap/order-dependent output 방지 |
| derived metadata를 final structure에서 계산 | stale literal count/length patch 방지 |
| Resolver success와 M1 분리 | match와 실제 application을 혼동하지 않음 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| Compiler가 NFSPARM offset 생성 | current engine 재사용 쉬움 | dynamic record에서 stale | 비채택 |
| raw byte pattern selector | schema 없이 빠름 | false-positive semantic match | 비채택 |
| arbitrary script transform | 표현력 큼 | 비결정성/validation 복잡성 | 비채택 |
| Proxy runtime RNG | 많은 fuzz value | replay 의미 불안정 | 비채택 |
| first/Nth-match | 특정 message 선택 쉬움 | traffic order 의존 | 비채택 |
| rule order로 conflict 해결 | 구현 간단 | arm 순서가 output 의미를 바꿈 | 비채택 |
| same snapshot + conflict preflight | order-independent | batch resolution 필요 | 채택 |
| raw arbitrary offset | malformed 범위 큼 | semantic attribution 상실 | 비채택 |

Transform 표현력이 부족하면 arbitrary script 대신 typed builtin을 추가하고 검증된
support만 Harness Capability Specification에 노출한다.

## 영향

### 상류

ProtocolSchema의 semantic path/type가 바뀌면 Compiler validation과 selector binding이
영향받는다. Transaction Context가 required dependency를 보존하지 못하면 response rule은
runtime에 resolve할 수 없다.

MutationRuleSet은 semantic intent만 제공하고 concrete offset/original을 제공하지 않는다.

### 하류

Resolver가 wrong target/transform을 만들면 Mutation Engine과 MutationDelta가 그 잘못된
의미를 정상 application으로 기록할 수 있다.

따라서 M1 신뢰성은 Decoder뿐 아니라 Resolver의 typed target/predicate binding에 직접
의존한다.

### 운영

Rule 수와 target occurrence 수에 따라 per-record resolution cost가 증가한다.

Runtime은 다음을 bounded하게 유지해야 한다.

```text
registered semantic rules
target occurrences per record
resolved concrete edits per record
transform temporary data
```

구체적인 numeric bound는 implementation gap analysis와 측정 후 정한다.

## 신뢰성 요구

가장 위험한 오류는 **거짓 양성 semantic application**이다.

```text
rule says OPEN.result.stateid
    but
Resolver edits a different field
    or
predicate was false for this occurrence
```

이 오류는 Proxy가 intended mutation이 적용됐다고 잘못 주장하게 한다.

| 항목 | 요구 |
|---|---|
| 오류 방향 | false-positive semantic target/application을 최우선 방지 |
| 실패 방식 | schema/context/type/conflict ambiguity는 fail closed |
| 관측 가능성 | rule별 scope/match/predicate/resolve/refusal 결과 필요 |
| 재현성 | same schema + same pre-mutation inputs => same resolution |

False negative도 reason code로 진단 가능해야 한다.

## 검증 오라클

### 1. literal replace

Known field를 typed literal로 replace한다.

Expected:

```text
correct semantic occurrence selected
current original snapshotted
expected concrete value encoded
no sibling field changed
```

### 2. request-context predicate

두 response가 같은 operation/status를 가지되 matching request context만 다르게 만든다.

Expected:
- predicate가 true인 transaction만 resolve;
- missing context에서는 semantic mutation 없음.

### 3. repeated operation in one COMPOUND

같은 operation을 두 번 넣고 semantic predicate로 하나만 구분한다.

Expected:
- predicate가 구분하면 해당 occurrence만 eligible;
- 구분 조건이 없으면 all_matches로 둘 다 eligible;
- sequence_index/Nth selector는 필요하지 않음.

### 4. same snapshot rule ordering

Rule A/B registration order를 바꿔 동일 record를 resolve한다.

Expected:

```text
same matched rule set
same predicate values
same concrete edits/conflict result
```

### 5. overlap conflict

두 rule이 같은 target span을 다르게 replace하게 한다.

Expected:
- conflict;
- registration order에 따라 한쪽이 이기지 않음;
- record는 partial semantic batch로 mutate되지 않음.

### 6. same-position insert conflict

독립 rule 두 개가 같은 operation boundary에 서로 다른 operation을 삽입하려 하면
ordering ambiguity로 conflict해야 한다.

### 7. structure preserve

Variable-length semantic value 또는 operation insertion을 preserve policy로 적용한다.

Expected:
- length/count/padding/op-count derived metadata 일관성;
- outer RPC record marker final length 일치.

### 8. structure raw

같은 semantic target을 raw policy로 적용한다.

Expected:
- requested structural mismatch 유지;
- target은 여전히 schema-proven pre-mutation field;
- outer RPC framing은 valid.

### 9. schema mismatch

Compiled rule schema_id와 runtime Decoder schema_id를 다르게 만든다.

Expected:
- no mutation;
- explicit schema_mismatch.

### 10. transform determinism

동일 current value, TransactionEntry, rule을 반복 resolve한다.

Expected:
- identical transform output;
- time/random/external state에 따른 variation 없음.

### 11. all_matches across records

동일 semantic predicate를 만족하는 여러 record를 전달한다.

Expected:
- 모든 match가 independently eligible;
- first/Nth count state 없음.

### 12. original precondition

Resolve 후 apply 직전에 input snapshot이 달라지는 synthetic test를 만든다.

Expected:
- verify-before-apply가 mutation을 거부;
- stale ResolvedMutation을 다른 bytes에 적용하지 않음.

이 검증은 crash/Q2를 증명하지 않는다.
또한 Resolver 성공만으로 M1을 증명하지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| selector miss | wrong RPC/protocol selector | selector stage result | Compiler/plan 검토 |
| schema_mismatch | stale compiled rule/schema | rule/runtime schema_id | recompile rule |
| target_not_found | traffic drift/path 부재 | decoded paths | Stage 2 plan/schema 검토 |
| target_ambiguous | predicate 부족 | occurrence candidates | predicate 강화/unsupported |
| context missing | CALL 미관측/expired | Transaction Context result | lifecycle 검토 |
| predicate false | live state 다름 | typed lhs/rhs | Mutation Strategy 재검토 |
| transform unsupported | runtime capability 없음 | transform_id/type | HarnessGapIssue |
| transform failed | overflow/type/runtime input 오류 | transform reason | rule 검토 |
| conflict | overlapping/order-sensitive rules | resolved spans | rule set 재설계 |
| structure constraint failed | metadata recompute 불가 | WireRef/container | schema/runtime gap |
| apply original mismatch | stale resolution/input mismatch | expected/current bytes | apply refusal |

## 한계와 미결 사항

- **결정됨:** CompiledMutationRule은 semantic executable rule이며 byte offset rule이 아니다.
- **결정됨:** selector는 direction과 RPC message type을 분리한다.
- **결정됨:** application mode는 `all_matches`다.
- **결정됨:** ordinal/Nth-message selector는 지원하지 않는다.
- **결정됨:** predicates는 typed conjunction이다.
- **결정됨:** transform은 deterministic하고 side-effect free여야 한다.
- **결정됨:** runtime RNG/time/global mutable pool은 transform input이 아니다.
- **결정됨:** raw policy도 schema-proven target에서 시작한다.
- **결정됨:** 모든 rule은 같은 pre-mutation record snapshot에서 resolve한다.
- **결정됨:** cross-rule conflict를 registration order로 해결하지 않는다.
- **결정됨:** Resolver success는 M1이 아니다.
- **미결:** CompiledMutationRule serialization/control ABI.
- **미결:** initial supported builtin transform registry.
- **미결:** insert/delete가 지원할 schema container subset.
- **미결:** explicit ordered composite mutation representation.
- **미결:** runtime numeric safety limits.
- **미결:** same-container independent edit conflict granularity.
- **미결:** existing NFSPARM engine 재사용 범위.
- **미검증:** order-independent semantics의 real workload performance cost.

## 참조

- `docs/design/03-nfs-proxy/01-architecture.md`
- `docs/design/03-nfs-proxy/02-semantic-decoder.md`
- `docs/design/03-nfs-proxy/03-transaction-context.md`
- `docs/design/02-llm-agent/08-mutation-rule-set.md`
- `docs/design/02-llm-agent/04-harness-capability-spec.md`
- `tools/nfs-proxy/src/control.c`
- `tools/nfs-proxy/src/edit.c`
- `tools/nfs-proxy/src/edit.h`
- `tools/nfs-proxy/src/delta.h`

## Agent 사용 지침

### 지원 범위

Agent가 semantic mutation intent를 사용할 수 있다고 가정하려면 다음이 모두 current
Harness Capability Specification에서 지원/검증되어야 한다.

```text
target ProtocolSchema path
required Decoder field/WireRef
required Transaction Context dependency
predicate operator/types
mutation kind
transform_id/value form
structure policy
concrete Mutation Engine mapping
```

Target design에 syntax가 존재한다는 이유만으로 current support라고 가정하지 않는다.

### 비지원 범위

다음 경우 Agent가 raw workaround를 만들지 않는다.

```text
unknown semantic path
unsupported predicate/operator
unsupported transform
missing request context capability
ordinal-only target identity
arbitrary raw offset requirement
order-dependent multi-rule semantics
unresolvable runtime conflict
```

Stage 2에 꼭 필요하면:

```text
unsupported_by_current_harness
    -> HarnessGapIssue
       gap_class = mutation_engine
```

### 확장 절차

새 selector/predicate/transform을 추가할 때 최소 Compiler validation/type rules, Proxy Resolver implementation,
Transaction Context dependency, Mutation Engine mapping, host unit tests, guest/runtime validation,
Harness Capability Specification을 함께 갱신한다.

### 제약

```text
semantic path only
all_matches
same pre-mutation snapshot
deterministic transform
no runtime ordinal identity
no runtime XID replay identity
no rule-order dependency
schema-proven raw target only
Q1/M1/Q2 evidence 분리
```

### 검증 방법

Compiler type/schema validation, live selector/predicate resolution, Transaction Context dependency,
transform determinism, repeated-operation all_matches, cross-rule conflict negative test,
preserve/raw structure test, verify-before-apply refusal test, guest/runtime application evidence를
통과해야 한다.

Compiler acceptance나 control registration ACK만으로 capability를 validated로 올리지 않는다.

## 다음 상세 설계

```text
1. [`MutationDelta / Replay contract`](05-mutation-delta-replay.md) — detailed contract fixed
2. [`Implementation gap analysis`](06-implementation-gap-analysis.md) — current-vs-target mapping fixed
3. Proxy implementation
```
