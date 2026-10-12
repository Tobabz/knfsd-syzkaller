# NFS Proxy Semantic Mutation Architecture

> 상태: draft · 최종 확인: 2026-10-12
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82
> 관련 구현: `tools/nfs-proxy`, syzkaller 0017/0019
> 관련 게이트: Stage 2 M1 mutation application

## 요약

NFS Proxy는 Agent의 semantic mutation rule을 live NFS/RPC record에 적용하는
Stage 2 실행 컴포넌트다. Proxy가 live record를 decode해서 target field와 현재 값을
runtime에 resolve하고, 실제 적용 결과를 durable delta로 남긴다. 이 계층이 잘못되면
M1이 잘못 판정되고 crash 재현이 다른 record를 변조할 수 있다.

용어: NFS Proxy(`tools/nfs-proxy`)는 운영 문서의 NFS 특화 Mutation Engine과 같은 컴포넌트이고,
**Edit Applier**는 그 내부에서 resolve된 concrete edit를 검증하고 적용하는 단계다(§10).

## 해결하려는 문제

현재 `tools/nfs-proxy`의 NFSPARM1/2는 코드상 concrete byte mutation을 받는다.

```text
anchor offset / bytes
edit offset
original bytes
replacement bytes
```

이 ABI를 목표 architecture로 그대로 올리면 Agent 또는 Compiler가 live record가
도착하기 전에 byte 위치와 original value를 알아야 한다.

NFS에는 실행마다 달라질 수 있는 값이 많다.

```text
XID
clientid
sessionid
stateid
slot sequence
filehandle
verifier
```

따라서 baseline run에서 raw record를 capture한 뒤 다음 run에 그 offset/original을
재사용하는 방식은 runtime 값 변화에 취약하다. 또한 N번째 message나 특정 XID를
identity로 사용하면 replay가 traffic ordering에 종속된다.

목표 설계는 이 문제를 다음과 같이 해결한다.

```text
semantic rule
    |
    v
live RPC/NFS decode
    |
    v
semantic field resolution
    |
    v
current value / concrete edit resolution
    |
    v
mutation + durable delta
```

현재 구현이 이 구조를 지원하지 않으면 구현을 목표 설계에 맞춰 확장한다.

## 구조

```text
  +---------------- application / runner ------------------+
  |                                                        |
  |  MutationRuleSet                                       |
  |        | semantic rule                                 |
  |        v                                               |
  |  [Mutation Rule Compiler]                              |
  |        | CompiledMutationRule                          |
  +--------|-----------------------------------------------+
           v
  +------------------- NFS Proxy --------------------------+
  |  [Record Framer]                                       |
  |        | RpcRecord                                     |
  |        v                                               |
  |  [RPC Decoder]                                         |
  |        | RPC metadata                                  |
  |        v                                               |
  |  [NFS Semantic Decoder] <--> [Transaction Context]     |
  |        | DecodedRpcMessage                             |
  |        v                                               |
  |  [Semantic Rule Resolver]                              |
  |        | ResolvedMutation                              |
  |        v                                               |
  |  [Edit Applier] -----(M)-----> [Delta Recorder]        |
  |        | mutated RPC                 | MutationDelta    |
  +--------|-----------------------------|------------------+
           v                             v
       peer/server               Runner host sink
```

`(M)`은 M1 evidence가 생성되는 관측 지점이다. MutationDelta는 guest 밖의 Runner host sink에
durable하게 기록된다(§12).
읽는 순서는 위에서 아래이며, RPC는 Proxy 안에서 semantic record로 해석된다.

## 설계

### 1. `[DATA] RpcRecord`

Mutation unit은 TCP packet이 아니라 SunRPC record reassembly가 끝난 하나의
complete RPC message다.

```text
RpcRecord
    route
        direction
        backend
        client

    rpc_payload
```

`rpc_payload`는 SunRPC record marker를 제외한 complete RPC message를 뜻한다.
semantic field offset은 TCP segment/fragment layout에 의존하지 않는다.

mutation 후 Record Framer가 output length에 맞는 record framing을 다시 만든다.

### 2. `[COMPONENT] Record Framer`

입력:

```text
TCP byte stream
```

출력:

```text
RpcRecord
```

책임:

```text
SunRPC record marker parsing
multi-fragment reassembly
complete message boundary validation
mutated payload의 record framing 재생성
```

같은 RPC semantics가 다른 TCP fragmentation으로 전달되어도 semantic rule의
의미는 같아야 한다.

### 3. `[COMPONENT] RPC Decoder`

RPC Decoder는 RPC envelope만 해석한다.

```text
CALL / REPLY
XID
program
version
procedure
auth / verifier boundaries
```

NFS operation 내부 field를 이 계층에서 추측하지 않는다.

### 4. `[COMPONENT] NFS Semantic Decoder`

상세 계약은
[`02-semantic-decoder.md`](02-semantic-decoder.md)에 정의한다.

NFS Semantic Decoder는 live RPC payload를 protocol schema에 따라 해석한다.

예:

```text
NFSv4 COMPOUND
    |
    +-- SEQUENCE
    |     +-- sessionid
    |     +-- sequenceid
    |
    +-- PUTFH
    |     +-- filehandle
    |
    +-- OPEN
          +-- request fields
          +-- response fields
              +-- status
              +-- stateid
```

출력은 semantic field와 live byte span을 함께 가진다.

```text
DecodedRpcMessage
    rpc
        message_type
        xid
        program
        version
        procedure

    protocol
        family
        nfs_version
        minor_version?

    operations[]
        operation
        semantic_fields[]
            path
            value
            byte_span

    decode_status
```

`byte_span`은 live `RpcRecord.rpc_payload`에서 decoder가 확인한 위치다.
Agent나 Compiler가 미리 계산하지 않는다.

Codec은 protocol/version 단위 registry로 확장한다.

```text
NFS Codec Registry
    |
    +-- NFSv3 procedure codecs
    +-- NFSv4.0 COMPOUND codecs
    +-- NFSv4.1 COMPOUND codecs
    +-- NFSv4.2 COMPOUND codecs
    +-- future RPC program codecs
```

Schema를 모르는 field boundary는 추측하지 않는다.

### 5. `[COMPONENT] Transaction Context`

상세 계약은
[`03-transaction-context.md`](03-transaction-context.md)에 정의한다.

Response를 semantic하게 해석하기 위해 request metadata를 runtime 동안 보존한다.

```text
TransactionEntry
    connection_id
    call_direction
    xid

    request_metadata
        rpc program/version/procedure
        NFS operation sequence
        semantic request context

    lifecycle
        request_seen
        response_seen
        expired
```

예:

```text
C2S CALL
    XID=100
    SEQUENCE / PUTFH / OPEN
        |
        v
Transaction Context
    connection_id + C2S + XID
        -> request operation sequence
        |
        v
S2C REPLY
    XID=100
        |
        v
OPEN result semantic decode
```

XID는 runtime correlation key일 뿐 replay identity가 아니다.

```text
allowed:
    connection_id + call_direction + XID
        -> live CALL/REPLY correlation

forbidden:
    literal XID -> durable mutation target identity
```

callback/backchannel traffic에서도 wire direction과 RPC CALL/REPLY를 별도 속성으로
유지한다.

### 6. `[DATA] CompiledMutationRule`

상세 runtime 계약은
[`04-semantic-mutation-runtime.md`](04-semantic-mutation-runtime.md)에 정의한다.

Mutation Rule Compiler는 Agent의 intent를 executable semantic rule로 낮춘다.

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
            message_type
            program
            version
            procedure?
        protocol
            family
            nfs_version?
            minor_version?
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

여기에는 다음을 넣지 않는다.

```text
TCP packet number
stream ordinal
Nth matching message
literal runtime XID identity
precomputed live field offset
precomputed live original bytes
```

### 7. `[COMPONENT] Semantic Rule Resolver`

상세 계약은
[`04-semantic-mutation-runtime.md`](04-semantic-mutation-runtime.md)에 정의한다.

입력:

```text
CompiledMutationRule
DecodedRpcMessage
TransactionEntry?
```

출력:

```text
ResolvedMutation
```

책임:

```text
traffic scope 확인
semantic selector matching
target field/path resolution
live current value 읽기
semantic precondition 확인
concrete edit 생성
```

예:

```text
CompiledMutationRule
    direction: S2C
    message_type: reply
    operation: OPEN
    target: nfs4.response.OPEN.result.ok.stateid
    mutation: zero_value

live OPEN response
        |
        v
Semantic Rule Resolver
        |
        +-- OPEN response 확인
        +-- stateid field resolve
        +-- current stateid 읽기
        +-- zero-stateid edit 생성
```

이 단계에서 처음으로 current offset/original bytes가 concrete해진다.

### 8. `[DATA] ResolvedMutation`

상세 구조는
[`04-semantic-mutation-runtime.md`](04-semantic-mutation-runtime.md)에 정의한다.

```text
ResolvedMutation
    rule_id

    target
        semantic_path
        wire_ref

    observed
        current_value

    output
        concrete_edits[]

    preconditions
        original_bytes[]
```

이 object는 Agent reasoning 결과가 아니라 live record에 rule을 적용하기 직전의
runtime resolution 결과다.

### 9. selector identity

Rule identity는 semantic/content 조건을 사용한다.

허용:

```text
direction = S2C
backend = knfsd
client = client0
RPC program = NFS
NFS version = 4.1
operation = OPEN
field = response.stateid
status = NFS4_OK
```

금지:

```text
3번째 OPEN
두 번째 matching reply
프로그램 시작 후 N번째 RPC
특정 runtime XID
특정 TCP packet number
```

같은 semantic selector와 일치하는 record가 여러 개면 기본 동작은
`apply_to_all_matching_records`다.

COMPOUND 내부 구조를 특정해야 하면 decoded message의 stable semantic path를
사용한다. Stream 전체의 temporal ordinal을 사용하지 않는다.

### 10. `[COMPONENT] Edit Applier`

Edit Applier는 `ResolvedMutation`을 받아 실제 payload를 변경한다.

기본 mutation family:

```text
replace
insert
delete
op_append
op_prepend
```

불변 조건:

```text
semantic resolver가 target을 확정
unknown field를 byte guess로 수정하지 않음
output size에 맞게 RPC record framing 재생성
겹치는 concrete edit는 명시적으로 거부
mutation failure를 silent success로 처리하지 않음
```

Structure-preserving mutation과 intentionally-invalid/raw mutation은
`structure_policy`로 명시적으로 구분한다.

### 11. runtime-derived value

Architecture는 실행마다 달라지는 값을 baseline capture literal로 고정하지 않는다.

지원해야 할 mutation value 형태:

```text
literal mutation
    status = NFS4ERR_BAD_STATEID

live-value transform
    current stateid -> zero stateid

transaction-derived transform
    current transaction context -> derived value
```

다른 transaction에서 얻은 값(state lineage)은 초기 target runtime 범위 밖이다(`04` §12, issue #6).

`value_or_transform`의 concrete DSL/ABI는 별도 runtime-rule 설계에서 고정한다.

### 12. `[COMPONENT] Delta Recorder`

상세 계약은
[`05-mutation-delta-replay.md`](05-mutation-delta-replay.md)에 정의한다.

MutationDelta는 recorded `CompiledMutationRule[]`과 production concrete application
evidence를 함께 보존한다. 논리 단위는 `ProgramGenerationExecution` 하나다(issue #2).

```text
CompiledMutationRule[]
        |
        +--> RULESET durable (host sink)
        |
ResolvedMutation[]
        |
        v
Edit Applier
        |
        +--> final mutated batch
                |
                v
          EXPOSURE_INTENT durable (host ACK)
                |
                v
              relay
```

`MutationDelta`는 최소한 다음 의미를 보존한다.

```text
MutationDelta
    schema/runtime identity
    rule_set[]
    program_generation_correlation
    append-only journal[]
        EXPOSURE_INTENT
        FORWARD_COMPLETE / FORWARD_FAILED
        GENERATION_COMPLETE
```

Crash 직전 mutation의 reproduction record가 유실되어서는 안 된다. Proxy는 crash가 일어나는
guest 안에서 실행되므로 durable 기록은 guest 밖, Runner가 소유한 host journal sink에 둔다(issue #3).
EXPOSURE_INTENT에 대한 host ACK를 받기 전에는 mutated output을 peer에 노출하지 않는다.

### 13. `[COMPONENT] Replay`

상세 계약은
[`05-mutation-delta-replay.md`](05-mutation-delta-replay.md)에 정의한다.

Replay도 별도 ad-hoc byte patcher가 아니라 같은 semantic resolution/application
경로를 사용한다. recorded rule set을 다시 설치하고 `CrashContextWindow`의 program을 순서대로
실행하며, generation 위치별로 semantic batch를 비교한다(issue #2).

```text
MutationDelta
      |
      +--> recorded CompiledMutationRule[]
      v
live replay traffic
      |
      v
RPC/NFS Decoder + Transaction Context
      |
      v
Semantic Rule Resolver
      |
      v
Edit Applier
```

Production original/mutated bytes는 evidence로 보존한다.
Replay-time current value/bytes는 live semantic record에서 다시 resolve한다.

특정 original semantic value가 반드시 같아야 하면 그 조건은 recorded rule의 typed
predicate로 표현한다. Production concrete original bytes를 implicit replay identity로
사용하지 않는다.

Replay-time Edit Applier는 새로 resolve한 current original bytes를 apply 직전에
verify한다.

Replay가 target semantic context를 찾지 못하거나 precondition을 만족하지 못하면
명시적인 replay mismatch로 보고한다.

### 14. wire capture의 위치

Raw wire capture는 Compiler의 필수 입력이 아니다.

```text
not the target architecture:

baseline capture
    -> Compiler
    -> precomputed offset/original
    -> next run mutation
```

Capture는 optional diagnostic artifact다.

```text
decoder 개발
schema 검증
mutation inspection
실패 분석
evidence 보존
```

정상 mutation path는 capture가 없어도 동작해야 한다.

### 15. Compiler와 Proxy 경계

Mutation Rule Compiler 책임:

```text
MutationRuleSet
    |
    v
semantic validation
schema target validation
rule normalization
supported mutation capability validation
    |
    v
CompiledMutationRule
```

Compiler는 다음을 하지 않는다.

```text
live field offset 계산
live original bytes 획득
runtime XID 선택
Nth-message 선택
baseline packet capture 강제
```

Proxy 책임:

```text
CompiledMutationRule
    +
live traffic
    |
    v
runtime semantic resolution
    |
    v
ResolvedMutation
```

### 16. `[RUNNER TASK]` Proxy lifecycle

rule의 **내용**은 Runner가 소유하고, rule의 **활성 구간**은 executor가 소유한다(issue #2).

```text
Stage2Campaign
    |
    +-- lane/route 준비
    +-- Proxy session 시작
    |     Runner가 Compiler가 검증한 불변 CompiledMutationRule[] 하나를 설치
    |     rule_set_id(digest)로 식별, RULESET을 host sink에 durable 기록
    |
    +-- syz-manager / scenario 실행
    |     program generation마다 (executor)
    |       BEGIN -> generation G
    |       activation(G) 요청, Proxy ACK 대기
    |       program syscall 실행
    |       deactivation(G) 요청, Proxy ACK 대기
    |       FINISH / ABORT
    |
    +-- mutation evidence / MutationDelta는 host sink에 누적
    +-- Proxy session 종료
```

rule set은 Proxy session 동안 바뀌지 않는다. rule set을 바꾸면 새 session/campaign이다.
target semantic rule은 syzlang 인자가 아니며 syzkaller가 변이시키지 않는다. Rule은 job/lane
execution lifetime 밖으로 누출되지 않는다.

eligibility:

- 새 CALL record는 activation ACK와 deactivation ACK 사이에서만 eligible하다.
- REPLY는 자기 CALL의 TransactionEntry에 기록된 generation으로 판단한다. G 안에서 시작한 CALL의
  REPLY는 drain 중에 도착해도 eligible하다([`03-transaction-context.md`](03-transaction-context.md) §5).
- managed generation이 없는 실행(comparison/hint 실행, bind 실패, remote cover 비활성)은 변조하지 않는다.
- eligible하지 않은 record는 변조 없이 relay하고 `outside_activation_window`로 센다.
- deactivation 직전에 변조된 record가 CLOSING 이후 knfsd에 도착하면 coverage 귀속을 잃는다.
  journal은 그 record를 G에 남긴다. 이 잔여 위험은 문서화된 한계다.

barrier 실패:

| 상황 | 동작 |
|---|---|
| activation ACK 없음 | program을 실행하지 않는다. activation lease를 해제하고 generation을 ABORT하며, 실행과 evidence를 `INCONCLUSIVE`로 표시한다 |
| deactivation ACK 없음 | kernel generation이 멈추지 않게 FINISH/ABORT는 진행한다. 남은 activation이 해제됐음을 확인할 때까지 그 lane에서 target mode generation을 더 실행하지 않는다 |
| orphan (BEGIN과 FINISH 사이에 program process 종료) | ABORT 전에 deactivation과 lease 해제를 시도한다 |
| 위 경우에 비활성 상태를 확인할 수 없음 | 재사용 전에 Proxy/lane을 격리하거나 재시작한다. 예: syzkaller 0008의 fail-closed runner 경로(VM/lane 재생성) |

ACK 유실은 요청 유실을 뜻하지 않는다. 그래서 activation ACK가 없을 때 rule set이 비활성이라고
가정하고 program을 실행하지 않는다.

activation endpoint는 executor 전용이다. executor가 상속한 private fd나 fuzz namespace 밖의 endpoint를
쓰며, fuzz program의 unix socket syscall로는 도달할 수 없다.

`vm_instance_id`와 channel/lane identity는 host가 기록한다. guest가 보낸 generation과 `rule_set_id`는
설치된 rule set과 현재 activation에 대조할 뿐 그대로 신뢰하지 않는다.

legacy NFSPARM arm과 target mode는 한 lane에서 동시에 활성화되지 않는다. target rule set이 설치된
동안 Proxy가 legacy arm 등록을 거부하는 것이 최종 경계이고, manager의 call filtering은 추가 방어선이다.

Proxy가 backend/client를 임의 선택하지 않는다.
Traffic scope는 Stage 1에서 선택한 route에 맞춰 Controller/Runner가 bind한다. Stage 1 harness도 같은
proxied route/topology에서 실행한다(`../02-llm-agent/05-reachability-plan.md` §12, issue #10).

### 17. Q1 / M1 / Q2 경계

Proxy는 Q1 Judge가 아니다.

```text
Q1 = generation-attributed remote KCOV
```

Proxy는 M1 evidence의 주요 producer다. Proxy와 Runner(host sink 포함)는 evidence를 만들고 봉인할 뿐
verdict를 내리지 않는다. M1 Judge는 Controller 측 validation layer에서 봉인된 evidence로 판정한다
(`../02-llm-agent/01-two-stage-agent-architecture.md` §11.1, issue #11).

M1이 검토할 최소 runtime 사실:

```text
semantic selector matched
target resolved
mutation applied
mutated record forwarding result
durable delta result
```

M1 verdict 계약은 `../02-llm-agent/01-two-stage-agent-architecture.md` §7이 소유한다
(issue #4). M1은 rule별 `APPLIED` / `NOT_APPLIED` / `INCONCLUSIVE`이고, delivery state
(`complete` / `failed` / `unknown`)는 M1과 분리된 필수 evidence다.

Q2는 crash/sanitizer Judge가 별도로 판정한다.

### 18. 현재 구현과의 관계

이 문서는 `tools/nfs-proxy`의 현재 구현을 설명하는 문서가 아니다.

현재 자산은 목표 architecture의 하위 계층으로 재사용할 수 있다.

```text
current record framing
current RPC/COMPOUND walk
current fixed/variable edit engine
current durable delta/replay
        |
        v
possible implementation substrate
```

특히 다음 성질은 유지할 가치가 있다.

```text
content-addressed matching
apply-to-all
explicit refusal
durable delta
same live/replay apply path
```

다음 current limitation은 target architecture의 제한이 아니다.

```text
precomputed byte offsets
precomputed original bytes
first-opcode-only semantic matching
opaque op-array body
mandatory baseline capture
```

필요하면 Proxy 구현을 먼저 확장한다.

초기 migration은 semantic layer를 concrete edit engine 위에 추가할 수 있다.

```text
CompiledMutationRule
        |
        v
Semantic Decoder / Resolver
        |
        v
ResolvedMutation
        |
        v
Concrete Edit Engine
        |
        v
Delta Recorder / Replay
```

NFSPARM1/2는 compatibility Layer 0, internal concrete edit representation,
legacy test/control ABI 중 하나로 남을 수 있다.
Agent-facing semantic ABI를 NFSPARM1/2와 동일하게 유지할 필요는 없다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| complete SunRPC record를 mutation unit으로 사용 | TCP fragmentation은 semantic identity가 아니며 record framing은 Proxy가 복원할 수 있음 |
| semantic rule을 live record에서 resolve | stateid/XID/session state처럼 runtime마다 달라지는 값을 baseline literal로 고정하지 않기 위함 |
| request/reply Transaction Context 유지 | response 의미가 request procedure/operation context에 의존할 수 있음 |
| XID는 runtime correlation에만 사용 | XID는 실행마다 바뀔 수 있어 durable replay identity로 부적합 |
| apply-to-all semantic matching | Nth-message ordering에 대한 replay 의존을 없앰 |
| unknown schema를 fail closed | 잘못된 field mutation을 성공으로 오인하는 M1 거짓 양성을 막음 |
| Delta는 실제 application 후 생성 | 등록된 intent와 실제 mutation을 분리해 M1 근거를 남김 |
| current NFSPARM1/2를 architecture constraint로 사용하지 않음 | 현재 byte ABI의 한계 때문에 목표 semantic design을 축소하지 않기 위함 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| NFSPARM1/2 raw offset rule을 Agent-facing ABI로 유지 | 현재 구현 재사용이 쉬움 | live original/offset을 사전에 알아야 하고 semantic intent가 byte geometry에 결합됨 | 비채택. Layer 0로는 재사용 가능 |
| baseline run에서 wire capture 후 다음 run rule compile | 구현이 단순함 | dynamic state 값이 run 사이에 바뀌며 2-pass 의존이 생김 | 비채택. capture는 diagnostic으로만 유지 |
| Nth-message / ordinal matching | 구현이 쉬움 | traffic ordering 변화에 replay가 깨짐 | 비채택 |
| Proxy 내부 random mutation | Agent 없이 넓은 mutation 가능 | candidate-specific intent와 evidence lineage가 약해짐 | 비채택 |
| live semantic resolution | dynamic record에 직접 적용 가능 | semantic decoder와 transaction context가 필요 | 채택 |

Per-op semantic schema를 생성형으로 만들지 hand-written codec으로 만들지는
decoder 상세 설계에서 재검토한다.

## 영향

### 상류

Mutation Rule Compiler는 raw byte rule 대신 `CompiledMutationRule`을 생성해야 한다.
Agent의 `MutationRuleSet`은 semantic intent를 유지할 수 있다.

### 하류

M1 Judge는 Proxy가 만든 selector-match, target-resolution, apply, forwarding,
delta durability를 독립적으로 볼 수 있어야 한다.

Replay와 Crash Report는 `MutationDelta`를 reproduction lineage로 사용한다.

### 운영

Semantic decode와 transaction state는 현재 byte-only mutation보다 CPU/memory 비용이
늘 수 있다. Context table은 connection close와 timeout에서 반드시 정리되어야 한다.

Decoder가 지원하지 않는 protocol은 byte guess로 fallback하지 않고 명시적으로
unsupported를 보고하므로 일부 campaign은 harness extension으로 block될 수 있다.

mutated record마다 `EXPOSURE_INTENT`의 host ACK를 기다리므로 guest-to-host 동기 왕복이 생긴다.
program generation마다 activation/deactivation barrier 왕복도 두 번 생긴다. 처리량 영향은 실제
manager workload에서 측정한다.

## 신뢰성 요구

가장 위험한 오류는 **거짓 양성 M1**이다.

```text
wrong field mutated
    but
Proxy reports intended field applied
```

이 오류는 Q2 crash를 잘못된 mutation intent와 연결하고 replay lineage를 오염시킨다.

따라서 semantic decode/resolution은 fail-closed를 기본으로 한다.

| 항목 | 요구 |
|---|---|
| 오류 방향 | 거짓 양성 M1을 최우선으로 방지 |
| 실패 방식 | unknown schema, ambiguous field, failed precondition은 explicit refusal |
| 관측 가능성 | decode/match/resolve/apply/delta/forward 결과를 각각 구분 |
| 재현성 | semantic selector와 transformation 의미가 run 간 유지되어야 함 |

Delta durability 실패를 mutation success로 숨기지 않는다.
Forward 실패와 mutation apply 성공도 별도 상태로 보존한다.

## 검증 오라클

Target architecture 구현은 다음 조건으로 검증한다.

```text
known RPC/NFS vector
    -> expected semantic tree + exact byte spans

matching semantic rule
    -> expected target only resolved

unknown / malformed schema
    -> no guessed edit

dynamic runtime field
    -> same semantic transform without baseline capture

applied mutation
    -> durable MutationDelta

replay
    -> same semantic resolver + mutation engine path
```

Negative oracle도 필요하다.

```text
wrong operation
wrong direction/backend/client
missing transaction context
unknown semantic field
failed precondition
```

에서는 intended mutation이 적용되었다고 보고하면 안 된다.

이 검증은 Q2 crash를 증명하지 않는다.
또한 Proxy M1 evidence는 Q1 reachability를 대신하지 않는다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| record decode 실패 | malformed RPC, unsupported protocol | decode status | passthrough/refusal 후 capability 검토 |
| response semantic decode 실패 | Transaction Context 없음 | context lookup result | correlation lifecycle 점검 |
| selector가 한 번도 match되지 않음 | scenario traffic 부재 또는 selector 오류 | selector match count | Stage 2 plan/rule 점검 |
| record는 match되지만 field resolve 실패 | schema 부족/ambiguous path | resolver status | semantic decoder 확장 |
| mutation precondition 실패 | live state가 hypothesis와 다름 | current value + precondition result | Mutation Strategy 재검토 |
| mutation apply 거부 | overlap/size/structure constraint | concrete mutation status | rule/compiler 수정 |
| delta persist 실패 | storage/runtime failure | delta durability result | mutation success로 취급하지 않음 |
| mutation 후 forward 실패 | connection/backend failure | forward result | M1과 transport failure 분리 |
| replay target 없음 | scenario drift 또는 selector mismatch | replay selector status | replay mismatch로 보고 |

## 한계와 미결 사항

- **미결:** NFS semantic schema를 generated codec으로 만들지 hand-written codec으로
  만들지 결정하지 않았다.
- **결정됨:** rule 내용은 Runner가 Proxy session마다 불변 rule set으로 설치하고, 활성 구간은
  executor가 program generation마다 ACK barrier로 정한다(§16, issue #2).
- **미결:** rule set 설치 경로와 activation/deactivation 메시지의 serialization/versioning.
- **미결:** runtime-derived `value_or_transform`의 DSL/typed representation.
- **결정됨:** write-ahead commit point `(D)`는 Runner host journal sink가 framed event append 전체를
  마친 뒤 보내는 ACK다(§12, `05-mutation-delta-replay.md`, issue #3).
- **미결:** guest-to-host journal transport 방식. 단, guest write-back cache로는 ACK를 만족할 수 없다.
- **미결:** runtime-dynamic field replay에서 exact original bytes와 semantic
  precondition의 관계.
- **미결:** transaction timeout/eviction policy와 bounded memory limits.
- **미검증:** current `tools/nfs-proxy` 중 어떤 concrete engine을 그대로 재사용할지.
- **결정됨:** raw wire capture는 Compiler의 mandatory input이 아니다.
- **결정됨:** unknown semantic layout을 raw offset guess로 fallback하지 않는다.

## 참조

- `docs/design/02-llm-agent/01-two-stage-agent-architecture.md`
- `docs/design/02-llm-agent/08-mutation-rule-set.md`
- `docs/design/02-llm-agent/04-harness-capability-spec.md`
- `tools/nfs-proxy/README.md`
- `tools/nfs-proxy/src/walk.h`
- `tools/nfs-proxy/src/delta.h`
- `tools/nfs-proxy/src/edit.h`
- `bundle/patches/syzkaller/0017-*`
- `bundle/patches/syzkaller/0019-*`

## Agent 사용 지침

### 지원 범위

이 문서는 **target architecture**를 정의한다.
현재 Agent가 실제 실행에서 사용할 수 있는 범위는 Harness Capability Specification에서
`validated` 또는 명시된 부분 검증 상태로 등록된 capability만이다.

목표 semantic interface는 다음 intent를 표현한다.

```text
direction / route scope
RPC/NFS semantic selector
semantic field path
replace / insert / delete / op_append / op_prepend
literal / live-derived / transaction-derived value transform
```

### 비지원 범위

구현된 decoder/schema가 없는 semantic field는 지원된 것으로 가정하지 않는다.

```text
unknown schema
    -> raw offset guess 금지
    -> unsupported semantic resolution
```

Current capability가 target rule을 표현하지 못하면
`HarnessGapIssue(gap_class=mutation_engine)`로 block한다.

### 확장 절차

Semantic Proxy 기능을 구현할 때는 최소 다음을 함께 검토한다.

```text
semantic decoder/schema
Transaction Context
semantic rule ABI
resolver
concrete mutation engine mapping
MutationDelta / replay
Harness Capability Specification
tests / guest validation
```

기능을 구현했다는 이유만으로 HCAP을 validated로 올리지 않는다.
실제 guest/runtime 검증 뒤 capability status를 갱신한다.

### 제약

```text
ordinal/Nth-message identity 금지
runtime XID를 replay identity로 사용 금지
unknown field offset 추측 금지
apply-to-all semantics 기본
Q1/M1/Q2 evidence 분리
candidate run 중 silent harness source modification 금지
```

### 검증 방법

Agent가 생성한 semantic rule은 먼저 Compiler/Proxy schema validation을 통과해야 한다.
그 다음 live execution에서 selector match, target resolution, mutation application,
delta durability가 관측되어야 M1 후보 evidence가 된다.

Parser가 rule을 받아들였다는 사실이나 control ACK만으로 mutation application을
성공으로 판정하지 않는다.

## 다음 상세 설계 순서

Proxy 내부는 다음 순서로 한 요소씩 고정한다.

```text
1. [`Semantic Decoder contract`](02-semantic-decoder.md) — detailed contract fixed
2. [`Transaction Context contract`](03-transaction-context.md) — detailed contract fixed
3. [`Semantic Mutation Rule runtime contract`](04-semantic-mutation-runtime.md) — detailed contract fixed
4. [`MutationDelta / Replay contract`](05-mutation-delta-replay.md) — detailed contract fixed
5. [`Implementation gap analysis`](06-implementation-gap-analysis.md) — current-vs-target mapping fixed
6. Proxy implementation
```

그 후 Agent 설계로 돌아가 다음을 고정한다.

```text
Mutation Rule Compiler
MutationEvidence / M1 Judge
CrashEvidence / Q2 Judge
```
