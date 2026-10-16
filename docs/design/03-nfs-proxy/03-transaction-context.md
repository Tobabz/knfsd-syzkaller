# NFS Proxy Transaction Context Contract

> 상태: draft · 최종 확인: 2026-10-12
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82

> 상위 설계: `01-architecture.md`
> 선행 계약: `02-semantic-decoder.md`
> 관련 구현: `tools/nfs-proxy/src/proxy.c`, `tools/nfs-proxy/src/proxy.h`
> 관련 게이트: Stage 2 semantic response resolution / M1 target resolution

## 요약

Transaction Context는 live RPC CALL과 그 REPLY를 같은 Proxy connection 안에서
안전하게 연결하는 runtime 컴포넌트다. Key는
`connection_id + call_direction + XID`이며 request의 procedure와 NFS semantic
summary를 bounded lifetime 동안 보존해 response Decoder/Resolver에 제공한다.
잘못된 correlation은 다른 request의 의미를 reply에 붙여 M1 거짓 양성을 만들 수
있으므로 ambiguous reuse는 fail closed 한다.

## 해결하려는 문제

RPC REPLY에는 원래 CALL의 모든 dispatch metadata가 반복되지 않는다.

특히 NFSv3 REPLY는 XID만으로는 어떤 NFS procedure의 result schema인지 결정할 수
없다.

```text
CALL
    XID=100
    NFSv3 WRITE
        |
        v
    request metadata
        |
        ?          REPLY
        +--------> XID=100
                   procedure 없음
```

NFSv4에서도 COMPOUND result 자체가 operation discriminant를 포함하지만,
request operation sequence, minor version, request-side semantic value가 필요한
consistency check와 mutation predicate가 있다.

또한 NFSv4.1+ session backchannel에서는 같은 TCP connection에서 다음 두 방향의
RPC transaction이 동시에 존재할 수 있다.

```text
forechannel:
    C2S CALL  XID=7
    S2C REPLY XID=7

backchannel:
    S2C CALL  XID=7
    C2S REPLY XID=7
```

따라서 `connection + XID`만 key로 사용하면 두 RPC caller의 XID namespace가
충돌할 수 있다.

Current `tools/nfs-proxy`는 accepted client socket과 backend socket을
`struct conn`으로 묶고 `client/backend` route를 보존하지만 transaction
correlation state는 없다. Target architecture는 fd나 `conns[]` slot을 durable
identity로 사용하지 않고 logical live connection identity를 별도로 제공해야 한다.

## 구조

```text
  +---------------------- NFS Proxy -----------------------+
  |                                                       |
  |  [Connection Registry]                                |
  |        | ConnectionRef                                |
  |        v                                              |
  |  RPC CALL ---->[Transaction Context] (T)              |
  |       |          | insert/enrich                      |
  |       |          v                                    |
  |       |      TransactionEntry                         |
  |       |          ^                                    |
  |       |          | lookup                             |
  |  RPC REPLY ------+                                    |
  |                  | context                            |
  |                  v                                    |
  |          [NFS Semantic Decoder]                       |
  |                  | DecodedRpcMessage                  |
  |                  v                                    |
  |          Semantic Rule Resolver                       |
  +-------------------------------------------------------+
```

`(T)`=runtime correlation correctness 관측 지점.
CALL은 context를 만들고 REPLY는 반대 CALL direction의 key를 조회한다.

## 설계

### 1. 요소 분류와 소유권

```text
[DATA] ConnectionRef
    Produced by:   Proxy connection lifecycle
    Consumed by:   Transaction Context / Decoder / evidence
    Lifetime:      one live proxied transport connection

[DATA] TransactionKey
    Produced by:   Transaction Context
    Fields:        connection_id + call_direction + xid
    Durable ID:    NO

[DATA] TransactionEntry
    Produced by:   Transaction Context
    Consumed by:   NFS Semantic Decoder / Semantic Rule Resolver
    Lifetime:      bounded runtime state

[COMPONENT] Transaction Context
    Runs at:       Proxy runtime
    Input:         RPC envelope events + decoded request metadata
    Output:        TransactionEntry lookup result / lifecycle diagnostics
    Mutates wire:  NO
```

Transaction Context는 mutation rule selection, wire mutation, replay identity,
vulnerability reasoning을 소유하지 않는다.

### 2. ConnectionRef

한 proxied bidirectional transport connection에는 runtime-only opaque ID를 부여한다.

```text
ConnectionRef
    connection_id

    route
        client
        backend

    transport
        protocol: tcp
        role?
            forechannel
            callback
            unknown

    lifecycle
        opened
        closed?
```

`connection_id`의 요구 조건:

```text
unique within one Proxy process/job
new TCP connection -> new connection_id
slot/fd reuse -> connection_id reuse 금지
runtime-only -> replay identity 아님
```

현재 구현의 `client_fd`, `backend_fd`, `conns[]` index, client/backend pair 자체는
`connection_id`가 될 수 없다. 이 값들은 reuse될 수 있거나 같은 route에 여러
connection이 동시에 존재할 수 있다.

구현(M1)은 `connection_id`를 Proxy 실행마다 1부터 시작하는 64-bit 단조 증가 카운터로 정했다.
accept할 때 하나를 할당하고 slot이나 fd에서 유도하지 않는다. 0은 할당되지 않은 slot을 뜻하므로
ID로 쓰지 않는다. 64-bit라 한 실행 안에서 wrap에 도달할 수 없다고 보고 wrap 처리는 두지 않는다.
실행마다 다시 1부터 시작하므로 Proxy process 경계를 넘는 identity로는 쓸 수 없고, 이는 위의
runtime-only 요구와 같다. 구현은 `tools/nfs-proxy/src/proxy.c`의 `next_connection_id`와
`tools/nfs-proxy/src/rpc_record.h`의 `struct nfsp_connection_ref`이고, slot을 재사용한 연결이
새 ID를 받는지는 `tools/nfs-proxy/test/test_proxy.c`의 `test_connection_id_not_reused`가 확인한다.

### 3. TransactionKey

TransactionKey는 **CALL을 보낸 방향**을 포함한다.

```text
TransactionKey
    connection_id
    call_direction
        C2S
        S2C
    xid
```

CALL이면:

```text
key.call_direction = record.direction
```

REPLY이면:

```text
key.call_direction = opposite(record.direction)
key.xid            = reply.xid
```

따라서 같은 connection에서 다음은 서로 다른 transaction이다.

```text
C2S CALL xid=7 -> (conn-A, C2S, 7)
S2C CALL xid=7 -> (conn-A, S2C, 7)
```

### 4. 왜 call_direction이 필요한가

NFSv4.1+ backchannel은 forechannel connection을 양방향 RPC transport로 사용한다.

```text
NFS client                     NFS server
    |                              |
    |--- CALL -------------------->|  forechannel request
    |<-- REPLY --------------------|
    |                              |
    |<-- CALL ---------------------|  backchannel callback
    |--- REPLY ------------------->|
```

양쪽 RPC caller는 각각 XID를 선택하므로 XID가 connection 전체에서 globally
unique하다고 가정하지 않는다.

### 5. TransactionEntry

```text
TransactionEntry
    key: TransactionKey

    rpc
        program
        version
        procedure

    protocol
        family?
        nfs_version?
        minor_version?

    request
        original                       # client가 보낸 CALL
            semantic_decode_status?
            operation_sequence[]
            semantic_context[]
        forwarded                      # peer 노출로 선택한 CALL (§6)
            original과 같음 | decoded view | undecodable

    activation_generation?

    lifecycle
        state
            awaiting_reply
            replied
            ambiguous
            expired

        created_at_monotonic
        last_seen_at_monotonic
        reply_seen_at_monotonic?

    diagnostics
        duplicate_call_count
        ambiguity_reason?
        expiry_reason?
```

`semantic_context[]`는 response decode나 active semantic rule이 실제로 필요로 하는
typed request metadata를 뜻한다. 모든 request packet을 무조건 장기간 보존하는
계약은 아니다.

entry는 `activation_generation`도 가진다. CALL을 관측한 시점에 그 lane에서 활성화된 program
generation이며, activation 창 밖에서 관측한 CALL은 값이 없다. REPLY의 mutation eligibility는 이
값으로 판단한다. 그래서 G 안에서 시작한 CALL의 REPLY는 deactivation 뒤 drain 중에 도착해도 G의
rule set으로 처리하고, 창 밖 CALL의 REPLY는 변조하지 않는다(`01-architecture.md` §16, issue #2).

drain은 G의 closure에서 끝난다(`01-architecture.md` §16, issue #18 F1). closure 뒤에 도착한 G entry의
REPLY는 변조하지 않는다. `activation_generation`은 entry가 끝날 때까지 바뀌지 않으며, 같은 lane에서
G+1이 활성화돼도 G+1로 다시 쓰지 않는다. closure summary에 쓰도록 Transaction Context는 G entry가
어떻게 끝났는지를 구분한다. `replied`와 `expired(connection_closed)`는 REPLY를 놓친 것이 아니다.
그 밖의 `expired`(timeout, capacity reclaim)와 closure 때 남은 `awaiting_reply`는 REPLY를 G로 처리하지
못한 entry다.

### 6. CALL 관측 순서

CALL은 두 단계로 context에 반영될 수 있다.

```text
RPC Decoder
    |
    | valid CALL envelope
    v
Transaction Context
    |
    +--> minimal TransactionEntry
    |       rpc program/version/procedure
    |
    v
NFS Semantic Decoder
    |
    | decoded request summary
    v
Transaction Context
    |
    +--> entry enrichment
```

이 순서는 circular dependency를 피한다.

NFSv3 response schema 선택에 필요한 `procedure`는 NFS request body semantic decode가
실패해도 valid RPC CALL envelope에서 보존할 수 있다.

반대로 request semantic predicate가 필요한 response mutation은 request decode가
성공해 해당 metadata가 entry에 attach된 경우에만 사용할 수 있다.

CALL에 semantic mutation이 적용될 수 있으면 entry는 두 request view를 가진다(issue #7).
`request.forwarded`는 peer에 실제로 노출하도록 선택한 CALL이다.

```text
receive CALL
    -> request.original decode / 저장
    -> 바뀌지 않은 RPC key로 TransactionEntry insert
    -> Resolver / Edit Applier가 mutated record 후보를 만든다

mutation 없음
    request.forwarded = request.original
    original relay

mutation 있음
    mutated record build / verify
    -> EXPOSURE_INTENT를 host sink에 append하고 ACK (D)를 기다린다

    ACK 성공
        mutated record를 노출할 record로 선택
        final mutated payload를 한 번 decode
            성공 -> request.forwarded = decoded final request
            허용된 raw mutation으로 decode 실패 -> request.forwarded = undecodable
        선택한 mutated bytes relay

    ACK 없음 / event 거부 / durability 실패
        mutated output을 노출하지 않는다 (`05` §11, issue #3)
        original을 변조 없이 relay
        request.forwarded = request.original
```

이후 socket 실패는 선택된 view를 바꾸지 않고 delivery evidence에만 영향을 준다. RPC envelope는
변조하지 않으므로(`02` §9) transaction key와 NFSv3 reply schema 선택은 두 view에서 같다.

### 7. REPLY lookup

REPLY가 오면 RPC Decoder가 다음을 제공한다.

```text
connection_id
record.direction
xid
reply status
```

Transaction Context는:

```text
call_direction = opposite(record.direction)

lookup(
    connection_id,
    call_direction,
    xid
)
```

를 수행한다.

결과:

```text
found
missing
ambiguous
expired
```

`found`만 context-dependent semantic resolution에 사용할 수 있다.

### 8. NFSv3 response context

NFSv3 response에서는 Transaction Context가 schema dispatch에 직접 필요하다.

```text
C2S CALL
    rpc.version = 3
    procedure = WRITE
    xid = X
       |
       v
TransactionEntry
       |
       v
S2C REPLY xid = X
       |
       v
WRITE3res schema
```

Entry가 없거나 ambiguous하면 procedure-specific reply field를 추측하지 않는다.

Decoder는 `transaction_context_missing` 또는 ambiguity reason을 명시적으로 남긴다.

### 9. NFSv4 COMPOUND context

NFSv4 request에서 최소 다음 metadata를 보존한다.

```text
minor_version
operation_sequence[]
```

Response decode에서는 wire result discriminant를 우선 해석하고 server가 실제로 받은
`request.forwarded` summary를 consistency context로 사용한다. `forwarded`가 undecodable이면
request-dependent 검증과 predicate를 쓰지 않는다(§6).

검증할 수 있는 항목:

```text
request/result operation compatibility
minor-version compatibility
early COMPOUND failure
shortened result array
request-side semantic predicate dependency
```

Response가 request보다 짧다는 사실 자체는 오류가 아니다. NFSv4 COMPOUND는
operation failure 뒤 남은 operation을 실행하지 않을 수 있으므로 protocol-valid
early termination을 허용한다.

### 10. callback / backchannel

Transaction Context는 다음 개념을 분리한다.

```text
wire direction
    C2S / S2C

RPC message type
    CALL / REPLY

transport role
    forechannel / callback / unknown
```

#### NFSv4.1+

Backchannel CALL은 같은 forechannel TCP connection의 S2C traffic일 수 있다.

```text
S2C CALL
    -> key(call_direction=S2C)

C2S REPLY
    -> lookup(call_direction=S2C)
```

#### NFSv4.0

서버 callback은 별도 TCP connection을 사용할 수 있다.
그 connection이 Proxy를 통과한다면 별도 `connection_id`를 부여해 처리한다.

Current `tools/nfs-proxy`가 reverse callback connection을 실제 proxy하는지는
이 contract가 지원 사실로 가정하지 않는다. 필요한 routing이 없으면 별도
harness/Proxy extension 대상이다.

### 11. duplicate CALL과 XID reuse

동일 key가 `awaiting_reply` 상태인데 새 CALL이 오면 무조건 overwrite하지 않는다.

```text
same key + equivalent CALL
    -> retransmission/duplicate observation
    -> existing entry 유지

same key + materially different CALL
    -> ambiguous
    -> semantic correlation fail closed
```

"equivalent" 판정은 downstream response semantics에 영향을 줄 수 있는 request
metadata가 동일함을 요구한다. client가 보낸 `request.original`끼리 비교한다.

Implementation은 필요하면 complete request fingerprint를 사용할 수 있다.
그 fingerprint는 duplicate detection용 runtime data이며 replay identity가 아니다.

### 12. completed XID reuse

기존 entry가 이미 `replied` 상태이고 같은 key의 새 CALL이 오면 새 transaction으로
재사용할 수 있다.

```text
old replied transaction
    -> retire/supersede

new CALL with same XID
    -> new TransactionEntry
```

XID 자체에 generation semantics를 부여하지 않는다.

### 13. unexpected / late REPLY

Entry가 없는 REPLY는 새 context를 만들지 않는다.

```text
REPLY without live matching CALL
    -> context_missing
```

가능한 원인:

```text
Proxy가 CALL 중간에 attach됨
entry timeout/eviction
connection lifecycle bug
unsupported callback path
late/duplicate reply
```

REPLY schema 선택에는 이 entry가 공급하는 dispatch identity가 필요하다(`02-semantic-decoder.md` §6). NFSv4
result discriminant를 wire에서 읽을 수 있어도 entry가 없으면 Decoder는 `decoded` field나 WireRef를 만들지
않고 진단만 남긴다(issue #18 F4).

### 14. connection close

ConnectionRef가 closed 상태가 되면 그 connection의 transaction state를 전부 정리한다.

```text
connection close
    |
    +--> awaiting_reply -> expired(connection_closed)
    +--> replied        -> retired
    +--> ambiguous      -> retired
```

Half-close는 곧바로 전체 context를 폐기하는 조건이 아니다.
한 방향 EOF 뒤에도 반대 방향의 pending reply가 전달될 수 있으므로 logical
connection이 완전히 종료될 때 정리한다.

### 15. timeout

모든 live entry는 finite lifetime을 가진다.

Timeout은 monotonic clock을 사용한다.

이 문서에서는 구체적인 milliseconds를 정하지 않는다. 적절한 값은 real NFS
workload, callback delay, fuzz slowdown을 측정한 뒤 구현에서 정한다.

정책 요구:

```text
finite timeout 존재
expiry reason 관측 가능
late reply를 wrong context와 연결하지 않음
```

### 16. capacity / bounded memory

Transaction Context memory는 bounded여야 한다.

최소 정책:

```text
per-connection outstanding bound
global outstanding bound
completed-entry retention bound
semantic_context size bound
```

구체적인 숫자는 미결이다.

Capacity pressure에서 오래된 active entry를 조용히 다른 request로 overwrite하지 않는다.

권장 failure semantics:

```text
safe expired/completed entry
    -> reclaim 가능

no reclaimable slot
    -> context_capacity_exhausted
    -> unmutated relay는 계속 가능
    -> context-dependent mutation은 fail closed
```

Transaction Context resource failure가 arbitrary traffic corruption이나 false-positive M1로
이어지지 않게 한다.

### 17. completed entry retention

REPLY 관측 직후 entry를 즉시 잊어야 할 필요는 없다. 짧고 bounded된
completed-retention 상태는 duplicate reply, late bookkeeping, M1 evidence
correlation 진단에 유용할 수 있다.

정확한 retention duration은 구현/측정 후 정한다.
새 CALL이 동일 key를 정당하게 reuse하면 completed old entry는 supersede될 수 있다.

### 18. semantic_context retention

`semantic_context[]`는 모든 decoded field를 무조건 복사하는 저장소가 아니다.

```text
response schema/consistency에 필요한 metadata
active CompiledMutationRule의 response predicate에 필요한 request values
```

어떤 field가 rule dependency인지 결정하는 exact typed interface는
`Semantic Mutation Rule runtime contract`가 소유한다.

### 19. TransactionEntry와 replay

다음 값은 runtime correlation data다.

```text
connection_id
call_direction
xid
activation_generation
created_at
table slot
duplicate count
```

이 값을 durable mutation identity로 사용하지 않는다.

```text
runtime correlation key
    !=
replay identity
```

replay도 같은 view 규칙을 따른다. production과 replay의 response rule은 같은 이름의 view
(`request_forwarded` / `request_original`)를 평가한다(issue #7).

### 20. event-loop ordering

Current Proxy implementation은 `on_record`와 control IPC를 같은 event loop에서 처리한다.
Target Transaction Context도 deterministic record ordering을 유지한다.

```text
Record Framer
    |
    v
RPC Decoder
    +-- CALL --> context minimal insert
    |
    v
NFS Semantic Decoder
    +-- CALL --> context enrichment
    +-- REPLY <- context lookup
    |
    v
Semantic Rule Resolver
```

### 21. failure/result model

```text
inserted
enriched
duplicate_equivalent
found
missing
ambiguous
expired
capacity_exhausted
connection_closed
```

이 결과는 M1 자체가 아니다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| connection-scoped key 사용 | 같은 XID는 다른 TCP connection에서 독립적으로 나타날 수 있음 |
| call_direction을 key에 포함 | v4.1+ backchannel에서 같은 connection 양쪽이 RPC CALL caller가 될 수 있음 |
| fd/slot을 connection identity로 쓰지 않음 | close/reuse 후 다른 transport를 같은 transaction namespace로 오인할 수 있음 |
| CALL envelope에서 minimal entry를 먼저 생성 | NFSv3 procedure는 body decode 실패와 무관하게 REPLY schema 선택에 필요 |
| request decode 후 context enrich | response predicate에 필요한 typed semantic metadata를 보존하기 위함 |
| duplicate outstanding key를 overwrite하지 않음 | wrong request metadata가 reply에 붙는 false-positive correlation 방지 |
| connection close에서 state purge | XID namespace를 reconnect 사이에 공유하지 않기 위함 |
| finite timeout/capacity | fuzz input이 unbounded state를 만들지 못하게 함 |
| capacity failure에서 mutation fail closed | relay pressure를 wrong semantic mutation으로 바꾸지 않기 위함 |
| runtime key를 replay identity로 사용하지 않음 | connection/XID는 run마다 달라질 수 있음 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| global XID table | 구현 간단 | 여러 connection의 같은 XID 충돌 | 비채택 |
| connection + XID | forechannel에 충분 | same connection backchannel CALL namespace 충돌 가능 | 비채택 |
| connection + call direction + XID | 양방향 RPC caller 분리 | connection identity 관리 필요 | 채택 |
| fd + XID | current code와 연결 쉬움 | fd reuse가 identity reuse를 만듦 | 비채택 |
| full request packet 장기 보존 | 모든 predicate 재구성 쉬움 | memory cost, retention 범위 과대 | 비채택 |
| 필요한 typed request context만 보존 | bounded semantic correlation | dependency contract 필요 | 채택 |
| context miss 시 byte heuristic | mutation 기회 유지 | wrong response schema/M1 거짓 양성 | 비채택 |
| context capacity 초과 시 connection drop | semantics 안전 | baseline traffic를 불필요하게 깨뜨림 | 기본 비채택; unmutated relay + semantic refusal 선호 |

Connection teardown 자체가 실험 목표인 별도 rule이라면 transport failure 정책은
Semantic Mutation Rule runtime contract에서 재검토할 수 있다.

## 영향

### 상류

Proxy connection lifecycle은 stable runtime `ConnectionRef`를 제공해야 한다.
RPC Decoder는 CALL/REPLY, XID, program/version/procedure를 정확히 제공해야 한다.

NFS Semantic Decoder는 CALL decode 후 response에 필요한 semantic summary를
Transaction Context에 attach할 수 있어야 한다.

### 하류

NFSv3 response Decoder는 TransactionEntry 없이는 procedure-specific result를
mutation-safe하게 해석할 수 없다.

NFSv4 Resolver는 request operation sequence와 request-side predicates를
TransactionEntry에서 참조할 수 있다.

잘못된 correlation은 wrong field mutation과 false-positive M1로 직접 이어질 수 있다.

### 운영

Outstanding RPC 수에 비례한 bounded runtime memory가 필요하다.
Timeout, duplicate detection, completed retention은 CPU/memory overhead를 추가하지만
wire packet capture 전체를 보존하는 것보다 작게 유지해야 한다.

Context table은 Proxy process/job 밖으로 persistence하지 않는다. transaction 사이의 state lineage도
보존하지 않는다(초기 runtime 범위 밖, `04` §12, issue #6).

## 신뢰성 요구

가장 위험한 오류는 **거짓 양성 correlation**이다.

```text
REPLY X
    matched to
wrong CALL X
```

| 항목 | 요구 |
|---|---|
| 오류 방향 | wrong CALL/REPLY match의 false positive를 최우선 방지 |
| 실패 방식 | duplicate conflict, ambiguity, missing context는 semantic fail closed |
| 관측 가능성 | insert/find/miss/ambiguous/expiry/capacity counters와 reason 필요 |
| 재현성 | 동일 record ordering에서는 동일 lifecycle/result를 내야 함 |

Relay 자체는 context miss에서 항상 connection을 끊을 필요가 없다.
하지만 context-dependent mutation은 context가 불확실하면 적용하지 않는다.

## 검증 오라클

### 1. 기본 CALL -> REPLY

```text
C2S CALL xid=A
S2C REPLY xid=A
```

Expected:
- one entry inserted;
- reply finds same entry;
- rpc procedure/request summary intact;
- reply transitions entry to `replied`.

### 2. out-of-order REPLY

```text
CALL xid=A
CALL xid=B
REPLY xid=B
REPLY xid=A
```

둘 다 올바른 entry를 찾아야 한다.

### 3. same XID on different connections

```text
conn-A: CALL xid=7
conn-B: CALL xid=7
```

reply가 서로 섞이면 실패다.

### 4. same XID on opposite CALL directions

```text
conn-A C2S CALL xid=7
conn-A S2C CALL xid=7
```

두 개의 독립 entry가 생성되어야 한다.
이 검사는 v4.1+ backchannel key correctness의 핵심 negative control이다.

### 5. duplicate equivalent CALL

같은 live key와 equivalent request가 reply 전에 다시 오면 새 entry로 overwrite하지 않고
duplicate count만 증가해야 한다.

### 6. duplicate conflicting CALL

같은 live key에 materially different request가 reply 전에 오면:

```text
state = ambiguous
```

이후 reply에 context-dependent semantic mutation을 허용하면 실패다.

### 7. unknown XID REPLY

entry 없는 reply는 `missing`이어야 한다.
임의의 최근 request나 route-level context와 연결하면 실패다.

### 8. connection close / slot reuse

old connection을 close하고 같은 implementation slot/fd가 재사용되어도
new connection은 new `connection_id`를 가져야 한다.

Old transaction을 찾으면 실패다.

### 9. timeout

entry가 configured lifetime 뒤 expired가 되고 late REPLY가 old semantic context를
사용하지 않아야 한다.

### 10. capacity exhaustion

bounded capacity를 채운 뒤:
- existing live entries가 silent overwrite되지 않음;
- new context failure가 observable;
- context-dependent mutation이 fail closed.

### 11. NFSv3 reply schema recovery

NFSv3 WRITE CALL context로 WRITE reply를 decode할 수 있어야 한다.
동일 XID의 READ context를 잘못 붙이면 oracle 실패다.

### 11a. reply dispatch 없음

NFSv4 COMPOUND REPLY를 matching CALL 없이, 또는 COMPOUND header decode에 실패한 CALL 뒤에 보낸다.

Expected:
- entry가 없으면 `transaction_context_missing`, `minor_version`이 없으면 `dispatch_incomplete`다;
- result shape가 그럴듯하게 parse돼도 `decoded`나 mutation-safe WireRef가 없다;
- matching CALL이 있으면 그 dispatch의 schema로 decode한다.

### 12. NFSv4 early COMPOUND failure

Request op sequence가 여러 op이어도 early result termination을 protocol-valid하게
해석해야 한다.

### 13. callback/backchannel

Same connection에서:

```text
C2S CALL / S2C REPLY
S2C CALL / C2S REPLY
```

를 동시에 실행해 independent context를 유지해야 한다.

### 14. C2S operation-array mutation 뒤 request view

C2S rule이 COMPOUND에 operation을 추가하고, S2C rule이 request predicate를 쓴다.

Expected:
- `request_forwarded`를 쓰는 S2C rule은 추가된 operation을 포함한 최종 sequence에 bind한다;
- 같은 rule이 `request_original`을 쓰면 변조 전 sequence를 본다;
- 의도적 raw mutation으로 forwarded request가 undecodable이면 request-dependent S2C rule은 거부한다;
- exposure ACK가 없으면 `forwarded`는 `original`과 같다.

이 검증은 Q1이나 Q2를 증명하지 않는다.
Transaction Context가 correct request/reply semantic context를 공급함만 증명한다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| reply context missing | CALL 미관측, timeout, route gap | miss reason + connection lifecycle | path/lifetime 확인 |
| wrong procedure decode | key collision/corruption | key + stored RPC metadata | Transaction Context bug |
| opposite-direction XID collision | call_direction 미포함 | same conn/xid, two CALL directions | key contract 수정 |
| duplicate call ambiguous | XID reuse before reply | stored/new request summary | semantic mutation 거부 |
| stale context after reconnect | fd/slot identity reuse | connection_id lifecycle | ConnectionRef bug |
| entries 계속 증가 | timeout/close cleanup 실패 | active/expired counters | lifecycle cleanup 수정 |
| capacity exhausted | workload burst/leak | per-conn/global counts | bound/lifetime 검토 |
| NFSv3 reply undecodable | context missing/wrong procedure | transaction lookup status | CALL capture 확인 |
| backchannel reply mismatch | direction assumption 오류 | RPC type + wire direction | caller-direction logic 수정 |

## 한계와 미결 사항

- **결정됨:** transaction key는 `connection_id + call_direction + xid`다.
- **결정됨:** XID와 connection ID는 durable replay identity가 아니다.
- **결정됨:** fd와 `conns[]` slot은 ConnectionRef identity가 아니다.
- **결정됨:** NFSv3 response schema dispatch는 live request context를 요구한다.
- **결정됨:** same connection의 opposite CALL directions는 독립 XID namespace다.
- **결정됨:** ambiguous duplicate/reuse는 semantic mutation에 fail closed 한다.
- **결정됨:** entry는 `request.original`과 peer 노출로 선택한 `request.forwarded`를 함께 가진다.
  response decode와 consistency 검증은 `forwarded`를 쓴다(issue #7).
- **결정됨:** context memory/lifetime은 bounded여야 한다.
- **결정됨:** full raw request 장기 보존은 기본 계약이 아니다.
- **결정됨:** `connection_id`는 Proxy 실행마다 1부터 시작하는 64-bit 단조 증가 카운터다(§2, M1).
- **결정됨(M3 초기값):** outstanding 4096(global) / 1024(per connection), completed retention
  1024 entries · 10 s, timeout 300 s(마지막 CALL 관측 기준, monotonic clock). 고정 pool을 한 번
  할당하고 retained entry만 회수한다(`tools/nfs-proxy/src/txn.h`). 실제 workload peak로 재검토한다.
- **결정됨:** request equivalence는 `rpc_payload` 전체 bytes의 독립 64-bit hash 두 개와 길이로
  판정한다. 같으면 retransmission, 다르면 ambiguous다(§11). Runtime 판정용이며 identity가 아니다.
- **결정됨:** request summary는 `minor_version`과 operation opcode 배열(최대 256)이다. request
  decode가 `decoded`/`partial`일 때만 저장·제공한다.
- **결정됨(M4 전):** legacy `on_record` rewrite hook이 있으면 `request.forwarded`는 unknown이다.
  그 rewrite는 minor version이나 procedure도 바꿀 수 있으므로, REPLY에 dispatch도 request summary도
  주지 않는다(`transaction_context_missing`). 없으면 `forwarded = original`이다.
- **결정됨:** §12의 재사용은 정상 응답(`replied`)으로 끝난 key에만 허용한다. `expired`나
  `ambiguous`로 끝난 key가 retained 상태인 동안 들어온 새 CALL은 key를 ambiguous로 유지하고
  retention을 다시 시작한다. 옛 CALL의 늦은 REPLY가 새 CALL의 context를 얻지 않게 하기 위해서다.
- **미결:** rule dependency에 따른 `semantic_context[]` exact typed representation.
- **미결:** callback/backchannel routing의 initial current-implementation coverage.
- **미검증:** real manager workload의 outstanding transaction peak와 retention 요구량.

## 참조

- `docs/design/03-nfs-proxy/01-architecture.md`
- `docs/design/03-nfs-proxy/02-semantic-decoder.md`
- `docs/design/02-llm-agent/04-harness-capability-spec.md`
- `tools/nfs-proxy/src/proxy.h`
- `tools/nfs-proxy/src/proxy.c`
- `tools/nfs-proxy/README.md`
- `report/normal-flow-corpus.md`
- `report/normal-flow-threads.md`

## Agent 사용 지침

### 지원 범위

Transaction Context는 Agent가 직접 생성하는 데이터가 아니다.

Agent가 response semantic selector를 사용할 때 current harness가 지원한다고
간주하려면 다음이 검증되어야 한다.

```text
target traffic가 Proxy를 통과
ConnectionRef 생성 가능
CALL/REPLY correlation 구현 존재
필요한 request semantic context 보존
guest/runtime validation 완료
promoted semantic capability registry scope에 포함
```

registry와 promotion 규칙은 `../02-llm-agent/04-harness-capability-spec.md` §4가 소유한다(issue #14).

### 비지원 범위

다음 상황에서 Agent가 transaction correlation을 가정하지 않는다.

```text
Proxy를 통과하지 않는 callback connection
missing/ambiguous/expired context
지원되지 않는 callback/backchannel routing
rule dependency field를 보존하지 않는 implementation
```

필요한 Stage 2 selector가 이를 요구하면:

```text
unsupported_by_current_harness
    -> HarnessGapIssue
       gap_class = mutation_engine
```

### 확장 절차

M3 구현 위치:

```text
tools/nfs-proxy/src/txn.{h,c}        Transaction Context table (key, state, bounds, lifecycle)
tools/nfs-proxy/src/semantic.{h,c}   on_rpc_record / on_connection observer:
                                     RPC Decoder -> txn -> NFS Semantic Decoder -> enrichment
tools/nfs-proxy/src/main.c           --semantic (observe only, counters in stats output)
tools/nfs-proxy/test/test_txn.c      oracle 1-10 (+ supersede, random model check)
tools/nfs-proxy/test/test_semantic.c oracle 11 (NFSv3), 11a, 12, 13 (NFSv4), forwarded unknown, lifecycle
tools/nfs-proxy/test/test_nfs3_decode.c  NFSv3 reply decode under its CALL's procedure only (oracle 11)
```

Oracle 14는 Resolver(M4)가
`request.forwarded`를 채울 때 검증한다. `activation_generation`은 M4 전까지 0이다.

변경 시 최소 다음을 함께 변경/검증한다.

```text
Proxy connection lifecycle
RPC record callback context
Transaction Context table
NFS Semantic Decoder integration
semantic rule dependency retention
host unit tests
guest/runtime validation
Harness Capability Specification
```

파일/심볼이 바뀌면 위 경로 목록을 갱신한다.

### 제약

```text
connection_id + call_direction + xid
XID-alone lookup 금지
fd/slot durable identity 금지
ambiguous context guess 금지
context miss에서 semantic mutation 금지
bounded memory / finite lifetime
Q1/M1/Q2 evidence 분리
```

### 검증 방법

Agent-facing response semantic mutation capability는 최소 다음을 통과해야 한다.

```text
normal CALL/REPLY correlation
out-of-order reply
same XID on different connections
same XID on opposite CALL directions
duplicate/reuse ambiguity
connection close/reconnect
timeout/capacity
NFSv3 response decode
NFSv4 backchannel correlation
```

Control registration이나 isolated Decoder unit test만으로 capability를 validated로
올리지 않는다.

## 다음 상세 설계

이 contract 이후 순서는 다음과 같다.

```text
1. [`Semantic Mutation Rule runtime contract`](04-semantic-mutation-runtime.md) — detailed contract fixed
2. [`MutationDelta / Replay contract`](05-mutation-delta-replay.md) — detailed contract fixed
3. [`Implementation gap analysis`](06-implementation-gap-analysis.md) — current-vs-target mapping fixed
4. Proxy implementation
```
