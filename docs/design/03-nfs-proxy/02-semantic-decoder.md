# NFS Semantic Decoder Contract

> 상태: draft · 최종 확인: 2026-10-13
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82
> 상위 설계: 01-architecture.md
> 관련 구현: tools/nfs-proxy/schema/normalize.py, tools/nfs-proxy/src/schema.h, tools/nfs-proxy/src/nfs_decode.h (M2), legacy tools/nfs-proxy/src/walk.h
> 관련 입력 shape: syzkaller 0006/0015
> 관련 게이트: Stage 2 M1 target resolution

## 요약

NFS Semantic Decoder는 complete RPC record를 versioned NFS schema로 해석해
stable semantic field와 exact live wire span을 생성하는 Proxy runtime 컴포넌트다.
Wire layout은 pinned XDR protocol schema가 소유하고 Agent-facing semantic path는
작은 annotation layer가 소유한다. 잘못된 field span을 내보내면 다른 bytes를
intended target으로 오인해 M1 거짓 양성을 만들 수 있으므로 unknown layout은
추측하지 않고 fail closed 한다.

## 해결하려는 문제

현재 tools/nfs-proxy의 nfsp_walk는 RPC envelope와 NFSv4 COMPOUND header,
first opcode까지만 확정하고 나머지 op-array body를 raw region으로 둔다.

```text
certain:
    RPC envelope
    COMPOUND header
    first opcode

unknown:
    remaining operation body
```

이 경계는 current Layer 0 byte mutator에는 안전하지만 다음 target selector를
해석할 수 없다.

```text
nfs4.response.OPEN.result.ok.stateid
nfs4.request.SEQUENCE.args.sessionid
nfs3.request.WRITE.args.count
```

syzkaller 0006/0015에는 request-side NFSv3/NFSv4 shape가 많이 존재한다.
하지만 이것은 fuzz input generation을 위한 description이다.

```text
bounded fuzz arrays
curated strings / values
request-oriented coverage
no complete response schema
```

이를 Decoder의 canonical wire schema로 사용하면 fuzz-generation restriction을
wire protocol restriction으로 오인할 수 있고, reply field boundary를 추측하게 된다.

따라서 Decoder는 protocol wire schema와 Agent-facing semantic naming을 분리해야 한다.

```text
version-pinned XDR
    -> exact wire layout

small semantic annotations
    -> stable semantic field path

live RpcRecord
    + normalized schema
    -> proven WireRef
```

## 구조

```text
  +---------------- repository / build -------------------+
  |                                                       |
  |  pinned RPC/NFS XDR source                            |
  |        | wire schema                                  |
  |        v                                              |
  |  [Protocol Schema Normalizer]                         |
  |        | ProtocolSchema                               |
  |        +<---- semantic annotations                    |
  +--------|----------------------------------------------+
           | schema
           v
  +------------------- NFS Proxy -------------------------+
  |  RpcRecord + RPC metadata + TransactionEntry?         |
  |        | live bytes                                   |
  |        v                                              |
  |  [NFS Semantic Decoder] (D)                           |
  |        |                                              |
  |        +----> DecodedRpcMessage                       |
  |                  |                                    |
  |                  +----> SemanticField                 |
  |                  +----> WireRef                       |
  +------------------|------------------------------------+
                     | decoded semantics
                     v
              Semantic Rule Resolver
```

(D)=decode correctness 관측 지점.
읽는 순서는 위에서 아래이며 Schema 생성과 live decode는 별도 단계다.

## 설계

### 1. 요소 분류와 소유권

```text
[Repository Design Data] ProtocolSchema
    Maintained by: repository maintainers
    Built from:    pinned protocol XDR source + annotations
    Read by:       NFS Semantic Decoder / Mutation Rule Compiler

[COMPONENT] Protocol Schema Normalizer
    Runs at:       build / development time
    Input:         protocol XDR source + annotations
    Output:        ProtocolSchema

[COMPONENT] NFS Semantic Decoder
    Runs at:       Proxy runtime
    Input:         SemanticDecodeInput
    Output:        DecodedRpcMessage
    Mutates wire:  NO

[DATA] SemanticField
    Produced by:   NFS Semantic Decoder
    Consumed by:   Semantic Rule Resolver

[DATA] WireRef
    Produced by:   NFS Semantic Decoder
    Meaning:       schema-proven span in live rpc_payload
```

Decoder는 selector matching, mutation application, M1 verdict를 소유하지 않는다.

### 2. protocol source-of-truth

Wire layout의 source-of-truth는 NFS/RPC protocol의 XDR 정의다.

초기 target source set:

```text
ONC RPC v2         RFC 5531 + XDR RFC 4506
NFSv3              RFC 1813
NFSv4.0            RFC 7530
NFSv4.1            RFC 8881
NFSv4.2            RFC 7862 + NFSv4.1 base schema
```

Repository는 실제 구현 시 정확한 source snapshot과 적용한 update/errata를
고정해야 한다. Runtime Decoder가 network에서 RFC 문서를 읽거나 파싱하지 않는다.

```text
protocol source snapshot
      |
      v
deterministic normalization
      |
      v
ProtocolSchema(schema_id)
      |
      v
Proxy runtime
```

schema_id는 exact normalized schema version을 식별한다.
구체적인 ID 형식은 implementation design에서 정하지만 runtime evidence와 delta가
어떤 schema로 decode되었는지는 식별 가능해야 한다.

### 3. ProtocolSchema

Decoder가 소비하는 normalized logical schema는 다음 정보를 가진다.

```text
ProtocolSchema
    schema_id

    protocol
        family
        rpc_program
        rpc_version
        nfs_version
        minor_version?

    procedures[]
    operations[]

    types[]
        scalar
        enum
        struct
        union
        fixed_array
        variable_array
        opaque
        string

    semantic_annotations[]
```

Wire layout과 semantic naming을 각각 한 source에서 소유한다.

```text
XDR schema
    -> field order
    -> integer width / endian
    -> union discriminant
    -> variable length/count
    -> XDR alignment/padding

semantic annotation
    -> stable semantic field path
    -> semantic alias
    -> mutation visibility
```

동일한 wire struct layout을 annotation file에서 다시 수동으로 복사하지 않는다.

### 4. hybrid schema model

채택 모델은 다음과 같다.

```text
generated / normalized wire schema
              +
small semantic annotation layer
```

Wire schema는 protocol 정의에서 deterministic하게 생성한다.
Annotation은 Agent와 Compiler가 참조할 안정적인 의미 이름만 제공한다.

예:

```text
wire node:
    OPEN4resok.stateid

semantic annotation:
    nfs4.response.OPEN.result.ok.stateid
```

이렇게 하면 protocol structure와 Agent-facing naming을 분리하면서도
두 개의 독립적인 byte-layout 구현을 유지하지 않는다.

Runtime 구현이 generic schema interpreter인지 generated C decoder인지는
이 계약에서 고정하지 않는다.

두 구현 모두 다음 계약을 지켜야 한다.

```text
same ProtocolSchema
same semantic path
same WireRef coordinates
same decode status semantics
```

### 5. syzkaller description의 역할

syzkaller NFS description은 canonical Decoder schema가 아니다.

현재 0006/0015 description은 다음 용도로 사용할 수 있다.

```text
request generator
known request vector source
request-side decoder cross-check
syzlang capability description
```

다음 특성은 canonical schema로 사용하지 않는 이유다.

```text
fuzz-only array bounds
curated path/string values
fuzzing-oriented value restrictions
partial/request-side coverage
```

따라서:

```text
ProtocolSchema != syzkaller type graph

ProtocolSchema
    may be cross-checked against
    syzkaller request encoding
```

### 6. SemanticDecodeInput

Runtime Decoder 입력은 다음 logical data다.

```text
SemanticDecodeInput
    record: RpcRecord

    rpc
        message_type
        xid
        program
        version
        procedure?

    transaction?

    reply_dispatch?             # REPLY만. 아래
```

RpcRecord.rpc_payload[0]이 모든 WireRef coordinate의 기준이다.

RPC record marker나 TCP fragment header는 Decoder coordinate space에 포함하지 않는다.

CALL의 program/version/procedure는 RPC Decoder가 직접 제공한다.
REPLY는 wire 자체에 program/version/procedure가 없다([RFC 5531 §9](https://www.rfc-editor.org/rfc/rfc5531.html#section-9)).
NFSv4 `COMPOUND4res`에는 request의 `minorversion`도 없다([RFC 8881 §16.2.2](https://www.rfc-editor.org/rfc/rfc8881.html#section-16.2.2)).
그래서 REPLY의 schema는 검증된 dispatch identity로만 고른다(issue #18 F4).

```text
reply_dispatch
    program
    version
    procedure
    minor_version?      # NFSv4 COMPOUND / CB_COMPOUND
    source              # transaction_entry | test_fixture
```

- live traffic에서 `reply_dispatch`의 출처는 lookup 결과가 `found`인 TransactionEntry 하나다
  (`03-transaction-context.md` §7). program/version/procedure는 그 entry의 valid CALL envelope에서 온다
  (`03-transaction-context.md` §6). NFSv4 `minor_version`은 CALL의 COMPOUND header를 decode했을 때만 있다.
- `test_fixture`는 M2 host test에서 fixture CALL이 dispatch를 공급할 때만 쓴다. production runtime은 이
  source를 받지 않는다.
- request semantic context(operation sequence, request field)의 유무와 dispatch identity의 유무는 다른
  조건이다. dispatch만 있고 request context가 없으면 result schema는 고를 수 있지만 request-dependent
  predicate는 쓸 수 없다.
- dispatch가 없거나 schema 선택에 필요한 값이 빠졌으면(NFSv4에서 `minor_version` 없음 포함) REPLY를
  `decoded`로 만들지 않는다. payload가 어떤 result shape로 그럴듯하게 parse된다는 사실은 dispatch가 아니다.

### 7. DecodedRpcMessage

```text
DecodedRpcMessage
    schema_id

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
        sequence_index
        status?
        fields[]
            SemanticField

    decode_status
    failure?
```

sequence_index는 하나의 COMPOUND 내부 structural position을 진단하고
request/reply 결과를 대응시키기 위한 runtime metadata다.

다음 selector identity로 사용하지 않는다.

```text
forbidden:
    mutate operation sequence_index == 2

preferred:
    mutate all OPEN result stateid fields matching semantic predicates
```

같은 record 안에 동일 operation이 여러 개 있고 구분이 필요하면 주변 semantic
context/predicate로 구분한다. Temporal stream ordinal로 구분하지 않는다.

### 8. SemanticField

```text
SemanticField
    path
    type
    value
    wire_ref
```

path는 stable semantic namespace다.

예:

```text
nfs3.request.WRITE.args.count

nfs4.request.SEQUENCE.args.sessionid
nfs4.request.WRITE.args.stateid

nfs4.response.OPEN.result.status
nfs4.response.OPEN.result.ok.stateid
```

Protocol implementation의 C struct/symbol 이름을 Agent-facing API로 직접 노출하지 않는다.

### 9. semantic path 규칙

기본 grammar:

```text
<family>.<direction>.<operation-or-procedure>.<branch>.<field...>
```

family:

```text
nfs3
nfs4
```

direction:

```text
request
response
```

NFSv3는 procedure 이름을 사용한다.

```text
nfs3.request.WRITE.args.count
nfs3.response.WRITE.result.status
```

NFSv4는 operation 이름을 사용한다.

```text
nfs4.request.OPEN.args.owner.clientid
nfs4.response.OPEN.result.ok.stateid
```

Union은 discriminant가 선택한 arm을 path에 반영한다. 규칙은 다음 하나다(M2 구현,
`tools/nfs-proxy/schema/README.md`).

```text
<union>.<discriminant 이름>       result.status
arm type이 struct                 result.ok.stateid          (struct member를 바로 이어 붙임)
arm type이 struct가 아님          claim.<branch>.<arm 이름>
```

branch는 case label에 annotation이 준 이름이고, 없으면 label을 소문자로 바꾼 것이다(`default:` arm은
`default`). arm 이름과 member 이름은 XDR identifier를 그대로 쓴다. 그래서 NFSv4 예시의 정확한 path는
pinned XDR이 들어온 뒤 그 identifier로 정해진다.

NFSv4 COMPOUND 자체는 procedure node로 쓴다. operation array target의 path는
`nfs4.request.COMPOUND.args.argarray`와 `nfs4.response.COMPOUND.result.resarray`다(`04` §5, issue #5).

Array의 element index는 decoder output 안에서 structural metadata로 사용할 수 있지만
Agent selector의 기본 identity로 사용하지 않는다. element path는 `<array>[]`이고 index는 별도 값이다.
XDR linked list(`struct T { ...; T *next; }`)도 같은 모양으로 펼친다. `entries[]`의 각 element가
자기 뒤의 link word를 `discriminant` metadata로 가진다.

Schema annotation이 제공하지 않는 arbitrary alias를 Agent가 생성할 수 없다.

RPC envelope(`xid`, `cred`/`verf`, `prog`/`vers`/`proc`)는 semantic path가 아니며 초기 target runtime의
mutation 대상이 아니다. `rpc.call.*` / `rpc.reply.*` namespace는 예약한다. 나중에 envelope mutation을
넣으면 forwarded XID 기준 re-keying과 original/forwarded envelope identity의 evidence 기록을 함께
정해야 한다. selector는 `SemanticSelector`의 typed RPC metadata를 계속 쓸 수 있다(issue #7). 현재
XID mutation은 legacy 경로의 capability로 남는다.

### 10. WireRef

WireRef는 semantic field가 live rpc_payload 안에서 차지하는 encoding을 명시한다.

```text
WireRef
    encoded_span
        offset
        length

    value_span
        offset
        length

    metadata_spans[]
        role
            length
            count
            discriminant
            padding
        offset
        length
```

모든 offset은:

```text
RpcRecord.rpc_payload[0]
```

기준이다.

#### encoded_span

해당 logical field의 complete XDR encoding span이다.

Variable opaque/string의 경우 length word와 trailing padding을 포함할 수 있다.

#### value_span

semantic value 자체의 payload bytes다.

예:

```text
XDR string:
    [u32 length][value bytes][padding]

encoded_span:
    length + value + padding

value_span:
    value bytes only

metadata_spans:
    length
    padding
```

#### metadata_spans

구조 보존 mutation이나 deliberate malformed mutation에서 별도로 주소화해야 하는
length/count/discriminant/padding을 분리한다.

이렇게 해서 "field span"이 length/padding 포함 여부를 암묵적으로 결정하지 않는다.

### 11. WireRef 생성 규칙

WireRef는 schema walk로 boundary가 증명된 경우에만 생성한다.

```text
schema-proven boundary
    -> WireRef

heuristic scan / magic value search
    -> NO WireRef
```

다음 방식은 금지한다.

```text
known-looking 16 bytes를 stateid로 추측
opcode 뒤 fixed offset으로 field 추측
matching literal을 찾아 semantic field라고 가정
padding을 data 일부로 임의 해석
```

WireRef를 출력했다는 사실 자체가 Decoder의 correctness claim이다.

### 12. XDR decode 규칙

Decoder는 protocol schema에 따라 checked cursor를 전진시킨다.

각 decode step은 최소 다음을 검증한다.

```text
current offset inside rpc_payload
required bytes available
declared length/count does not overflow
padding does not exceed record
union discriminant has supported arm
array traversal terminates inside record
```

Declared length를 신뢰해 unchecked allocation하지 않는다.

Fuzz traffic은 hostile/malformed input일 수 있으므로 Decoder memory use가
declared length 자체에 비례해 폭증해서는 안 된다.

가능하면 value는 rpc_payload view로 유지하고, materialization이 필요한 경우에도
record size와 implementation safety limit를 넘지 않는다.

### 13. request decode

#### NFSv3 request

RPC CALL의 procedure가 직접 schema selector가 된다.

```text
RPC program = 100003
RPC version = 3
procedure = WRITE
        |
        v
WRITE3args schema
```

#### NFSv4 request

COMPOUND header의 minor version을 읽고 operation array를 순서대로 schema decode한다.

```text
COMPOUND4args
    tag
    minorversion
    argarray<>
        SEQUENCE
        PUTFH
        OPEN
```

각 operation은 opcode discriminant로 해당 arg schema를 선택한다.

### 14. response decode

Response decode에서 Transaction Context는 protocol에 따라 필요성이 다르다.

#### NFSv3 response

RPC REPLY에는 original NFS procedure number가 직접 들어 있지 않다.
따라서 다음 context가 필요하다.

```text
connection_id + call_direction + XID
    -> original CALL procedure
    -> response result schema
```

TransactionEntry가 없으면 procedure-specific response field를 추측하지 않는다.

```text
decode_status = transaction_context_missing
```

entry는 있지만 request body semantic decode가 실패한 경우에도 procedure는 CALL envelope에서 오므로
`reply_dispatch`가 있다(§6). 이때 result schema decode는 가능하고 request-dependent predicate는 쓸 수 없다.

#### NFSv4 response

NFSv4 COMPOUND result에는 operation result discriminant가 있으므로 wire schema로
operation을 식별할 수 있다.

TransactionEntry가 있으면 server가 실제로 받은 `request.forwarded`로 다음 consistency를 검증한다
(`03-transaction-context.md` §6, issue #7). `forwarded`가 undecodable이면 이 검증과 request-dependent
predicate를 쓰지 않는다.

```text
request operation sequence
response result sequence
early failure / shortened result array
minor-version expectations
```

operation result discriminant는 operation을 식별할 뿐, 이 payload에 적용할 program/version과
minorversion을 증명하지 않는다. 그래서 NFSv4 REPLY도 §6의 `reply_dispatch`가 있어야 `decoded`가 된다
(issue #18 F4).

| 조건 | decode_status | 출력 |
|---|---|---|
| `reply_dispatch` 있음, request context 있음 | `decoded` | 위 consistency를 검증한 field와 WireRef. request-dependent predicate 사용 가능 |
| `reply_dispatch` 있음(`minor_version` 포함), request context 없음 또는 `forwarded` undecodable | `decoded` | result schema field와 WireRef. request-dependent predicate/alias는 unavailable |
| entry 없음(missing, expired, ambiguous) | `transaction_context_missing` | mutation-safe field와 WireRef 없음. 진단용 prefix만 |
| entry는 있지만 `minor_version` 없음 | `dispatch_incomplete` | 위와 같다 |

dispatch가 없을 때 result discriminant를 읽어 만든 값은 §15의 partial diagnostics이며 Resolver input이
아니다.

Transaction Context의 key/lifecycle 정책은
[`03-transaction-context.md`](03-transaction-context.md)가 소유한다.

### 15. malformed / unknown input

Decoder는 fail closed 한다.

M2 구현은 `truncated`와 `malformed`를 다음처럼 나눈다. record가 고정 크기 item(word, hyper, fixed
opaque) 중간에서 끝나면 `truncated`다. XDR이 허용하지 않는 값이면 `malformed`다. 선언되지 않은 enum 값,
0/1이 아닌 bool, arm이 없는 discriminant, bound를 넘거나 record 끝을 넘는 length/count, 0이 아닌
padding, procedure body 뒤의 남은 bytes가 여기에 든다.

decode_status:

```text
decoded
unsupported_schema
malformed
truncated
transaction_context_missing
dispatch_incomplete
resource_limit
```

필요하면 failure에 다음 진단을 남긴다.

```text
failure
    offset
    schema_node
    reason
```

Decoder가 failure 이전에 일부 prefix field boundary를 증명했더라도,
decode_status가 decoded가 아니면 Semantic Rule Resolver의 mutation input으로
사용하지 않는다.

Proven prefix는 diagnostics로 보존할 수 있다.

```text
partial diagnostics
    !=
mutation-safe decoded message
```

이 규칙은 malformed traffic의 앞부분을 잘못 mutation-safe라고 오인하는 것을 막는다.

### 16. intentionally malformed mutation과의 관계

Stage 2는 malformed output을 만들 수 있다.

하지만 순서는 다음과 같다.

```text
valid / fully decoded input
        |
        v
semantic target resolved
        |
        v
ResolvedMutation
        |
        v
Edit Applier
        |
        +--> intentionally malformed output
```

Decoder가 이미 malformed한 input의 unknown layout을 추측해서 target을 찾는 구조가 아니다.

### 17. schema coverage와 capability

Target architecture는 현재 fixture가 지원하는 protocol family를 다룬다.

```text
NFSv3
NFSv4.0
NFSv4.1
NFSv4.2
```

하지만 구현은 점진적으로 들어갈 수 있다.

```text
schema exists
    !=
runtime implementation validated
    !=
promoted registry scope (Agent usable)
```

field 단위 지원 범위는 Harness Capability Specification에 나열하지 않고 Proxy build가 생성하는 semantic
capability registry가 소유한다. guest/runtime validation(M7)을 통과한 subset의 registry digest와 scope만
promotion되어 HCAP에서 참조된다(`../02-llm-agent/04-harness-capability-spec.md` §4, issue #14).

### 18. schema extension

새 NFS operation/version을 지원하려면 conceptual 순서는 다음과 같다.

```text
protocol source set 확인
    |
    v
ProtocolSchema normalization
    |
    v
semantic annotation 추가/검토
    |
    v
golden + negative decode tests
    |
    v
runtime guest validation
    |
    v
Harness Capability Specification update
```

M2에서 normalizer와 decoder가 들어왔다(`tools/nfs-proxy/schema/README.md`). NFS XDR source는 아직
repository에 없다. 그래서 NFS 메시지는 지금 모두 `unsupported_schema`다. 테스트는 합성 protocol
(`tools/nfs-proxy/test/schema/`)로 한다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| XDR source를 wire truth로 사용 | request와 response의 exact encoding을 같은 protocol truth에서 해석하기 위함 |
| semantic annotation을 분리 | Agent-facing naming을 RFC/C symbol과 분리하면서 byte layout 중복을 피함 |
| syzkaller를 canonical schema로 쓰지 않음 | fuzz-generation bounds와 curated values가 wire protocol 자체의 제한이 아님 |
| WireRef를 schema-proven span에만 발급 | wrong-field mutation으로 인한 M1 거짓 양성을 막음 |
| value/encoded/metadata span을 분리 | variable XDR의 length/padding 포함 여부를 명시화 |
| NFSv3 reply에 TransactionEntry 사용 | RPC REPLY만으로 original procedure를 식별할 수 없음 |
| NFSv4 reply는 self-described result + context 검증 | 가능한 wire semantics를 유지하면서 request context도 consistency에 사용 |
| decode failure는 mutation에 fail closed | partial/ambiguous layout을 target으로 오인하지 않기 위함 |
| runtime network schema fetch 금지 | job reproducibility와 isolation을 유지하기 위함 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| current nfsp_walk만 계속 확장 | 구현 최소화 | first opcode 이후 semantic target을 해석할 수 없음 | 비채택 |
| per-op hand-written byte decoder | 직접 제어가 쉬움 | RFC/XDR layout을 수동 중복하고 drift 위험이 큼 | 비채택 |
| syzkaller description을 canonical schema로 사용 | 기존 request shape 재사용 | fuzz-specific bounds, reply coverage 부족 | 비채택 |
| RFC/XDR generic schema만 노출 | wire correctness 단순 | Agent-facing stable semantic naming이 protocol symbol에 결합 | 부분 채택 |
| generated wire schema + semantic annotations | wire truth와 stable naming을 분리 | normalizer/annotation 검증이 필요 | 채택 |
| live packet pattern scan | schema 없이 빠르게 시작 | false-positive field resolution 위험 | 비채택 |

Generated runtime decoder와 generic schema interpreter 중 어느 것을 쓸지는
performance/safety prototype 결과를 보고 재검토한다.

## 영향

### 상류

Protocol source snapshot과 semantic annotation이 바뀌면 schema_id가 바뀐다.
Mutation Rule Compiler는 selector/field_path가 해당 ProtocolSchema에서 유효한지
정적으로 검증해야 한다.

### 하류

Semantic Rule Resolver는 Decoder가 생성한 SemanticField/WireRef만 mutation target으로
사용한다. Decoder가 wrong span을 내면 M1과 MutationDelta가 함께 오염된다.

Transaction Context는 reply decode에 필요한 request metadata를 제공해야 한다.

### 운영

Full per-operation decode는 current header-only walk보다 CPU cost가 증가한다.

Decoder는 fuzz traffic을 처리하므로:
- record length보다 큰 unchecked allocation 금지,
- length arithmetic overflow 방지,
- bounded stack/iteration,
- malformed decode의 deterministic refusal

이 필요하다.

Schema artifact는 runtime network dependency 없이 job input과 함께 고정되어야 한다.

## 신뢰성 요구

가장 위험한 오류는 거짓 양성이다.

```text
bytes A..B
    decoded as OPEN.stateid
        but
actual protocol field is different
```

이 오류가 mutation까지 이어지면 Proxy가 wrong field를 바꾸고도 M1을 성공으로
보고할 수 있다.

| 항목 | 요구 |
|---|---|
| 오류 방향 | false-positive field resolution을 최우선으로 방지 |
| 실패 방식 | unsupported/ambiguous/malformed는 fail closed |
| 관측 가능성 | schema_id, status, failure offset/node/reason을 남김 |
| 재현성 | same schema + same bytes => same semantic tree/WireRef |

False negative도 진단 가능해야 한다.
지원되는 schema인데 unsupported로 떨어지는 경우 decode status와 failure location으로
implementation gap을 찾을 수 있어야 한다.

## 검증 오라클

### 1. golden protocol vector

Known encoded record와 expected field tree/span을 fixture로 고정한다.

```text
input bytes
    -> expected semantic paths
    -> expected values
    -> expected WireRef spans
```

### 2. truncation negative vectors

각 variable/fixed field 경계에서 input을 truncate한다.

Expected:

```text
status != decoded
no out-of-bounds read
no guessed WireRef
```

### 3. malformed length/count vectors

```text
oversized opaque length
array count beyond remaining record
unknown union discriminant
invalid padding boundary
```

에서 deterministic failure가 발생해야 한다.

### 4. syzkaller request cross-check

0006/0015 description으로 만든 known request bytes를 Decoder에 넣어 다음을 비교한다.

```text
expected procedure/opcode
expected request values
expected field spans
```

이 검사는 request-side cross-check이며 syzkaller가 schema truth라는 뜻은 아니다.

### 5. real wire capture

실제 lane에서 capture한 request/response를 Decoder regression vector로 사용할 수 있다.

Capture는 implementation exercise/evidence다.
Schema source-of-truth는 아니다.

### 6. independent differential check

독립 decoder/tool이 있는 field는 selected vector에 대해 semantic value와 operation tree를
cross-check할 수 있다.

이 tool은 runtime dependency가 아니라 test oracle이다.

### 7. mutation-address oracle

Decoder가 반환한 target WireRef만 변경했을 때 다른 sibling field/padding이
의도치 않게 바뀌지 않는지 확인한다.

이 검증은 M1/Q2를 증명하지 않는다.
Decoder가 target field와 span을 정확히 해석했음을 검증한다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| unsupported_schema | schema source에 version/op 없음 | schema_id + protocol selector | schema extension issue |
| truncated | record가 field 중간에서 끝남 | failure offset/node | passthrough/refusal |
| malformed | invalid discriminant/length/padding | reason + field path | mutation target으로 사용 금지 |
| transaction_context_missing | NFSv3 reply context 없음 | connection/XID lookup | Transaction Context 확인 |
| resource_limit | safety bound 도달 | limit type + record size | bound/traffic 검토 |
| expected path 없음 | annotation/schema mismatch | schema node vs path mapping | annotation 수정/검증 |
| wrong value | schema decode bug | golden/differential vector | Decoder bug로 처리 |
| wrong WireRef | span accounting bug | mutation-address oracle | Decoder bug로 처리 |
| replay target 없음 | schema/semantic drift | schema_id + path resolution | replay mismatch 진단 |

## 한계와 미결 사항

- **결정됨:** wire-layout truth는 protocol XDR source set이 소유한다.
- **결정됨:** semantic naming은 작은 annotation layer가 소유한다.
- **결정됨:** syzkaller descriptions는 canonical Decoder schema가 아니다.
- **결정됨:** WireRef는 RpcRecord.rpc_payload 기준이다.
- **결정됨:** unknown/malformed layout에 heuristic WireRef를 만들지 않는다.
- **결정됨:** decode_status가 decoded가 아니면 mutation-safe input으로 쓰지 않는다.
- **결정됨:** REPLY schema는 검증된 `reply_dispatch`로만 고른다. NFSv4도 dispatch 없이 result shape만으로
  `decoded`를 만들지 않는다(§6, §14, issue #18 F4).
- **결정됨(M2):** Normalizer는 build/development time에 도는 Python 표준 라이브러리 script다
  (`tools/nfs-proxy/schema/normalize.py`). C build와 guest build container는 Python이 필요 없다.
- **결정됨(M2):** normalized ProtocolSchema의 artifact는 생성된 C 상수 table이며 commit한다. `build.sh`가
  매번 다시 생성해 다르면 실패한다. `schema_id`는 normalized schema의 canonical JSON SHA-256이다
  (`<family>[.<minor>]/sha256:<hex>`). XDR comment만 바뀌면 바뀌지 않는다.
- **결정됨(M2):** runtime은 generic interpreter(`src/nfs_decode.c`)다. bounds check가 한 곳에만 있고,
  schema 변경이 unchecked read를 만들 수 없다.
- **결정됨(M2):** annotation은 줄 단위 directive 파일이다(`tools/nfs-proxy/schema/README.md`). field나
  offset, width를 다시 적지 않는다.
- **결정됨(M2):** resource limit은 nesting depth 64(normalizer가 build 때 거부하고 runtime도 다시 확인)와
  message당 field 기본 65536개(호출자가 낮출 수 있음)다. 실패한 decode는 field를 하나도 남기지 않는다.
- **결정됨(M2):** NFSv4 NULL procedure는 COMPOUND가 없어 minor version이 없다. 그래서 하나의
  ProtocolSchema를 고를 수 없고 `unsupported_schema`다. 그 REPLY는 §14 표대로 `dispatch_incomplete`다.
- **미결:** NFS XDR snapshot 반입. NFSv4.0/4.1/4.2는 RFC 7531/5662/7863의 XDR을 추출해 pin한다. NFSv3는
  RFC 1813에 추출 가능한 XDR 파일이 없어 source 형태를 따로 정해야 한다.
- **미결:** NFS callback/backchannel program의 initial schema coverage.
- **미결:** request/response consistency 검증(§14)은 request context가 있어야 한다. M3 TransactionEntry가
  생기기 전까지 M2 decoder의 `request_context`는 항상 0이다.
- **한계:** `fattr4`의 attribute 값처럼 XDR에서 `opaque`로 선언되고 내용이 bitmap에 따라 정해지는 data는
  opaque 하나로만 decode된다. XDR로 표현되지 않는 layout이라 schema walk로 증명할 수 없다.
- **미검증:** RFC/XDR-derived normalized schema와 current syzkaller request shape 전체의 차이.

## 참조

- docs/design/03-nfs-proxy/01-architecture.md
- docs/design/02-llm-agent/08-mutation-rule-set.md
- docs/design/02-llm-agent/04-harness-capability-spec.md
- tools/nfs-proxy/src/walk.h
- tools/nfs-proxy/src/walk.c
- tools/nfs-proxy/README.md
- bundle/patches/syzkaller/0006-sys-linux-describe-opt-in-SunRPC-fuzz-messages.patch
- bundle/patches/syzkaller/0015-sys-linux-add-protocol-shaped-NFS-fuzz-operations.patch

## Agent 사용 지침

### 지원 범위

Agent가 semantic selector/field_path로 사용할 수 있는 field는 다음 조건을 모두 만족해야 한다.

```text
ProtocolSchema에 wire schema 존재
semantic annotation/path 존재
runtime Decoder 구현 존재
guest/runtime validation 완료
Harness Capability Specification에 usable로 등록
```

Target design 문서에 field path가 예시로 있다는 사실만으로 current harness가
지원한다고 가정하지 않는다.

### 비지원 범위

다음은 unsupported다.

```text
schema에 없는 NFS version/op/procedure
annotation 없는 arbitrary implementation symbol
unknown union arm
malformed/partial record의 semantic mutation
heuristic byte search로만 찾을 수 있는 field
```

이 경우 Agent가 raw offset workaround를 생성하지 않는다.

Stage 2에서 필요한 target이면:

```text
unsupported_by_current_harness
    -> HarnessGapIssue
       gap_class = mutation_engine
```

### 확장 절차

Normalizer와 annotation 문법은 `tools/nfs-proxy/schema/README.md`에 있다. 새 schema는 XDR source와
annotation 파일을 추가하고, `build.sh`의 `SCHEMAS` 목록에 생성 table을 등록해 넣는다.

현재 repository에서 확인 가능한 extension workflow는 다음과 같다.

```text
02-semantic-decoder.md design update
        |
        v
tools/nfs-proxy implementation + tests
        |
        v
guest/runtime validation
        |
        v
04-harness-capability-spec.md update
```

NFS XDR source가 들어오면 이 절에 그 path를 적는다.

### 제약

```text
schema-proven WireRef only
unknown layout guess 금지
stream ordinal identity 금지
runtime XID replay identity 금지
syzkaller fuzz bounds를 wire protocol bounds로 해석 금지
Q1/M1/Q2 evidence 분리
```

### 검증 방법

Agent-facing field를 지원한다고 표시하려면 최소 다음 증거가 있어야 한다.

```text
golden decode vector
negative/truncation vector
exact WireRef validation
live guest/runtime decode
semantic rule target resolution
```

Control ACK나 parser acceptance만으로 semantic field support를 validated로 올리지 않는다.

## 다음 상세 설계

이 contract 이후 순서는 다음과 같다.

```text
1. [`Transaction Context contract`](03-transaction-context.md) — detailed contract fixed
2. [`Semantic Mutation Rule runtime contract`](04-semantic-mutation-runtime.md) — detailed contract fixed
3. [`MutationDelta / Replay contract`](05-mutation-delta-replay.md) — detailed contract fixed
4. [`Implementation gap analysis`](06-implementation-gap-analysis.md) — current-vs-target mapping fixed
5. Proxy implementation
```
