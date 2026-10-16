# NFS Proxy MutationDelta / Replay Contract

> 상태: draft · 최종 확인: 2026-10-12
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82
> 상위 설계: `01-architecture.md`
> 선행 계약: `02-semantic-decoder.md`, `03-transaction-context.md`,
> `04-semantic-mutation-runtime.md`
> 관련 구현: `tools/nfs-proxy/src/delta.c`, `delta.h`, `edit.c`,
> `control.c`
> 관련 게이트: Stage 2 M1 evidence / crash reproduction

## 요약

MutationDelta는 Stage 2에서 실제 사용한 `CompiledMutationRule` set과 생산 실행의
concrete mutation evidence를 durable하게 함께 보존하는 semantic replay artifact다.
Replay는 생산 당시 byte offset/original bytes를 그대로 다시 패치하지 않고,
recorded semantic rule을 동일 Decoder/Transaction Context/Resolver/Edit Applier
경로에서 live traffic에 다시 resolve한다. 생산 당시 concrete bytes는 증거로 남지만
dynamic field의 replay identity가 아니다. 논리 단위는 program generation 하나
(`ProgramGenerationExecution`)이고, journal은 crash가 일어나는 guest가 아니라 Runner가 소유한
host journal sink에 durable하게 기록한다.

## 해결하려는 문제

Current `NFSPDLT1/2`는 concrete byte rule을 reproduction unit으로 사용한다.

```text
recorded rule
    direction / route / first opcode / anchor
    byte offset
    exact original bytes
    exact replacement bytes
    applied_count
```

Replay는 production original bytes와 현재 bytes가 다르면 hard failure다.
이 invariant는 fixed/static field replay에는 강하지만 target semantic runtime의
dynamic state에는 그대로 적용할 수 없다.

```text
production:
    OPEN result stateid = A
    transform = zero_value

replay:
    OPEN result stateid = B
```

`A != B`여도 같은 semantic OPEN result이고 같은 rule/predicate가 성립하면
`B -> zero_value`가 target semantic replay다.

반대로 replay가 다른 field나 다른 request context를 mutation하면 안 된다.

따라서 target artifact는 다음 둘을 분리한다.

```text
semantic replay contract
    exact CompiledMutationRule snapshot
    schema/runtime semantics

production evidence
    actual target/value/bytes/edit/output observed
```

Replay-time original bytes는 live record에서 다시 resolve하고 apply 직전에 다시
verify한다. Production original bytes는 evidence이지 default replay selector가 아니다.

## 구조

```text
  +---------------- production execution ----------------+
  |  CompiledMutationRule[]                              |
  |        | durable rule-set snapshot                   |
  |        v                                             |
  |  [Delta Recorder]                                    |
  |        |                                             |
  |  live record -> Resolver -> Edit Applier             |
  |                         | built mutated batch         |
  |                         v                            |
  |                  EXPOSURE_INTENT (D)                 |
  |                         | host ACK before exposure   |
  |                         v                            |
  |                      relay                           |
  |                         | full write?                |
  |                         v                            |
  |                  FORWARD_COMPLETE                    |
  +-------------------------|-----------------------------+
                            |
                            v
              MutationDelta (Runner host sink)
                            |
                            v
  +------------------- replay execution -----------------+
  |  same CompiledMutationRule[]                         |
  |        |                                             |
  |  Decoder -> Transaction Context -> Resolver          |
  |        -> Edit Applier -> replay batch log           |
  +--------------------------------------|---------------+
                                         v
                                 replay comparator
                           (validation layer, 01 §11.1)
                                         |
                                         v
                                   ReplayResult
```

`(D)`=crash-survival durability point. Runner host journal sink가 framed event append 전체를
마친 뒤 보내는 ACK다(§11, issue #3). 원본 MutationDelta는 replay 중 수정하지 않는다.

## 설계

### 1. 요소 분류와 소유권

```text
[DATA] MutationDelta
    Produced by:   Delta Recorder
    Consumed by:   Replay / Crash Report / M1 evidence
    Scope:         one ProgramGenerationExecution (logical)

[COMPONENT] Delta Recorder
    Runs at:       Proxy runtime (guest)
    Input:         CompiledMutationRule[] + applied mutation batches
    Output:        append-only journal events -> Host Journal Sink

[COMPONENT] Host Journal Sink
    Runs at:       Runner host (guest 밖)
    Owned by:      Runner
    Input:         guest Delta Recorder가 보낸 journal events (untrusted)
    Output:        durable host journal + 동기 ACK (D)

[COMPONENT] Replay
    Runs at:       Runner + Proxy runtime
    Input:         MutationDelta + matching ProtocolSchema + scenario
    Output:        replay journal (host sink, 봉인)

[COMPONENT] Replay comparator
    Runs at:       Controller 측 validation layer (`../02-llm-agent/01` §11.1)
    Input:         봉인된 production / replay evidence + JudgeProfile(Replay)
    Output:        ReplayResult

[DATA] ReplayResult
    Produced by:   Replay comparator
    Meaning:       replay-time semantic application/delivery comparison
```

Delta Recorder는 crash/sanitizer verdict를 만들지 않는다.
ReplayResult도 Q2 crash reproduction verdict 자체가 아니다.

### 2. Delta scope

MutationDelta의 logical scope는 **한 `ProgramGenerationExecution`**, 즉 한 lane에서
remote-KCOV generation 하나로 실행한 syz program 하나다(issue #2). 같은 rule set으로 여러
generation, lane, VM instance를 실행하는 campaign 전체는 `Stage2Campaign`이며 replay 비교 단위가
아니다. campaign 전체를 한 단위로 묶으면 crash한 program과 그 동안 적용된 batch를 연결할 수 없다.

Current `arm-N.delta`처럼 rule 하나당 독립 reproduction file을 target 기본 단위로
사용하지 않는다.

이유:

```text
same record
    -> rule A
    -> rule B
    -> shared conflict/structure preflight
    -> one final rebuild
```

Rule별 artifact로 분리하면 production에서 같은 pre-mutation snapshot에 함께
resolve된 batch 관계를 잃는다.

물리적으로 host journal이 여러 generation을 한 file/segment에 multiplex해도 된다. 그것은
implementation detail이며 replay identity가 아니다. Logical artifact는 한 generation의 rule set과
application journal이다.

generation-scoped event는 다음 correlation을 가진다. session-scoped event(`RULESET`, `RUN_COMPLETE`)는
generation이 생기기 전이나 뒤에 오므로 이 correlation을 갖지 않는다(§6).

```text
program_generation_correlation
    vm_instance_id      # host sink가 channel에서 기록
    lane_id / proc_id
    kcov_generation     # correlation 값, replay identity 아님
    rule_set_id
    program_digest      # cross-check
```

host sink는 guest가 보낸 값을 Runner가 설치한 rule set과 host가 bind한 generation 상태에 대조한다
(§6, `01-architecture.md` §16).

### 3. MutationDelta

```text
MutationDelta
    format_version
    semantic_runtime_version
    candidate_id
    schema_id
    rule_set_id
    program_generation_correlation

    rule_set[]
        CompiledMutationRule

    journal[]
        JournalEvent
```

`format_version`은 file/serialization contract를 식별한다.

`semantic_runtime_version`은 selector/predicate/transform evaluation semantics를
식별한다. Builtin transform의 versioned `transform_id`도 rule snapshot에 포함된다.

`schema_id`는 production Decoder/Compiler가 사용한 exact ProtocolSchema contract다.

### 4. replay source는 CompiledMutationRule snapshot

Replay는 MutationRuleSet을 다시 Agent에게 보내거나 Compiler를 다시 실행하지 않는다.

```text
production CompiledMutationRule[]
        |
        v
durable exact normalized snapshot
        |
        v
Replay
```

이유:
- Agent reasoning은 replay dependency가 아니다.
- Compiler가 이후 변경돼도 recorded rule semantics가 바뀌면 안 된다.
- replay가 current Compiler normalization 차이에 영향받으면 안 된다.

Runtime이 recorded semantic runtime version/transform ID를 지원하지 못하면
silent migration 대신 explicit incompatibility로 실패한다.

### 5. ProtocolSchema dependency

MutationDelta가 entire ProtocolSchema bytes를 반드시 inline해야 하는 것은 아니다.

대신:

```text
MutationDelta.schema_id
    ->
exact matching ProtocolSchema artifact
```

가 replay input으로 존재해야 한다.

Matching schema artifact를 확보할 수 없으면 replay는 `schema_unavailable`이다.
다른 schema로 best-effort remap하지 않는다.

Crash Report/reproduction package가 필요하면 schema artifact를 함께 bundle할 수 있다.
그 packaging contract는 이 문서의 scope가 아니다.

### 6. JournalEvent

Target journal은 append-only event stream이다.

```text
JournalEvent
    session_binding         # host-stamped (아래)
    event_seq
    event_type
    payload
```

Core event:

```text
RULESET
GENERATION_OPEN
GENERATION_DRAINING
EXPOSURE_INTENT
APPLY_REFUSAL
FORWARD_COMPLETE
FORWARD_FAILED
GENERATION_COMPLETE
RUN_COMPLETE
```

`event_seq`는 journal integrity/order용 local sequence다.
Semantic replay selector나 mutation identity가 아니다.

**event scope와 admission (issue #18 F3).** 물리 journal은 여러 generation을 multiplex할 수 있으므로(§2)
host sink는 event마다 scope를 확인한다.

```text
session_binding                 # host가 channel과 session 설치에서 기록
    vm_instance_id
    channel_id
    proxy_session_id            # Runner가 rule set을 설치할 때 정한다
    rule_set_id
```

| event | scope | 필수 identity | 금지 / 선행 조건 |
|---|---|---|---|
| `RULESET` | session | `session_binding` | `program_generation_correlation` 없음. session의 첫 event이며 첫 `GENERATION_OPEN`보다 먼저 `(D)`에 도달한다 |
| `GENERATION_OPEN` | generation | `session_binding`, `program_generation_correlation`, `draining_generations[]` | `kcov_generation`은 이 session에서 처음 bind된다. 같은 lane에 admitting인 generation이 남아 있으면 거부한다. `draining_generations[]`는 같은 lane에서 `GENERATION_DRAINING` 뒤 아직 summary가 없는 generation 목록이며, host가 그 lane에 draining으로 가진 집합과 같아야 한다. 다르면 거부한다. 받아들이면 새 generation은 admitting이다 |
| `GENERATION_DRAINING` | generation | 위와 같음 | admitting인 generation에만 한 번 온다. 받아들이면 host는 그 generation을 draining으로 바꾼다. Proxy는 이 event의 host ACK 뒤에만 deactivation을 ACK한다(`01-architecture.md` §16) |
| `EXPOSURE_INTENT`, `APPLY_REFUSAL` | generation | 위와 같음 | correlation이 이 session의 evidence-open generation binding(lane, `kcov_generation`, `rule_set_id`)과 맞아야 한다. draining generation에서는 `record_context`가 REPLY인 event만 받는다. CALL-context event는 거부하고 기록한다(PR #22 review) |
| `FORWARD_COMPLETE`, `FORWARD_FAILED` | generation | 위와 같음, `batch_id` | 같은 session과 generation에서 받아들인 `EXPOSURE_INTENT`의 `batch_id`를 참조한다. batch마다 forward 종료 event는 하나다 |
| `GENERATION_COMPLETE` | generation | 위와 같음 | evidence-open generation의 마지막 event. 받은 뒤 그 binding은 closed다(§21) |
| `RUN_COMPLETE` | session | `session_binding` | `program_generation_correlation` 없음. 그 session의 마지막 event |

identifier 범위:

- `event_seq`는 Proxy session마다 0부터 빈틈없이 증가한다. 여러 session이 한 물리 journal을 공유해도 범위는
  session이다.
- Proxy는 session의 event를 `event_seq` 순서로 하나씩 보낸다. host 응답이 없는 event가 있는 동안 그 session의
  다음 event는 보내지 않는다. 그래서 여러 connection이 event를 만들어도 sink가 보는 순서는 `event_seq` 순서이고,
  빈틈은 구현 오류다(아래 sequence violation).
- `batch_id`는 `EXPOSURE_INTENT`가 정하며 Proxy session 안에서 유일하다. forward 종료 event는 새 batch가 아니라
  그 batch의 lifecycle 전이이므로 같은 `batch_id`를 다른 payload로 참조한다.
- host binding의 generation 상태는 evidence 상태다. `GENERATION_OPEN`부터 `GENERATION_COMPLETE`까지
  evidence-open이며, 그 안에서 admitting(`GENERATION_OPEN` 뒤)과 draining(`GENERATION_DRAINING` 뒤)을
  구분한다. host가 lane마다 admitting generation을 하나만 두는 것은 `GENERATION_OPEN`의 거부 규칙이 보장한다. CALL admission은 Proxy가 lane마다 하나의
  generation에만 준다(`01-architecture.md` §16). 같은 lane에서 draining G와 admitting G+1이 함께
  evidence-open일 수 있다.
- `proxy_session_id`는 Runner가 정하고 host가 기록한다. guest가 보낸 값은 대조만 한다.

재수신과 충돌:

| 상황 | sink 동작 |
|---|---|
| 같은 session, 같은 `event_seq`, byte-identical payload (ACK 유실 뒤 재전송) | 다시 append하지 않고 같은 ACK를 다시 보낸다. 새 application으로 세지 않는다 |
| 같은 `event_seq`에 다른 payload | 거부하고 session journal conflict를 host 기록으로 남긴다. 그 session의 open generation은 summary가 와도 내부 불일치다 |
| 이미 받은 `batch_id`로 두 번째 `EXPOSURE_INTENT`, 또는 이미 forward 종료 event가 있는 batch에 다른 `event_seq`의 두 번째 종료 event | 위와 같다 |
| 받지 않은 `batch_id`를 참조하는 forward 종료 event | 거부하고 기록한다 |
| `event_seq` 빈틈 또는 역행 | 거부하고 sequence violation을 기록한다. 그 session의 open generation은 내부 불일치다 |
| 알 수 없는 또는 이미 끝난 `proxy_session_id` (stale session) | 거부하고 기록한다. 다른 session이나 새 generation에 편입하지 않는다 |
| 다른 lane, 없는 generation, closed generation의 correlation | 거부하고 기록한다. host 값으로 고쳐 받아들이지 않는다 |
| Proxy process 재시작 | 새 Proxy session이다. Runner가 rule set을 다시 설치하고 새 `proxy_session_id`를 정한다. 이전 session의 open generation은 summary 없이 끝난다 |
| Runner process 재시작 | sink는 durable journal에서 session별 다음 `event_seq`, batch, generation binding을 복원한 뒤 수신을 재개한다. 복원할 수 없는 session의 event는 거부한다 |

어느 경우에도 guest가 보낸 값을 host 값으로 바꿔 성공시키지 않는다(`../02-llm-agent/01` §11.1).

### 7. RULESET event

`RULESET`은 Proxy session에서 traffic mutation이 시작되기 전에 host sink에서 `(D)`에 도달해야
한다. rule set은 Runner가 Proxy session마다 설치하는 불변 집합이다(`01-architecture.md` §16).

```text
RULESET
    semantic_runtime_version
    schema_id
    candidate_id
    rule_set_id
    CompiledMutationRule[]
```

Runner/Proxy는 RULESET durability가 확인되기 전에 Stage 2 traffic mutation을 시작하지
않는다.

Rule registration ACK가 존재한다면 target architecture에서는 최소한 해당 semantic
rule set이 memory에 유효하게 등록되고 RULESET이 durable하다는 의미까지만 가진다.
ACK 자체는 M1이 아니다.

### 8. mutation durability unit은 batch

한 complete RPC record에 여러 semantic rule/occurrence가 함께 적용될 수 있다.

따라서 durability unit도 record-level mutation batch다.

```text
MutationBatch
    batch_id
    semantic_signature
    record_context
    applications[]
    concrete_output
```

`batch_id`는 journal event correlation용 local identifier다.
Replay selector가 아니며 다음 run에서 동일할 필요가 없다.

### 9. batch semantic signature

Replay equivalence를 stream ordinal 없이 비교하기 위해 각 successful mutation batch에
semantic signature를 만든다.

```text
semantic_signature
    canonical multiset of:
        rule_id
        target.semantic_path
        target.part
        mutation.kind
```

같은 rule/path가 한 record에서 여러 번 적용되면 multiplicity를 보존한다.

예:

```text
record A:
    rule-open-stateid x 2
    rule-status       x 1
```

Signature는 record를 찾는 selector가 아니다.
Production과 replay가 같은 semantic batch composition을 만들었는지 사후 비교하는
witness다.

### 10. EXPOSURE_INTENT

Edit Applier가 original precondition을 검증하고 final mutated record를 성공적으로
구성한 뒤, 그 bytes를 relay에 노출하기 **전에** 다음 event를 durable하게 기록한다.

```text
EXPOSURE_INTENT
    batch_id
    semantic_signature

    record_context
        program_generation_correlation   # §2
        direction
        backend
        client
        rpc message type/program/version/procedure?
        nfs version/minor?

    applications[]
        rule_id
        semantic_target
        predicate_values[]
        transform_source_values[]
        original_value_snapshot
        mutated_value_snapshot
        concrete_edits[]

    output
        final_record_length
        concrete_output_snapshot?
```

Concrete output snapshot 전체를 inline할지 concrete edits + final length로 충분한지는
serialization 설계에서 결정한다.

하지만 최소한 production에서 실제로 어떤 semantic value와 bytes가 바뀌었는지
사후 검증할 수 있어야 한다.

### 11. 왜 exposure 전에 durable하게 쓰는가

Crash를 만든 마지막 mutation은 crash 직후 user-space가 더 이상 journal을 갱신할
기회를 얻지 못할 수 있다. 더 근본적으로 Proxy는 crash가 일어나는 guest 안에서 실행되고, guest의
파일은 guest kernel crash나 VM 종료와 함께 사라질 수 있다. syz-manager의 qemu backend는 기본으로
`-snapshot`을 써서 VM 종료 시 디스크 변경을 버린다. 그래서 guest 안의 `O_SYNC`/`fsync`는 이 계약의
durability가 아니다(issue #3).

따라서 invariant는:

```text
unrecorded mutated output
    must never be exposed to peer
```

이다.

failure domain과 commit point:

| 항목 | 계약 |
|---|---|
| 견뎌야 하는 장애 | Proxy process crash, guest kernel crash, VM teardown/교체, Runner process restart |
| 범위 밖 | Runner host OS/storage 손실. 나중에 범위에 넣으면 `fsync`/`fdatasync`와 directory metadata durability가 `(D)`에 포함된다 |
| `(D)` | Runner host journal sink가 framed event append 전체를 마친 뒤 보내는 host-generated ACK. userspace buffer 진입이나 부분 `write()`는 해당하지 않는다. ACK되지 않은 부분 append는 torn-tail 규칙(§24)이 처리한다 |
| transport | 구현 선택이며 request/ACK journal service를 선호한다. guest write-back cache로는 ACK를 만족할 수 없다 |
| trust | sink는 event를 framing·bound·검증하고, host가 아는 channel identity를 기록하며, guest가 보낸 correlation을 activation 상태와 대조한다 |

Delta durability가 실패하거나 sink가 event를 거부하면 mutated output을 relay에 넘기지 않는다.
record는 변조 없이 relay하고 그 generation의 evidence는 불완전으로 남긴다. positive evidence가
없으면 M1은 `INCONCLUSIVE`다(`../02-llm-agent/01-two-stage-agent-architecture.md` §7).

### 12. production concrete snapshot의 의미

EXPOSURE_INTENT에 저장한 다음 값은 production evidence다.

```text
original_value_snapshot
mutated_value_snapshot
concrete original bytes
concrete replacement/insert bytes
live WireRef-derived coordinates
```

이 값은 다음 질문에 답한다.

> production에서 실제 무엇을 바꿨는가?

하지만 default replay selector가 아니다.

### 13. semantic replay precondition

Replay precondition은 production concrete original equality가 아니라 recorded
`CompiledMutationRule`의 semantic contract다.

```text
same schema_id
same semantic selector
same typed predicates
same context dependencies
same transform semantics
same structure policy
```

Replay-time Resolver는 현재 live value/bytes를 새로 snapshot한다.

```text
production original = A
replay original     = B

if same semantic rule matches:
    resolve B
    transform B
    verify B before apply
```

### 14. exact original equality가 필요한 경우

Replay가 특정 semantic original value를 반드시 요구한다면 그 요구는 production
snapshot 암묵 비교가 아니라 rule predicate로 표현한다.

예:

```text
predicate:
    target == NFS4_OK
```

또는:

```text
predicate:
    current_message.some_field == literal
```

이렇게 하면 production/replay 모두 같은 typed condition을 검증한다.

Production concrete byte snapshot 자체를 replay predicate로 승격하지 않는다.

### 15. replay-time verify-before-apply

Production original bytes를 요구하지 않는다는 것이 verify-before-apply를 없애는 것은
아니다.

Replay-time flow:

```text
live replay record
    |
    v
Semantic Resolver
    |
    +--> replay current value
    +--> replay current original bytes
    |
    v
ResolvedMutation
    |
    v
Edit Applier
    |
    +--> verify replay-current original bytes
    +--> apply
```

즉 TOCTOU/wrong-buffer 방지를 위한 concrete verification은 **매 실행마다 새로 resolve한
bytes**를 기준으로 유지한다.

### 16. forward lifecycle

EXPOSURE_INTENT가 durable해진 뒤에만 mutated record를 relay에 넘긴다.

Relay는 batch와 연결된 local token을 받아 full record write 결과를 Delta Recorder에
돌려줄 수 있어야 한다.

```text
EXPOSURE_INTENT durable
        |
        v
relay accepts mutated record
        |
        +--> full record written
        |        |
        |        v
        |   FORWARD_COMPLETE
        |
        +--> known failure
                 |
                 v
            FORWARD_FAILED
```

Current `on_record` callback은 output buffer만 반환하고 downstream full-write completion을
Delta Recorder에 통지하지 않는다. Target contract를 구현하려면 relay completion hook이
필요하다.

### 17. FORWARD_COMPLETE

```text
FORWARD_COMPLETE
    batch_id
    forwarded_length
```

Destination socket에 complete RPC record가 local relay 관점에서 전부 write된 뒤에만
append한다.

`FORWARD_COMPLETE`는 remote kernel이 그 record를 처리했다는 증거는 아니다.
그것은 local Proxy가 complete bytes를 peer socket으로 넘겼다는 evidence다.

### 18. FORWARD_FAILED

Known local failure는 다음처럼 기록할 수 있다.

```text
FORWARD_FAILED
    batch_id
    reason
    bytes_written?
```

Partial socket write 뒤 fatal error가 난 경우도 success로 올리지 않는다.

### 19. socket delivery와 disk commit의 atomicity 한계

File append와 socket write를 하나의 atomic transaction으로 묶을 수 없다.

따라서 다음 crash window는 제거할 수 없고 **명시적으로 표현해야 한다**.

```text
EXPOSURE_INTENT durable
        |
        v
socket write may start / may complete
        |
       CRASH
        |
        v
no FORWARD_COMPLETE event
```

이 상태의 delivery verdict:

```text
delivery_unknown
```

이다.

다음을 주장하지 않는다.

```text
no FORWARD_COMPLETE
    == definitely not delivered
```

또한 write completion 후 FORWARD_COMPLETE event가 durable해지기 직전에 crash할 수 있다.
이 경우 peer가 bytes를 받았어도 local journal에서는 delivery_unknown으로 남는다.

host append는 끝났지만 `EXPOSURE_INTENT`의 ACK가 유실될 수도 있다. 이때 Proxy는 mutated output을
노출하지 않는다. journal에 남은 `EXPOSURE_INTENT`는 적용 evidence로 유지하되, forward event 없이
delivery로 승격하지 않는다(issue #3).

### 20. crash-cut state

Journal에서 batch state를 다음처럼 재구성한다.

```text
no EXPOSURE_INTENT
    -> no recorded mutation exposure

EXPOSURE_INTENT only
    -> mutation built and durable
    -> peer delivery unknown

EXPOSURE_INTENT + FORWARD_COMPLETE
    -> local full-write confirmed

EXPOSURE_INTENT + FORWARD_FAILED
    -> local forwarding failure known
```

이 distinction을 in-place counter 하나로 압축하지 않는다.

### 21. GENERATION_OPEN / GENERATION_DRAINING / APPLY_REFUSAL / GENERATION_COMPLETE / RUN_COMPLETE

generation G의 lifecycle(admitting, draining, closed)은 `01-architecture.md` §16이 소유한다. journal에는
G의 처음과 끝이 남는다.

```text
GENERATION_OPEN
    program_generation_correlation
    rule_set_id
```

Proxy는 activation(G)을 처리할 때 `GENERATION_OPEN`을 append하고 host ACK `(D)`를 받은 뒤에만
activation을 ACK한다. host sink는 이 event로 G를 Proxy session과 lane에 bind한다. G의 다른 event는 이
binding이 있어야 받아들인다(§6).

```text
GENERATION_DRAINING
    program_generation_correlation
    rule_set_id
```

Proxy는 deactivation(G)을 처리할 때 G의 CALL admission을 닫고 `GENERATION_DRAINING`을 append한 뒤, host
ACK `(D)`를 받아야 deactivation을 ACK한다(PR #22 review). host는 이 event로 G를 draining으로 바꾸고, 그 뒤에
오는 G의 CALL-context `EXPOSURE_INTENT`/`APPLY_REFUSAL`을 거부한다. G+1이 열리지 않아도 이 전이는 일어난다.
host ACK가 오지 않거나 sink가 거부하면 deactivation은 ACK되지 않고 barrier 실패 경로를 따른다
(`01-architecture.md` §16). 그때 G의 rule에는 M1 `NOT_APPLIED`를 내리지 않는다. 유효한 host-durable
`EXPOSURE_INTENT`가 있는 rule은 `APPLIED`를 유지하고(§11), 없는 rule은 `INCONCLUSIVE`다. ACK 실패는 적용
사실을 취소하지 않는다. journal 손상이나 correlation 불일치는 별도의 invalid-evidence 규칙을 따른다(§6, §24).

forward가 끝나지 않은 batch는 connection close 때 `FORWARD_FAILED`로 끝난다(§18). Proxy는 G의 closure를
판정하고 G의 모든 batch가 `FORWARD_COMPLETE`/`FORWARD_FAILED`를 남긴 뒤 G의 마지막
event로 mandatory `GENERATION_COMPLETE`를 append한다(issue #4, issue #18 F1). normal non-match는 record마다
기록하지 않고 여기에 rule별로 집계한다.

```text
GENERATION_COMPLETE
    program_generation_correlation
    rule_set_id
    records_seen
    exposure_batch_count
    outside_activation_window
    evidence_path_failures
    resolver_summary[]        # rule_id별 04 §31 taxonomy count
    closure
        reason                # drained | reply_unresolved | aborted
        drain_bound
        reply_unresolved_count
```

| closure reason | 조건 |
|---|---|
| `drained` | G의 모든 entry가 `replied` 또는 `expired(connection_closed)`로 끝났다 |
| `reply_unresolved` | closure 때 `awaiting_reply`가 남았거나(drain bound 만료), timeout/capacity reclaim으로 REPLY를 G로 처리하지 못한 entry가 있다(`03-transaction-context.md` §5). 그 수가 `reply_unresolved_count`다 |
| `aborted` | generation ABORT 통지로 닫혔다 |

closure가 rule에 대해 clean인지는 rule의 `selector.rpc.message_type`(`04-semantic-mutation-runtime.md` §4)에
따라 정한다.

| closure reason | `call` rule | `reply` rule |
|---|---|---|
| `drained` | clean | clean |
| `reply_unresolved` | clean. CALL admission은 deactivation에서 이미 닫혔다 | clean 아님 |
| `aborted` | clean 아님 | clean 아님 |

M1 `NOT_APPLIED`는 activation/deactivation barrier가 모두 ACK되고, 그 rule에 대해 clean인 closure를 가진
durable `GENERATION_COMPLETE`가 있으며, 그 rule의 `EXPOSURE_INTENT`가 없을 때만 성립한다. crash나 session
종료로 summary가 없으면 그 generation의 M1은 `INCONCLUSIVE`다
(`../02-llm-agent/01-two-stage-agent-architecture.md` §7).

`GENERATION_COMPLETE(G)`가 `(D)`에 도달하면 host sink는 G binding을 closed로 바꾸고, 그 뒤에 오는 G의
event를 거부하며 거부 사실을 host 기록으로 남긴다. 봉인된 G journal에 summary 뒤의 G event나 그 거부
기록이 있으면 내부 불일치다. Judge는 그 generation에 확정 verdict를 내리지 않는다
(`../02-llm-agent/01-two-stage-agent-architecture.md` §11.1).

summary는 crash-cut에서 사라질 수 있다. 그래서 replay 비교에 필요한 hard refusal 사실은 summary와 별도로
write-ahead한다(issue #18 F2). hard refusal인지는 JudgeProfile(Replay)의 분류(§29)가 정한다.

```text
APPLY_REFUSAL
    program_generation_correlation
    rule_id
    refusal            # 04 §31 taxonomy 값 또는 apply_precondition_failed
    record_context     # direction / rpc message type / program / version / procedure
```

- Proxy는 (generation, rule_id)마다 첫 hard refusal의 `APPLY_REFUSAL`을 append하고 host ACK `(D)`를 받은
  뒤에 거부된 record를 relay한다. 두 번째부터는 summary의 count에만 남긴다. 비교에는 위치마다 hard
  refusal의 존재만 필요하기 때문이다. 첫 `APPLY_REFUSAL`이 아직 ACK되지 않은 동안 같은 (generation, rule_id)의
  hard refusal이 다른 connection에서 나오면, 그 record도 첫 event의 ACK를 기다린 뒤 relay한다. 그래야 어느
  connection에서 relay된 refusal이든 durable `APPLY_REFUSAL`이 앞선다.
- normal non-match는 이 event를 만들지 않는다. 지금처럼 summary에만 집계한다.
- Proxy는 host 응답(ACK 또는 거부) 없이 거부된 record를 relay하지 않는다. 응답이 없으면 같은 `event_seq`로
  같은 event를 다시 보낸다(§6의 재수신 규칙).
- 기다림의 범위는 둘이다. record relay는 그 record와 같은 connection·방향에서만 멈춘다(순서 보존). event
  전송은 session 전체에서 멈춘다(§6, 한 번에 하나). 그래서 다른 connection에서 event가 필요 없는 record는
  계속 relay되고, event가 필요한 record(application, 첫 hard refusal)는 앞 event의 응답을 기다린다.
- 이 두 규칙 때문에 relay된 hard refusal record에는 durable `APPLY_REFUSAL`이 이미 있다. guest가 응답을
  기다리는 중에 종료되면 기다리던 record는 peer에 닿지 않았으므로 production prefix 밖이다. sink가 응답하지
  않는 상태가 계속되면 traffic이 멈추고, Runner가 stall을 종료 원인으로 기록한다(§29의 `unknown`).
- sink가 명시적으로 거부하면 host가 그 거부를 기록한다. Proxy는 record를 변조 없이 relay하고(§11과 같다)
  session을 `evidence_path_degraded`로 표시하며, 이후 event와 summary의 `evidence_path_failures`에 남긴다.
- summary가 있으면 rule별 hard refusal count가 0보다 큰데 `APPLY_REFUSAL`이 없는 것은 내부 불일치다.

Proxy session이 clean하게 끝나면 optional `RUN_COMPLETE` event를 append할 수 있다.

```text
RUN_COMPLETE
    rule summaries[]
    batch count
    forward complete count
    forward failed count
```

Crash reproduction correctness는 RUN_COMPLETE에도, crash한 generation의 GENERATION_COMPLETE에도
의존하면 안 된다. Crash가 목적일 수 있으므로 journal prefix만으로 의미를 복구할 수 있어야 한다.

### 22. append-only durability contract

Target MutationDelta는 production application state를 in-place update하지 않는다.

```text
append RULESET
append EXPOSURE_INTENT
append FORWARD_COMPLETE
...
```

각 event는 다음 조건을 가져야 한다.

```text
framed length
event type/version
monotonic event_seq
bounded payload
integrity check
host sink (D) before success return (§11)
```

Exact binary framing/checksum algorithm은 implementation design에서 정한다.

### 23. journal 생성과 RULESET durability

journal file은 Runner host journal sink가 만든다. guest 안의 file 생성과 `O_SYNC`는 이 계약의
durability가 아니다.

Mutation traffic를 시작하기 전에 RULESET이 host sink에서 `(D)`에 도달해야 한다. 선언한 failure
domain(§11)에서는 완료된 host append로 충분하다. host OS crash를 범위에 넣으면 그때
`fsync`/`fdatasync`와 parent-directory metadata durability가 `(D)`에 포함된다.

Contract는:

```text
RULESET acknowledged durable (host sink)
    before
first mutation exposure
```

를 요구한다.

### 24. torn tail

Crash 중 마지막 append가 완성되지 않을 수 있다.

Reader는 event framing/integrity를 사용해:

```text
complete valid prefix
    + incomplete final tail
```

을 구분해야 한다.

Incomplete final event는 committed event로 취급하지 않는다.

반면 middle-of-journal corruption이나 sequence/integrity violation은 artifact
corruption이다.

Silent skipping 후 replay를 계속하지 않는다.

### 25. Replay 입력

Replay에 필요한 logical input:

```text
recorded rule set (rule_set_id, CompiledMutationRule[])
CrashContextWindow의 순서 있는 ProgramGenerationExecution 목록
    각 entry의 syz program
    각 entry의 MutationDelta
matching ProtocolSchema(schema_id)
compatible semantic runtime
same ReachabilityHarness / fixture / image identity
```

crash evidence는 crashing generation 하나가 아니라 `CrashContextWindow`
(`../02-llm-agent/01-two-stage-agent-architecture.md` §8)에 보존된 선행 generation을 함께 쓴다.
lane state가 program 사이에 유지되기 때문이다. 필요한 선행 program이나 MutationDelta가 없으면
multi-generation attribution은 `INCONCLUSIVE`이며 crashing program만 replay하는 것으로 대신하지
않는다(issue #2).

MutationDelta 자체가 network scenario 전체를 포함한다고 가정하지 않는다.

Scenario/harness reproduction package는 Controller/Runner/Crash Report lineage가
제공한다.

### 26. Replay는 Agent/Compiler를 다시 호출하지 않는다

```text
MutationDelta.rule_set[]
        |
        v
validate semantic runtime version
validate schema_id
        |
        v
register recorded CompiledMutationRule[]
```

Agent가 새로운 reasoning을 하거나 current Compiler가 rule을 재-normalize하면
replay 의미가 drift할 수 있으므로 금지한다.

### 27. Replay pipeline

Replay도 production과 동일 semantic execution path를 사용한다.

```text
live replay traffic
        |
        v
Record Framer
        |
        v
RPC Decoder
        |
        v
Transaction Context
        |
        v
NFS Semantic Decoder
        |
        v
Semantic Rule Resolver
        |
        v
Conflict / Structure Preflight
        |
        v
Edit Applier
```

별도 ad-hoc replay byte patcher를 만들지 않는다.

### 28. ReplayResult

```text
ReplayResult
    production_evidence_manifest_sha256
    replay_evidence_manifest_sha256
    judge_profile_id
    schema_id / semantic_runtime_version
    semantic_verdict
    delivery_evidence

    positions[]                      # CrashContextWindow 순서
        production_generation        # correlation 값
        replay_generation            # correlation 값
        production
            batch_signature_multiset
            forward_complete_multiset
            hard_refusals[]          # rule_id, refusal
            refusal_evidence         # complete | prefix_complete | unknown
        replay
            batch_signature_multiset
            forward_complete_multiset
            hard_refusals[]
            refusal_evidence
        differences[]

    runtime_errors[]
```

Replay는 recorded rule set을 설치하고 window의 program을 순서대로 실행해 replay journal을 남긴다.
comparator가 봉인된 두 evidence에서 각 위치의 production generation과 replay generation batch를
비교한다(issue #11). 두 generation의 numeric id는 같을 필요가 없다.

ReplayResult는 production MutationDelta를 수정하지 않는 별도 execution result다.

### 29. semantic replay verdict

Semantic replay는 successful exposure-intent batch semantics를 stream position 없이 비교한다.

```text
REPLAY_EQUIVALENT
REPLAY_DIVERGED
REPLAY_INCONCLUSIVE
REPLAY_INVALID
```

`REPLAY_EQUIVALENT`는 delta/runtime/schema가 compatible하고, window의 모든 위치에서
production/replay의 `EXPOSURE_INTENT` semantic batch signature multiset이 동일하며, 양쪽 모두 hard
semantic/apply refusal이 없음이 증명됨을 뜻한다.

`REPLAY_DIVERGED`는 실행은 valid하지만 missing/extra batch, batch composition 또는
cardinality가 production과 다르거나, 어느 쪽에 hard refusal이 있음을 뜻한다. 양쪽에 같은 hard refusal이
있어도 equivalent로 올리지 않는다. hard refusal은 그 위치에서 rule set이 의도대로 적용되지 않았다는
사실이기 때문이다.

`REPLAY_INCONCLUSIVE`는 비교 전제는 성립하고 divergence도 관측되지 않았지만, 어느 위치에서 hard refusal이
없었다는 사실을 증명할 수 없음을 뜻한다(issue #18 F2).

`REPLAY_INVALID`는 delta corruption, schema/runtime incompatibility, unsupported
transform, invalid fixture/resource failure 등으로 의미 있는 비교 자체가 불가능한 경우다.

`REPLAY_INVALID`는 manifest와 correlation 검증을 통과한 봉인 evidence에서만 나온다. 검증에 실패한
bundle로는 비교 verdict를 내지 않는다. comparator는 그 replay 시도를 invalid evidence로 기록하며,
evidence를 고친 뒤 replay를 다시 실행한다(`../02-llm-agent/01` §11.1, issue #11).

**refusal 분류.** JudgeProfile(Replay)은 resolver taxonomy(`04-semantic-mutation-runtime.md` §31)와 Edit
Applier refusal을 다음처럼 분류한다. 아래는 첫 profile의 내용이다. 분류를 바꾸면 새 profile version이다.

| 분류 | 값 | 비교에서의 의미 |
|---|---|---|
| normal non-match | `scope_miss`, `rpc_selector_miss`, `target_not_found`, `predicate_false` | 영향 없음. record마다 기록하지 않는다 |
| hard refusal | `schema_mismatch`, `decode_unavailable`, `transaction_context_missing`, `transaction_context_unusable`, `target_ambiguous`, `predicate_reference_ambiguous`, `transform_failed`, `conflict`, `structure_constraint_failed`, `apply_precondition_failed` | 그 위치를 `REPLAY_EQUIVALENT`에서 제외한다 |
| incompatibility | `transform_unsupported` | `REPLAY_INVALID`(§39) |

**refusal evidence 완전성.** comparator는 위치와 쪽마다 hard refusal 사실의 완전성을 봉인 bundle에서
정한다.

| 값 | 조건 |
|---|---|
| `complete` | durable `GENERATION_COMPLETE`가 있고 `evidence_path_failures`가 0이다. hard refusal 존재는 summary count와 `APPLY_REFUSAL`이 함께 정한다 |
| `prefix_complete` | summary가 없다(crash-cut). journal prefix가 integrity 검증을 통과하고(torn final tail은 허용, §24), `evidence_path_degraded` 표시, sink의 append 실패·거부 기록, channel 장애 기록이 없으며, Runner가 기록한 종료 원인이 guest crash 또는 VM teardown이다(sink 무응답으로 인한 stall은 해당하지 않는다). host 응답 전 relay 금지 규칙(§21) 때문에 relay된 record의 hard refusal은 모두 prefix에 있다. 응답을 기다리며 relay되지 않은 record는 peer에 닿지 않았으므로 cut 뒤의 traffic과 같이 production prefix 밖이다 |
| `unknown` | 그 밖의 경우 |

crash-cut prefix라는 사실만으로는 `unknown`이 아니다. `delivery_unknown`도 이 완전성과 무관하며 semantic
divergence로 바꾸지 않는다(§37).

**판정 순서.** 위에서부터 처음 맞는 행을 적용한다.

| 순서 | 조건 | 결과 |
|---|---|---|
| 1 | manifest / correlation 검증 실패 | verdict 없음. invalid evidence 기록 |
| 2 | format / runtime / schema / transform 비호환, fixture·resource 실패, incompatibility 분류 refusal | `REPLAY_INVALID` |
| 3 | 어느 위치든 batch signature multiset이 다름 | `REPLAY_DIVERGED` |
| 4 | 어느 위치든 어느 쪽에 hard refusal이 있음 | `REPLAY_DIVERGED` |
| 5 | 어느 위치든 어느 쪽의 `refusal_evidence`가 `unknown` | `REPLAY_INCONCLUSIVE` |
| 6 | 그 밖 | `REPLAY_EQUIVALENT` |

이 verdict는 Q2 crash reproduced/not reproduced와 별개다.

### 30. cardinality contract

Target rule mode가 `all_matches`이므로 replay에서 extra/missing successful mutation은
scenario drift다.

Rule별 count만 비교하지 않고 record-level semantic batch signature의 multiset을 비교한다.

```text
production:
    batch [A, B]
    batch [A]

replay:
    batch [A]
    batch [A, B]

    -> equivalent
```

반면:

```text
production:
    batch [A, B]

replay:
    batch [A]
    batch [B]

    -> diverged
```

Rule counts가 같아도 같은 RPC record에서 함께 적용됐는지가 다르기 때문이다.

### 31. production ordering은 replay identity가 아님

Journal event order는 crash evidence chronology에는 필요하지만 replay target selector는
아니다. Production first/second mutated record를 replay의 first/second record로 찾지 않는다.

Batch signature multiset은 사후 equivalence 비교에만 사용한다.

### 32. dynamic semantic values

다음 값은 run 사이에 달라질 수 있다.

```text
XID
clientid
sessionid
stateid
slot sequence
filehandle
verifier
```

Production/replay snapshot bytes가 달라도 same recorded rule, schema, target path,
predicate, request view(`03-transaction-context.md` §19), deterministic transform semantics가 성립하면
semantic replay가 가능하다.

### 33. concrete byte comparison

ReplayResult는 diagnostic으로 production/replay concrete value/bytes 비교를 남길 수 있다.

```text
byte_comparison
    identical
    differs
    not_comparable
```

`differs`가 곧 semantic replay failure는 아니다.

```text
production stateid A -> zero
replay stateid B     -> zero
```

는 production original bytes가 다르지만 동일 semantic transform이 재적용된 경우다.

### 34. stable literal condition

특정 original value equality가 replay correctness에 필수라면 그 조건은
`CompiledMutationRule.predicates[]`에 이미 존재해야 한다.

Replay layer가 production concrete snapshot을 보고 새로운 implicit equality predicate를
만들지 않는다.

### 35. transform source comparison

`copy` 또는 context-derived builtin은 production과 replay source value가 달라질 수 있다.
Replay는 same ValueRef source semantics와 same typed transform을 요구한다.
Production source value snapshot은 evidence다.

### 36. replay batch logging

Replay 자체도 target kernel crash를 일으킬 수 있다.

따라서 Replay 실행도 production과 같은 exposure-before-forward durability discipline을
사용해 별도의 replay execution log를 남겨야 한다. replay journal도 Runner host sink에 기록한다(§11).

```text
production MutationDelta
    read-only

replay execution
    -> replay application journal
    -> ReplayResult
```

Crash가 replay 중 발생해도 마지막 replay mutation candidate가 durable해야 한다. replay journal도
`APPLY_REFUSAL` write-ahead 규칙(§21)을 따른다. 그래서 replay 쪽 refusal evidence 완전성도 production과
같은 규칙(§29)으로 정한다.

### 37. delivery evidence

Semantic replay verdict와 local delivery evidence를 분리한다.

```text
delivery_evidence
    complete
    unknown
    failed
```

Production/replay 각각 batch별 delivery state를 가진다.

Production batch가 `EXPOSURE_INTENT`만 남기고 crash했다면 semantic replay input으로는
사용 가능하지만 production delivery는 unknown이다.

### 38. FORWARD_COMPLETE cardinality

Production에 FORWARD_COMPLETE가 존재하는 batch subset은 replay delivery 결과와 별도로
비교할 수 있다.

하지만 crash-triggering 마지막 batch가 production에서 delivery_unknown일 수 있으므로
semantic replay equivalence를 FORWARD_COMPLETE equality 하나에만 묶지 않는다.

delivery state와 M1의 관계는 `../02-llm-agent/01-two-stage-agent-architecture.md` §7이 정한다
(issue #4). `unknown`은 M1 `APPLIED`로 세지만 확인된 delivery가 아니고, `failed`는 그 batch의
완전한 forward가 성립하지 않았다는 뜻이다.

### 39. schema/runtime incompatibility

다음은 implicit migration하지 않는다.

```text
format_version unsupported
semantic_runtime_version unsupported
schema_id unavailable/mismatch
versioned transform_id unsupported
```

결과는 `REPLAY_INVALID`이다.

Old artifact migration이 필요하면 explicit offline migration/compatibility path를 별도로
만든다.

### 40. multiple-rule replay

Replay는 MutationDelta의 entire recorded rule set을 한 unit으로 설치한다.

```text
rule A
rule B
rule C
    -> same pre-mutation snapshot
    -> same conflict preflight
```

Rule별 file을 순차 replay해 production batch semantics를 재구성하지 않는다.

### 41. replay 중 rule mutation 금지

Replay 실행 중 Agent 재계획, Compiler 재작성, rule 추가/삭제, predicate 완화,
transform substitution, schema remapping을 하지 않는다.

Recorded rule set을 current traffic에 그대로 semantic resolve한다.

### 42. current NFSPDLT1/2와의 관계

Current `NFSPDLT1` / `NFSPDLT2`는 concrete Layer 0 replay artifact다.

유지할 가치가 있는 invariant:

```text
no ordinal matching
verify-before-patch
explicit orig mismatch
durable mutation record
produce/replay share apply implementation
application cardinality checked
```

하지만 literal anchor, precomputed byte offset, production exact original bytes,
one-arm-per-file, in-place applied_count update는 target semantic replay identity가 아니다.

Implementation migration에서 NFSPDLT1/2는 legacy compatibility input, concrete
application evidence subrecord, Layer 0 regression fixture로 남을 수 있다. guest 안에 `O_SYNC`로
쓰는 NFSPDLT file은 legacy 구현과 host unit test 기반일 뿐, target semantic crash evidence의
durability 기반이 아니다(§11, issue #3).

Dynamic semantic campaign의 top-level artifact는 이 contract의 semantic MutationDelta다.
host frame magic/version과 ACK envelope은 §45에서 정한다. event payload별 canonical encoding과
guest transport는 후속 M5/S1b 구현에서 이 framing 위에 연결한다.

### 43. current applied_count와 target cardinality

Current delta는 rule별 `applied_count`를 in-place 갱신하고 replay 종료 시 exact count를
비교한다.

Target은 이를 record-level semantic batch signature multiset + delivery state로
일반화한다. Rule summary count는 진단에는 쓸 수 있지만 primary equivalence gate가 아니다.

### 44. M1 / Q2 경계

MutationDelta는 M1 Judge가 사용할 semantic rule snapshot, concrete production mutation,
EXPOSURE_INTENT durability, FORWARD_COMPLETE/FAILED/unknown evidence를 제공한다.

하지만 Delta Recorder가 M1 verdict를 직접 결정하지 않는다. M1 Judge는 Controller 측에서 Runner가 봉인한
host journal을 읽는다(`../02-llm-agent/01-two-stage-agent-architecture.md` §11.1).

```text
REPLAY_EQUIVALENT
    !=
Q2 crash reproduced
```

Q2는 crash/sanitizer evidence가 별도로 판단한다.

### 45. M5 host frame 및 ACK 계약 v1

첫 구현은 `agent_pipeline/journal_framing.py`의 frame codec, bounded prefix reader와 ACK schema다.
codec 자체는 event payload admission, session/generation 상태 복원, durable writer 또는 live transport를
제공하지 않는다(그 부분은 아래 "M5 구현 (v1)"의 sink다). frame 검증 성공이나 `JournalAck` 객체 생성은 `(D)`의 증명이 아니다.

**Frame layout.** 모든 정수는 unsigned big-endian이며 header는 80 bytes다.

| offset | 크기 | 필드 |
|---|---|---|
| 0 | 8 | magic `NFSPJNL1` |
| 8 | 2 | frame version = 1 |
| 10 | 2 | kind: 1 = host journal event, 2 = host rejection record, 3 = host ACK |
| 12 | 4 | payload byte length, 1–4 MiB |
| 16 | 32 | SHA-256(payload) |
| 48 | 32 | SHA-256(header bytes 0–47) |
| 80 | length | payload bytes |

kind/version/length를 포함한 header hash를 payload 읽기 전에 검사한다. 길이 필드 손상 때문에 뒤의
정상 record까지 incomplete tail로 숨기는 것을 막는다. 완전한 frame의 hash 오류는 마지막 frame이어도
corruption이다. 불완전한 마지막 header/payload만 tail로 보고하며, known magic/version/kind/length가
이미 잘못된 prefix는 tail로 구제하지 않는다. reader는 input을 자르거나 고쳐 쓰지 않는다.
hash는 무결성 검사이며 channel 인증이나 host provenance를 대신하지 않는다.

reader는 segment당 최대 64 MiB, 16,384 records를 읽고 한도를 낮출 수 있다. ACK frame은 journal
record로 읽지 않는다. `JournalPrefix.complete_bytes`는 framing이 완전한 prefix의 길이이며, event가
admission되었다거나 ACK되었다는 의미가 아니다. frame payload는 codec에서 opaque bytes이고, future sink는
§6–§21의 event별 canonical encoding/schema/limits를 따로 검증해야 한다. 큰 rule snapshot이나 concrete
snapshot을 artifact로 분리하면 해당 bytes도 ACK 전에 host에서 보존·검증해야 한다. segment 회전과
총 session 저장량 제한은 sink 구현에서 정하며, 한도 초과를 silent drop으로 처리하지 않는다.

**ACK envelope.** kind 3 payload는 repository `canonical_json`으로 직렬화한 다음 필드다.
duplicate key, 추가 필드, 비정규 JSON 표현과 범위를 벗어난 값은 거부한다.

```text
schema_version = "nfs-proxy-journal-ack.v1"
journal_id                    # host segment identifier
session_binding
    vm_instance_id
    channel_id
    proxy_session_id
    rule_set_id               # exact NFSPRUL1 snapshot SHA-256
event_seq                     # uint64, per-session
request_sha256                # exact canonical request bytes
record_sha256                 # complete stored frame, including header
committed_end_offset          # exclusive offset in that host segment
```

이 ACK는 host-stamped binding과 현재 한 개 outstanding request의 sequence/digest가 모두 같을 때만
수신 측에서 사용한다. guest가 보낸 `vm_instance_id`/channel/binding은 host 값과 대조하며, 다른 값을
host 값으로 덮어 성공시키지 않는다. channel 인증과 lifetime은 transport/Runner 책임이다.

**Sink가 지켜야 할 처리 순서.** 다음 순서는 계약이며 codec이 수행하는 동작이 아니다.

1. host channel binding과 설치된 immutable rule set을 선택한다. request framing/payload를 bound하고
   §6의 scope, `event_seq`, batch, admitting/draining/closed 상태를 검증한다.
2. exact request digest와 host-stamped event를 하나의 frame으로 append한다. short write는 끝까지 처리하고,
   referenced snapshot bytes까지 host에 보존한 뒤에만 성공으로 간주한다. 기존 §11의 failure domain을
   유지한다. host OS/storage crash 보장은 별도 확장이다.
3. ACK는 완성된 frame의 digest와 끝 offset을 가리킨다. append 성공 뒤 ACK 유실은 재전송으로 복구한다.
   같은 session/sequence/request bytes에는 동일한 ACK를 반환하고 다시 append하지 않는다.
4. 같은 sequence의 다른 request, gap, batch 충돌, stale binding, post-summary event는 host rejection
   record로 남긴다. 이런 거부를 success ACK로 표현하지 않는다. 거부 자체를 기록할 수 없으면 channel을
   실패시키고 evidence를 불완전으로 남긴다. 거부 response의 payload encoding은 sink/transport에서 정한다.
5. restart 시 완전한 frame만 읽은 후 event semantics와 session별 순서를 다시 검증한다. framing prefix만
   읽고 generation을 accepting 상태로 되돌리지 않는다. 부분 tail의 재사용/절단은 외부 ACK 기록과 기존
   segment 보존 여부를 포함한 writer recovery 정책에서 명시한다. codec은 자동 절단을 하지 않는다.

후속 구현의 필수 검증은 ACK 유실 재전송, 동일 sequence의 다른 payload, 다른 lane/VM/session,
draining 중 CALL 거부 및 REPLY 허용, summary 뒤 event 거부, short write/append 중 종료와 restart다.
지금의 codec 검증은 모든 마지막 append 절단 위치와 frame 손상·한도·ACK canonicality를 검사한다.
M5/S1b 완료와 M1 판정 연결은 실제 sink, guest transport, relay completion 및 봉인이 연결된 뒤에 판단한다.

**M5 구현 (v1).** `agent_pipeline/journal_sink.py`(host sink)와 `tools/nfs-proxy/src/journal.c`,
`target.c`(guest Delta Recorder)가 위 계약을 다음 encoding으로 구현한다.

- **Request.** guest는 kind 1 frame 하나에 canonical JSON request를 담아 보낸다:
  `{event_seq, event_type, payload, proxy_session_id, rule_set_id, schema_version =
  "nfs-proxy-journal-request.v1"}`. `payload`는 event type별 strict schema(추가 필드 거부)이며
  canonical이 아닌 bytes는 `malformed_request`다. `request_sha256`은 이 payload bytes 전체의 SHA-256이다.
  request는 최대 4 MiB − 64 KiB다. 남긴 64 KiB는 저장 envelope(binding, digest)가 한 frame에 들어가게
  하는 몫이고, 그래도 저장할 수 없는 record는 그 channel만 실패시킨다.
- **Install / session end.** Runner의 `install_session`이 `nfs-proxy-journal-install.v1`(binding, lane,
  rule set bytes)을, `end_session`이 `nfs-proxy-journal-session-end.v1`을 kind 1 record로 먼저 남긴다.
  restart는 이 record로 session을 복원한다. guest가 이 값을 정하지 않는다. 실행 entry
  (`python -m agent_pipeline.journal_sink`)는 같은 session이 이미 복원됐으면 binding, lane, rule set
  bytes가 정확히 같을 때만 그 session을 이어 쓰고, 하나라도 다르면 시작을 거부한다.
- **Accepted.** stored record는 `nfs-proxy-journal-event.v1` `{event_seq, event_type, request,
  request_sha256, schema_version, session_binding}`이고 응답은 이 frame을 가리키는 `JournalAck`다.
- **Rejected.** stored record는 kind 2 `nfs-proxy-journal-rejection.v1` `{channel_id, consumed, event_seq,
  event_type, inconsistent, proxy_session_id, reason, request_sha256, schema_version, vm_instance_id}`,
  응답은 kind 2 `nfs-proxy-journal-reject.v1` `{event_seq, journal_id, reason, request_sha256,
  schema_version}`이다. 기대한 seq의 request는 수락·거부와 관계없이 seq를 소비한다(`consumed`).
  낮은 seq의 같은 digest는 기억한 응답을 다시 보내고 append하지 않는다. 낮은 seq의 다른 digest는
  `sequence_conflict`, 높은 seq는 `sequence_violation`이며 둘 다 seq를 소비하지 않는다.
- **Terminal과 summary 대조.** `FORWARD_COMPLETE.forwarded_length`는 그 batch `EXPOSURE_INTENT`의
  `final_record_length`와 같아야 하고, `FORWARD_FAILED.bytes_written`은 그보다 작아야 한다.
  `GENERATION_COMPLETE`는 host가 draining으로 본 generation만 `drained`/`reply_unresolved`로 닫을 수
  있다(`aborted`는 admitting에서도 가능). `drained`는 `reply_unresolved_count = 0`이어야 하고,
  `exposure_batch_count`는 host가 받은 그 generation의 batch 수와 같아야 한다. `RUN_COMPLETE`는 모든
  generation이 closed이고 모든 batch가 terminal이며 generation, batch, complete/failed 수가 host 값과 같을
  때만 받는다. 그 위에서 session이 clean해야 한다: 그 session의 channel로 들어온 rejection이 하나도
  없고, generation summary와 `RUN_COMPLETE` 자신의 `evidence_path_failures`가 모두 0이어야 한다.
  어긋나면 `closure_mismatch`, `summary_mismatch`, `generations_open`, `forward_length_mismatch`,
  `session_dirty`로 거부하고 inconsistent로 남긴다. rejection은 journal에 저장되므로 restart replay도
  같은 판정을 낸다.
- **Append 실패.** append나 저장 한도 초과가 실패하면 응답 없이 channel을 끝낸다. guest는 그 event와 뒤의
  pending event를 LOST로 본다. frame 하나가 segment 한도보다 크면 쓰기 전에 같은 방식으로 실패한다(새
  segment에 혼자 써도 recovery가 거부하므로, ACK한 record는 모두 같은 설정으로 복구된다).
- **Segment recovery.** segment는 `<name>.NNNN.njnl`이다. restart는 모든 segment의 완전한 frame을 순서대로
  다시 admission해 같은 상태를 만들고, 새 segment에 이어 쓴다. 부분 tail은 자르거나 재사용하지 않는다.
  완전한 frame의 손상은 corruption으로 시작을 거부한다.
- **Transport.** guest는 virtio-serial port(`/dev/virtio-ports/NAME`)를 stream으로 쓰고, QEMU chardev가 host
  Unix socket(`ChannelServer`)에 client로 붙는다. 연결은 VM 하나의 channel identity로 고정된다.
- **Guest 순서.** journal.c는 한 번에 event 하나만 보내고, 답이 없으면 `retransmit_ms`(기본 1000 ms) 뒤 같은
  bytes를 다시 보낸다. 답은 sink가 쓰는 canonical 문서 그대로여야 한다. 모든 field의 존재, 타입,
  범위(`committed_end_offset` > 80 등), 추가 field 없음, key 순서와 공백까지 값을 다시 직렬화해 bytes로
  비교한다. 그 위에서 binding의 `proxy_session_id`/`rule_set_id`, `event_seq`, `request_sha256`가 모두
  맞아야 ACK로 받아들인다. guest는 `vm_instance_id`/`channel_id`를 모르므로 형식만 검사한다.
- **세션 종료.** relay가 멈춘 뒤 Proxy는 먼저 남은 답과 그 답이 만드는 event(held batch의
  `FORWARD_FAILED`, drain bound에서 닫히는 generation의 `GENERATION_COMPLETE`)를 모두 처리한다. 모든
  event가 ACK됐고, 기록하지 못한 event가 없고(동기 submit·추적 실패나 `evidence_path_failures`가 있으면
  `evidence_path_degraded`), 연 generation이 모두 summary까지 ACK됐고, 모든 batch가 terminal일 때만 마지막으로
  `RUN_COMPLETE`를 보낸다. 아니면 보내지 않고 Runner의 session end에 맡긴다. 이미 답을 받은 seq의 ACK는 무시하고, 그 밖의 잘못된 frame,
  EOF, I/O 오류는 pending event 전부를 LOST로 만든다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| CompiledMutationRule snapshot을 replay source로 저장 | Agent/Compiler evolution이 replay meaning을 바꾸지 않게 함 |
| production concrete bytes를 evidence로 분리 | dynamic state 값이 replay에서 달라질 수 있음 |
| replay current bytes를 다시 resolve/verify | wrong-buffer patch를 막으면서 dynamic replay 허용 |
| rule-set execution을 하나의 delta scope로 사용 | same-snapshot multi-rule batch/conflict semantics 보존 |
| semantic batch signature multiset 비교 | stream ordinal 없이 batch composition/cardinality 비교 |
| EXPOSURE_INTENT를 forwarding 전에 durable | crash 직전 mutation candidate가 사라지지 않게 함 |
| append-only events 사용 | crash-cut 상태를 in-place counter 하나로 덮어쓰지 않음 |
| forward completion을 별도 event로 기록 | local mutation build와 peer socket write를 분리 |
| delivery_unknown을 명시 | socket write와 disk commit은 atomic transaction이 아님 |
| replay도 같은 semantic runtime path 사용 | produce/replay semantic drift 방지 |
| production delta를 replay 중 immutable하게 유지 | reproduction evidence 오염 방지 |
| exact original condition은 rule predicate로 표현 | concrete snapshot을 implicit replay identity로 만들지 않음 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| production concrete edits를 그대로 replay | current engine 재사용 쉬움 | dynamic state에서 stale original/offset | 비채택 |
| production original bytes 항상 exact-match | wrong target 방지 강함 | semantically same dynamic record도 거부 | 비채택 |
| original verification 완전 제거 | dynamic replay 쉬움 | TOCTOU/wrong-buffer 위험 | 비채택 |
| replay-time current original 새로 verify | dynamic semantics + apply safety | semantic resolver 필요 | 채택 |
| rule applied_count만 비교 | 구현 단순 | same count/different batch composition 놓침 | 비채택 |
| semantic batch signature multiset | order-independent batch equivalence | signature normalization 필요 | 채택 |
| forward 성공만 기록 | delivery certainty 높음 | crash 직전 mutation record 소실 가능 | 비채택 |
| forwarding 전 write-ahead intent | crash survival | delivery 별도 tracking 필요 | 채택 |
| in-place lifecycle update | compact | crash-cut 의미/torn update 복잡 | 비채택 |
| append-only lifecycle events | complete prefix 해석 가능 | artifact가 더 커짐 | 채택 |

## 영향

### 상류

Semantic runtime은 stable `CompiledMutationRule` serialization을 제공해야 한다.
Edit Applier는 final batch output과 per-application concrete evidence를 Delta Recorder에
제공해야 한다. Relay는 full-write completion을 batch token과 연결해 notify해야 한다.

### 하류

M1 Judge는 delivery state와 semantic application evidence를 읽을 수 있다.
Replay Runner는 matching ProtocolSchema와 scenario/harness input을 준비해야 한다.
Crash Report는 production Delta와 ReplayResult/Q2 evidence를 함께 묶을 수 있다.

### 운영

Per-mutation synchronous durability write가 필요하다. Semantic all-matches campaign의
actual write volume은 real workload로 재검증한다.

Journal snapshot은 hostile/malformed traffic에서 나온 data를 포함할 수 있으므로
모든 serialized length/count는 bounded여야 한다.

## 신뢰성 요구

가장 위험한 오류는 두 종류다.

```text
1. production mutation이 있었는데 durable evidence가 없음
2. replay가 다른 semantic target을 바꿨는데 equivalent라고 판정
```

| 항목 | 요구 |
|---|---|
| crash survival | mutated output exposure 전에 EXPOSURE_INTENT가 host sink `(D)`에 도달 |
| replay safety | schema/rule/context/target을 live semantic path에서 재검증 |
| apply safety | replay-current original bytes verify-before-apply |
| ambiguity | delivery/corruption/schema drift를 explicit state로 남김 |
| ordering | replay selector가 event/stream ordinal을 사용하지 않음 |
| immutability | production MutationDelta는 replay 중 수정하지 않음 |

Artifact reader는 corrupt data를 permissive하게 해석해서 replay하지 않는다.

## 검증 오라클

### 1. dynamic original replay

Production/replay에서 같은 semantic target의 stateid bytes를 다르게 만든다.

Expected:
- production original mismatch만으로 replay를 거부하지 않음;
- replay semantic predicate/target이 맞으면 replay-current bytes에서 transform;
- replay-current original을 apply 직전에 verify.

### 2. explicit stable predicate

Rule에 `target == literal` predicate를 넣고 replay value를 다르게 만든다.

Expected:
- predicate false;
- mutation 없음;
- production concrete snapshot을 implicit predicate로 사용하지 않음.

### 3. same batch multiset, different arrival order

Production/replay RPC arrival order를 바꾸되 semantic mutation batch set은 같게 만든다.

Expected: `REPLAY_EQUIVALENT`.

### 4. same rule counts, different batch grouping

Production에서는 [A,B]가 한 record에 적용되고 replay에서는 [A], [B]로 나뉘게 만든다.

Expected: `REPLAY_DIVERGED`.

### 5. extra / missing semantic match

Replay에서 production에 없던 match를 추가하거나 production batch 하나를 없앤다.

Expected:
- batch signature/cardinality mismatch;
- REPLAY_DIVERGED.

### 6. schema / transform incompatibility

Recorded schema_id 또는 versioned transform semantics를 runtime에서 지원하지 않게 한다.

Expected:
- no substitution/remap;
- REPLAY_INVALID.

### 7. durability before exposure

Delta append를 강제로 실패시킨다.

Expected:
- mutated record가 relay에 노출되지 않음;
- unrecorded mutation 없음.

### 8. crash after EXPOSURE_INTENT

Intent durability 직후 process를 종료한다.

Expected:
- batch concrete evidence survives;
- no FORWARD_COMPLETE;
- delivery_unknown.

### 9. crash after socket write, before FORWARD_COMPLETE

Full local write 직후 completion event 전에 종료한다.

Expected:
- artifact does not claim definite complete delivery;
- delivery_unknown.

### 10. known forward failure

Relay full-write를 실패시키고 failure callback을 만든다.

Expected:
- FORWARD_FAILED;
- confirmed delivery로 세지 않음.

### 11. torn final journal event

마지막 event를 중간에서 truncate한다.

Expected:
- complete prefix recovered;
- torn tail not committed;
- earlier events preserved.

### 12. middle journal corruption

중간 event integrity를 깨뜨린다.

Expected:
- artifact corrupt;
- silent skip/replay 금지.

### 13. production delta immutability

Replay 전/후 production MutationDelta bytes를 비교한다.

Expected: unchanged.

### 14. replay crash durability

Replay 중 target crash를 일으킨다.

Expected:
- separate replay log에 last EXPOSURE_INTENT surviving;
- production delta unchanged.

### 15. guest crash after host ACK

host sink가 `EXPOSURE_INTENT`를 ACK한 직후 guest kernel crash 또는 VM teardown을 일으킨다.

Expected:
- host journal에 EXPOSURE_INTENT가 남는다;
- forward event가 없으므로 delivery_unknown이다;
- guest 안의 파일에 의존하지 않는다.

### 16. host ACK 유실

host append는 끝나고 ACK만 유실되게 만든다.

Expected:
- Proxy는 mutated output을 노출하지 않는다;
- journal의 EXPOSURE_INTENT는 적용 evidence로 남고 delivery로 승격되지 않는다.

### 17. sink 불가 / event 거부

sink를 끊거나 inconsistent correlation event를 보낸다.

Expected:
- mutated output이 노출되지 않는다;
- record는 변조 없이 relay된다;
- 그 generation의 evidence는 불완전이며 M1은 positive evidence가 없으면 `INCONCLUSIVE`다.

### 18. 다음 generation의 crash

generation G에서 rule을 적용하고 G+1에서 crash를 일으킨다.

Expected:
- `CrashContextWindow`가 G와 G+1을 순서대로 고른다;
- replay가 위치별로 비교한다;
- G의 evidence가 없으면 multi-generation attribution은 `INCONCLUSIVE`다.

### 19. generation closure

G에서 시작한 CALL의 eligible REPLY를 deactivation(G) 전후와 closure(G) 전후로 옮긴다. drain 중에 같은
lane에서 G+1을 활성화한다.

Expected:
- closure 전에 도착한 REPLY의 application은 G의 `EXPOSURE_INTENT`로 남고 G의 summary 앞에 온다;
- closure 뒤에 도착한 REPLY는 변조되지 않고 `late_after_close`로 세어진다;
- draining G의 event는 G+1로 바뀌지 않고 G binding으로 검증된다;
- drain bound 만료로 닫힌 G에서 `reply` rule의 M1은 `NOT_APPLIED`가 아니다;
- 봉인된 clean `NOT_APPLIED` 뒤에 G의 application이 추가되면 FAIL이다.

### 20. crash-cut hard refusal

성공 batch multiset은 같고 한쪽에만 hard refusal이 있는 두 실행을 만든다. 각각 summary 전에 종료시킨다.

Expected:
- refusal이 있는 쪽의 `APPLY_REFUSAL`이 거부된 record의 relay 전에 host journal에 있다;
- comparator가 둘을 `REPLAY_DIVERGED`로 구분한다;
- 한쪽의 `APPLY_REFUSAL`을 sink가 거부하게 하면 `refusal_evidence = unknown`이고 `REPLAY_INCONCLUSIVE`다;
- 한쪽의 `APPLY_REFUSAL` 요청이 host에 닿지 않게 하고 ACK timeout 뒤 guest를 종료한다. 거부된 record와 그
  connection·방향의 뒤 record가 peer에 relay되지 않았어야 한다. timeout 뒤 원본 record가 relay됐는데
  `prefix_complete`나 `REPLAY_EQUIVALENT`가 나오면 FAIL이다;
- sink 무응답으로 traffic이 멈춰 종료된 실행은 `refusal_evidence = unknown`이고 `REPLAY_INCONCLUSIVE`다;
- 여러 connection에서 같은 rule의 hard refusal을 동시에 만든다. 첫 `APPLY_REFUSAL`의 ACK 전에는 어느
  connection에서도 거부된 record가 peer에 relay되지 않아야 하고(peer capture로 확인), 다른 connection의
  event가 필요 없는 record는 계속 relay되어야 한다;
- 거부된 record가 relay되기 전에 guest를 종료하면 `prefix_complete`이고, relay된 traffic만으로 비교한다.
  refusal이 없는 쪽과 relay된 traffic이 같으면 `REPLAY_EQUIVALENT`가 될 수 있다;
- host 응답 없이 거부된 record가 relay된 것이 peer capture에 보이면 구현 오류이며 test FAIL이다;
- 여러 connection이 event를 만들 때 sink가 `event_seq` 빈틈을 보면 sequence violation이고, 그 session은
  내부 불일치다;
- refusal이 없는 정당한 crash-cut prefix 두 개는 `REPLAY_EQUIVALENT`가 될 수 있다. crash-cut이라는 이유만으로
  비교를 막으면 FAIL이다;
- `delivery_unknown`만 다른 두 실행을 `REPLAY_DIVERGED`로 판정하면 FAIL이다.

### 21. event scope와 재수신

ACK를 유실시켜 같은 event를 다시 보내고, 같은 `event_seq`에 다른 payload, stale `proxy_session_id`, 다른 lane의
correlation을 보낸다. 활성 generation이 없을 때 `RULESET`을 보낸다.

Expected:
- generation이 없을 때의 `RULESET`은 받아들인다;
- G+1 없이 deactivation(G)을 처리한다. `GENERATION_DRAINING(G)`의 host ACK 뒤에만 deactivation이 ACK되고,
  그 뒤 G의 CALL-context event는 거부되어 기록되며, G의 eligible REPLY event는 받아들여진다;
- `GENERATION_DRAINING(G)`의 host ACK를 막으면 deactivation은 ACK되지 않고 barrier 실패로 처리된다. 그 전에
  유효한 `EXPOSURE_INTENT(G, rule=r)`가 ACK된 rule r은 `APPLIED`를 유지하고, `EXPOSURE_INTENT`가 없는 rule은
  `INCONCLUSIVE`다. 어느 rule도 `NOT_APPLIED`가 되면 FAIL이다;
- 같은 lane에 admitting generation이 남아 있을 때의 `GENERATION_OPEN`은 거부된다;
- generation-scoped event는 open generation binding 없이는 거부한다;
- 재전송은 다시 ACK되고 application이 한 번만 세어진다;
- `GENERATION_DRAINING(G)` 뒤 같은 lane의 `GENERATION_OPEN(G+1)`(`draining_generations = [G]`)을 받아들이고, 그 뒤 G의
  REPLY event와 G+1의 event를 각각의 binding으로 받는다;
- `EXPOSURE_INTENT(batch=b)` 뒤의 `FORWARD_COMPLETE(batch=b)`를 받아들이고, b의 두 번째 종료 event는 거부한다;
- 충돌, stale session, wrong lane은 새 generation에 편입되지 않고 거부와 함께 host에 기록된다.

## 실패 양상과 진단

| 증상 | 가능한 원인 | 구분하는 관측 | 조치 |
|---|---|---|---|
| delta open 실패 | missing/corrupt artifact | header/read status | replay invalid |
| schema_unavailable | matching ProtocolSchema 없음 | schema_id lookup | package 보완 |
| runtime incompatible | semantic runtime/transform version 불일치 | version check | compatible runtime 사용 |
| replay batch missing | scenario/context drift | batch signature diff | replay diverged |
| replay extra batch | new all-match traffic | batch signature diff | replay diverged |
| same count, grouping 다름 | rules가 다른 records에 적용됨 | batch multiset | replay diverged |
| production/replay bytes 다름 | dynamic semantic value | typed snapshots + rule | 별도 진단 |
| EXPOSURE_INTENT만 존재 | crash window | no terminal event | delivery_unknown |
| FORWARD_FAILED | relay/socket failure | batch terminal event | M1/Q2와 분리 |
| torn final event | crash during append | valid prefix + incomplete tail | tail 무시 |
| middle corruption | storage corruption/bug | integrity/sequence failure | artifact invalid |
| replay orig verify 실패 | replay-time TOCTOU/wrong buffer | current precondition bytes | apply refusal |
| host ACK 없음 | sink 장애, channel 단절, ACK 유실 | sink/transport 상태, host journal의 intent 존재 여부 | mutated output 노출 안 함, generation evidence 불완전 |
| G summary 뒤 G event 또는 sink의 post-close 거부 기록 | Proxy closure 구현 오류, correlation 오류 | 봉인 journal의 event 순서, host 거부 기록 | 그 generation 확정 verdict 없음, Proxy lifecycle 수정 |
| `reply` rule이 `reply_unresolved`로 `INCONCLUSIVE` 반복 | drain bound가 짧음, timeout/capacity 설정 | `reply_unresolved_count`, entry 종료 사유 | bound/capacity 조정 |
| crash window 선행 entry 없음 | window bound 초과, program/delta artifact 유실 | `CrashContextWindow` 보존 기록 | multi-generation attribution `INCONCLUSIVE` |

## 한계와 미결 사항

- **결정됨:** MutationDelta replay source는 recorded `CompiledMutationRule[]`이다.
- **결정됨:** Replay는 Agent와 Compiler를 다시 호출하지 않는다.
- **결정됨:** production concrete original/mutated bytes는 evidence이며 default replay identity가 아니다.
- **결정됨:** replay-time current bytes를 새로 resolve하고 verify-before-apply한다.
- **결정됨:** exact stable original 요구는 semantic predicate로 표현한다.
- **결정됨:** Delta logical scope는 one `ProgramGenerationExecution`이다. physical host journal은
  여러 generation을 multiplex할 수 있다(issue #2).
- **결정됨:** crash replay는 `CrashContextWindow`의 순서 있는 generation 목록을 위치별로 비교한다(issue #2).
- **결정됨:** application durability unit은 one mutated RPC record batch다.
- **결정됨:** semantic batch signature multiset으로 replay cardinality/composition을 비교한다.
- **결정됨:** EXPOSURE_INTENT는 mutated output을 relay에 노출하기 전에 host sink `(D)`에 도달해야 한다.
- **결정됨:** failure domain은 Proxy process, guest kernel, VM teardown, Runner process 장애다. host
  OS/storage 손실은 범위 밖이며 per-event `fsync`는 요구하지 않는다(issue #3).
- **결정됨:** generation마다 `GENERATION_OPEN`으로 시작해 closure 뒤 마지막 event인
  `GENERATION_COMPLETE`로 끝난다. clean 여부는 closure reason과 rule의 message type으로 정한다
  (§21, issue #4, issue #18 F1).
- **미결:** drain bound의 숫자.
- **결정됨:** (generation, rule)마다 첫 hard refusal은 relay 전에 `APPLY_REFUSAL`로 write-ahead한다.
  replay 판정은 refusal 분류, refusal evidence 완전성, 판정 순서(§29)를 따른다(issue #18 F2).
- **결정됨:** `APPLY_REFUSAL`에 host 응답이 없으면 거부된 record를 relay하지 않고 같은 event를 다시
  보낸다. 그래서 host에 닿지 않은 refusal 뒤에 relay된 record는 없다. 완전성을 이 규칙으로 입증할 수 없는
  종료(sink 거부, sink 무응답 stall)는 `unknown`이다(§21, §29, PR #22 review).
- **결정됨:** production journal은 append-only lifecycle events를 사용한다.
- **결정됨:** socket delivery와 disk commit의 atomicity gap은 `delivery_unknown`으로 표현한다.
- **결정됨:** production MutationDelta는 replay 중 immutable이다.
- **결정됨:** replay도 same Decoder/Context/Resolver/Edit Applier path를 사용한다.
- **결정됨:** NFSPDLT1/2 literal-original semantics는 target dynamic replay identity가 아니다.
- **미결:** semantic MutationDelta exact serialization.
- **미결:** event framing/integrity algorithm.
- **미결:** semantic_runtime_version versioning scheme.
- **미결:** concrete output snapshot 전체를 inline할지 여부.
- **미결:** ReplayResult on-disk representation.
- **미결:** guest-to-host journal transport와 host sink framing 세부.
- **결정됨:** event는 session-scoped와 generation-scoped로 나뉜다. sink admission, identifier 범위, 재수신과
  충돌 처리는 §6의 표를 따른다(issue #18 F3).
- **미결:** ACK timeout으로 노출을 포기한 batch에 sink 복구 뒤
  `FORWARD_FAILED(reason=not_exposed_after_ack_timeout)`를 남길지. issue #3에 비차단 제안으로 올렸고
  아직 합의되지 않았다. 남기지 않아도 그 batch는 `delivery_unknown`으로 안전하게 남는다.
- **미결:** relay full-write completion callback/token API.
- **미결:** journal size/snapshot value numeric caps.
- **미결:** legacy NFSPDLT1/2 compatibility reader 유지 여부.
- **미검증:** host 동기 ACK와 generation barrier 왕복의 syz-manager throughput 영향.

## 참조

- `docs/design/03-nfs-proxy/01-architecture.md`
- `docs/design/03-nfs-proxy/02-semantic-decoder.md`
- `docs/design/03-nfs-proxy/03-transaction-context.md`
- `docs/design/03-nfs-proxy/04-semantic-mutation-runtime.md`
- `docs/design/02-llm-agent/08-mutation-rule-set.md`
- `docs/design/02-llm-agent/04-harness-capability-spec.md`
- `tools/nfs-proxy/src/delta.h`
- `tools/nfs-proxy/src/delta.c`
- `tools/nfs-proxy/src/edit.h`
- `tools/nfs-proxy/src/edit.c`
- `tools/nfs-proxy/src/control.c`
- `tools/nfs-proxy/test/test_delta.c`
- `tools/nfs-proxy/test/test_edit.c`
- `tools/nfs-proxy/test/test_control.c`
- `tools/nfs-proxy/test/guest-delta-replay.c`

## Agent 사용 지침

### 지원 범위

Agent가 replay 가능한 semantic mutation이라고 가정하려면 current implementation에서
최소 다음이 검증되어야 한다.

```text
CompiledMutationRule durable serialization
matching ProtocolSchema retention
same semantic Resolver/Edit Applier replay path
production EXPOSURE_INTENT durability (Runner host sink `(D)`)
dynamic replay-current resolution
batch signature/cardinality comparison
replay execution logging
```

Target design 문서가 존재한다는 사실만으로 HCAP-09가 semantic replay를 지원한다고
가정하지 않는다. HCAP-09는 현재 NFSPDLT1/2 concrete replay capability다.

### 비지원 범위

다음 경우 semantic replay 성공을 주장하지 않는다.

```text
schema/runtime version unavailable
recorded rule set을 exact semantic form으로 load할 수 없음
dynamic replay를 production literal original로 강제해야만 하는 current backend
batch signature/cardinality comparison 없음
delivery state를 알 수 없는데 complete라고 가정
legacy concrete delta를 semantic delta라고 취급
```

필요한 campaign이 target semantic replay를 요구하지만 implementation이 없으면
`HarnessGapIssue(gap_class=mutation_engine)`로 block한다.

### 확장 절차

Semantic Delta/Replay 구현 시 semantic delta serialization, Delta Recorder, relay
completion callback, Replay loader/runtime, ReplayResult comparison, legacy compatibility,
host/guest tests와 Harness Capability Specification을 함께 갱신한다.

### 제약

```text
recorded CompiledMutationRule is replay source
no Agent/Compiler rerun
no runtime XID/connection/ordinal replay identity
production concrete bytes are evidence
replay-current verify-before-apply
all rule set replayed together
production delta immutable
write-ahead exposure intent
delivery_unknown kept explicit
Q1/M1/Q2 evidence separated
```

### 검증 방법

Semantic replay capability를 validated로 올리려면 dynamic-original replay,
stable-predicate negative test, batch multiset comparison, extra/missing divergence,
schema/transform incompatibility, durability/crash-cut tests, torn-tail/corruption tests,
production-delta immutability와 guest/runtime replay를 통과해야 한다.

Current NFSPDLT1/2 replay success만으로 target semantic replay capability를 validated로
올리지 않는다.

## 다음 상세 설계

```text
1. [`Implementation gap analysis`](06-implementation-gap-analysis.md) — current-vs-target mapping fixed
2. Proxy implementation
```
