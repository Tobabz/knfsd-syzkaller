# NFS Proxy Target-vs-Current Implementation Gap Analysis

> 상태: draft · 최종 확인: 2026-10-12
> 기준: kernel v7.3-rc5 / syzkaller 801f0966669a37e048adabf9e5f38ce52825ea82
> 대상 구현: `tools/nfs-proxy`
> 상위 설계: `01-architecture.md`
> 상세 계약: `02-semantic-decoder.md`, `03-transaction-context.md`,
> `04-semantic-mutation-runtime.md`, `05-mutation-delta-replay.md`
> 목적: target architecture를 current implementation에 매핑해 구현 순서를 결정

## 요약

Current `tools/nfs-proxy`는 SunRPC/TCP framing, four-route relay, fixed/variable
concrete edit, verify-before-patch, durable NFSPDLT1/2 replay에 강한 Layer 0 substrate를
이미 가진다. 반면 target architecture의 ProtocolSchema, semantic NFS decoder,
Transaction Context, semantic rule ABI/Resolver, semantic journal/replay는 구현되어
있지 않다.

따라서 구현 전략은 current Proxy를 버리고 새로 만드는 것이 아니라:

```text
preserve
    framing / relay / concrete edit safety / legacy tests

refactor or extend
    connection identity
    RPC parsing boundary
    concrete edit batch API
    relay write-completion lifecycle

add
    ProtocolSchema
    Semantic Decoder
    Transaction Context
    semantic rule serialization / Resolver
    semantic MutationDelta / Replay
```

이다. 그리고 `tools/nfs-proxy` 밖의 syzkaller/Runner 통합(S1: executor activation
barrier, Runner host journal sink, `CrashContextWindow`)이 함께 필요하다(§34).

가장 큰 architectural incompatibility는 current `control.c`의 v1 -> v2 sequential
mutation과 `edit.c`의 equal-offset rule-order tie-break다. Target runtime은 모든
semantic rule을 같은 pre-mutation snapshot에서 resolve하고 conflict를 apply 전에
명시적으로 거부해야 한다.

## 해결하려는 문제

Target design이 구현보다 앞서 있으므로 다음 질문에 답해야 한다.

```text
무엇을 그대로 쓸 수 있는가?
무엇은 adapter만 있으면 되는가?
무엇은 target invariant에 맞춰 확장해야 하는가?
무엇은 current semantics가 target과 충돌해 교체해야 하는가?
무엇이 완전히 없는가?
```

이 구분 없이 바로 구현하면 두 가지 위험이 있다.

첫째, 이미 검증된 framing/edit/replay safety property를 불필요하게 다시 구현할 수 있다.

둘째, current NFSPARM1/2의 byte-oriented semantics를 target architecture로 잘못
고착시킬 수 있다.

## 구조

```text
  target contracts                         current code
  ----------------                         ------------
  Record Framer -------------------------- framing.c
  RPC Decoder ---------------------------- walk.c (partial)
  ProtocolSchema ------------------------- missing
  NFS Semantic Decoder ------------------- missing
  ConnectionRef -------------------------- struct conn (partial)
  Transaction Context -------------------- missing
  CompiledMutationRule ABI --------------- NFSPARM1/2 (different)
  Semantic Rule Resolver ----------------- missing
  Edit Applier --------------------------- delta.c/edit.c substrate
  Semantic Delta Recorder ---------------- NFSPDLT1/2 (different)
  Replay --------------------------------- concrete replay only
  Forward completion evidence ------------ aggregate queue stats only
  Host journal sink (Runner) ------------- missing (deltas in guest)
  Generation activation (executor) ------- program-scoped legacy arm
  CrashContextWindow (syz-manager) ------- LastExecuting (partial)
        |
        v
  Gap Matrix
        |
        v
  Implementation dependency order
```

## 설계

### 1. 상태 분류

이 문서에서 각 target element를 다음 중 하나로 분류한다.

| 상태 | 의미 |
|---|---|
| `reuse_as_is` | target contract에 그대로 사용 가능 |
| `reuse_with_adapter` | core invariant는 맞고 interface/coordinate adapter만 필요 |
| `extend` | current component를 유지하되 target 기능을 추가해야 함 |
| `replace` | current semantics가 target과 충돌해 target path를 별도로 구현해야 함 |
| `missing` | target component가 current code에 없음 |

이 분류는 legacy NFSPARM1/2 compatibility code를 삭제하라는 뜻이 아니다.
Target Agent-facing path와 current compatibility path는 병존할 수 있다.

### 2. Gap Matrix

| Target element | Current implementation | Status | Reusable pieces | Required changes | Validation |
|---|---|---|---|---|---|
| Record Framer / RpcRecord | `framing.c`, `proxy.c` | reuse_with_adapter | bounded fragment parsing, complete-record detection, relay buffering | marker-free canonical `rpc_payload` view/reassembly, output reframing boundary | existing framing tests + multi-fragment semantic decode |
| RPC Decoder | `walk.c` partial RPC walk | extend | bounds-checked cursor, CALL envelope/auth parsing, reply envelope parsing | isolate RPC envelope decoder from NFS walk; operate canonical payload; preserve reply status/auth semantics | RPC golden/truncation vectors |
| ProtocolSchema / Normalizer | none | missing | syzkaller request descriptions only as cross-check | pinned XDR source, annotations, deterministic normalizer/artifact | schema generation + cross-check |
| NFS Semantic Decoder | `walk.c` only COMPOUND header/first opcode/raw body | missing | cursor/XDR helpers, current header tests | full NFSv3 + v4.0/v4.1/v4.2 schema walk, SemanticField/WireRef | 02 contract oracle |
| ConnectionRef | `struct conn` pairs client/backend sockets | extend | connection lifecycle, route, half-close handling | stable `connection_id`; pass lifecycle/ID to semantic callbacks | reconnect/fd-slot reuse test |
| Transaction Context | none | missing | same-thread event loop ordering | connection_id + call_direction + XID table, lifecycle, bounded retention | 03 contract oracle |
| Semantic control ABI | NFSPARM1/NFSPARM2 (program-armed, FD lifetime) | missing | Unix SOCK_SEQPACKET control transport, ACK model | Runner-installed immutable rule set per proxy session (`rule_set_id`); executor-only activation/deactivation barrier per generation; versioned rule-set serialization, schema/runtime IDs, typed rules; legacy arm refusal while target is installed | decode/validation, barrier ACK-loss/orphan, endpoint isolation tests |
| Semantic Rule Resolver | none | missing | current route scoping concepts | selector/predicate/transform/context dependency runtime | 04 contract oracle |
| Edit Applier | `delta.c`, `edit.c` | reuse_with_adapter | verify-before-patch, original-coordinate rebuild, overlap refusal, one-pass output rebuild | consume conflict-free concrete edit batches instead of matching raw rules; remove semantic dependence on rule order | current tests + batch adapter tests |
| Structure derivation | `edit.c` op-count + record-marker rebuild | extend | COMPOUND op-count bump, final marker rebuild | schema-derived length/count/padding/discriminant fixups from final structure | preserve/raw semantic tests |
| Rule-set same-snapshot preflight | v1 then v2 sequential in `control.c` | replace | v2 multi-rule batch aggregation idea | all semantic rules resolve on original record; global conflict preflight; one final apply | registration-order permutation tests |
| Delta Recorder | NFSPDLT1/2 writer (guest `O_SYNC` file) | replace | bounded binary IO, corruption refusal; guest `O_SYNC` stays legacy only | per-generation semantic journal events (RULESET/GENERATION_OPEN/GENERATION_DRAINING/EXPOSURE_INTENT/APPLY_REFUSAL/FORWARD_*/GENERATION_COMPLETE) with generation correlation, sent to the host sink | 05 crash-cut oracle incl. guest crash after host ACK |
| Forward completion lifecycle | `queue.pending_records`, aggregate delivered stats | missing | nonblocking queue/flush loop | per-record/batch token boundaries and full-write completion/failure callback | partial-write/full-write tests |
| Semantic Replay loader/runtime | concrete NFSPDLT1/2 loader in `control.c` | replace | CLI replay mode, shared process path, legacy replay tests | load recorded CompiledMutationRule set, run the ordered `CrashContextWindow` programs, same semantic runtime path, separate replay log on the host sink | dynamic replay + multi-generation + compatibility tests |
| ReplayResult comparator | none | missing | current applied-count diagnostics | per-position batch-signature multiset + delivery comparison and verdict, in the Controller-side validation layer over sealed production/replay evidence (issue #11) | equivalent/diverged/invalid tests |
| Legacy compatibility | NFSPARM1/2 + NFSPDLT1/2 | reuse_as_is | validated current campaigns/tests | keep isolated from target semantic ABI; do not expose as semantic capability; never active on a lane together with a target rule set; usable only by manual/legacy campaigns (HCAP-07/08/09), never lowered from an Agent MutationRuleSet (issue #8) | full existing regression suite |
| Runner/main integration | `main.c` control or replay mode | extend | process lifecycle, route CLI, stats | schema/runtime inputs, semantic ruleset/replay artifact, replay log output | startup/mode integration tests |
| HCAP registration | HCAP-07/08/09 describe current concrete layer | extend | stable current capability IDs/evidence | proxy build generates the semantic capability registry; promote a subset's registry digest and scope only after the M7 gate; HCAP references the promoted registry by digest and never lists paths in prose (issue #14) | registry digest matches the build + M7 guest evidence in HCAP evidence_refs |
| Host journal sink (Runner) | none; deltas live in the guest | missing | read-only 9P host share exists for fixture input only | Runner-owned sink, guest-to-host channel, host ACK after full framed append, channel identity stamping, untrusted-event validation | 05 oracles 15-17 |
| Executor generation activation (syzkaller) | `syz_arm_nfs_proxy*` program-scoped arm (0017/0019); KCOV generation BEGIN/FINISH (0001/0002) | missing | generation boundary, orphan cleanup, 0008 fail-closed lane path | activation/deactivation barrier around program syscalls, orphan-path deactivation before ABORT, generation id and barrier result in exec results, no semantic rule struct in syzlang | barrier, ACK-loss, orphan tests |
| CrashContextWindow (syz-manager) | `pkg/rpcserver` `LastExecuting` (6 programs per proc; `Hanged()` rewrites `Proc`) | extend | per-proc ring of recent programs, crash-time `Collect()` | executor-reported generation id, host-known original lane/proc, MutationDelta references, bound as explicit job policy | crash join with a predecessor generation |

### 3. Record Framer / RpcRecord

#### Current

`framing.c`는 RFC 5531 record marker를 bounded하게 parse하고 multiple fragment를
complete record boundary까지 모은다.

강점:

```text
fragment length bound
fragment count bound
zero-length non-final fragment refusal
incomplete input = need-more
framing error = connection failure
```

Current `nfsp_framing_peek()`가 돌려주는 length는 fragment header를 포함한다.
그리고 `proxy.c::feed()`는 그 buffer를 그대로 `on_record`에 전달한다.

#### Gap

Target `RpcRecord.rpc_payload` coordinate zero는 record marker를 제외한 RPC message다.

현재 multi-fragment record는:

```text
[frag hdr][body 1][frag hdr][body 2]...
```

형태로 callback에 전달되며 `walk.c`는 single-fragment만 semantic walk한다.

`walk.c`의 current comment도 fragmented RPC를 semantic mutation에서 거부한다.

따라서 framing parser 자체는 재사용하되 semantic layer에는:

```text
framed transport record
    |
    v
canonical contiguous rpc_payload
    |
    v
semantic decode
```

adapter가 필요하다.

#### Required change

- fragment bodies를 contiguous `rpc_payload`로 materialize하거나 zero-copy view로 제공.
- semantic offset coordinate를 marker-free payload 기준으로 통일.
- Edit Applier output을 RFC 5531 record로 다시 frame.
- legacy NFSPARM1/2 path는 기존 marker-inclusive coordinates를 계속 사용할 수 있음.

Target semantic API와 legacy concrete API의 coordinate system을 섞지 않는다.

### 4. RPC Decoder

#### Current

`walk.c`에는 이미 reusable한 checked XDR cursor가 있다.

```text
cur_u32
cur_skip_padded
walk_auth
CALL rpcvers/prog/vers/proc
REPLY reply_stat/verifier/accept_stat
```

Current walk는 RPC envelope와 NFSv4 COMPOUND partial walk를 한 component에 함께 둔다.

#### Gap

Target architecture는:

```text
RPC Decoder
    -> RPC envelope only

NFS Semantic Decoder
    -> protocol body
```

로 책임을 분리한다.

또한 current walk offsets는 fragment header 포함 record coordinate를 사용한다.

#### Required change

Current checked parsing logic을 재사용하되 marker-free `rpc_payload`를 입력으로 받는
RPC envelope decoder API를 분리한다.

Target output에는 최소:

```text
message_type
xid
program/version/procedure?   # CALL
reply status
auth/verifier boundaries
body offset
```

가 필요하다.

NFSv3 REPLY의 original procedure는 RPC Decoder가 추측하지 않고 Transaction Context가
보완한다.

### 5. ProtocolSchema / Schema Normalizer

#### Current

없다.

Current syzkaller 0006/0015는 request generation shape를 제공하지만 target contract상
canonical wire schema가 아니다.

#### Required change

새 repository-owned component/data가 필요하다.

```text
pinned RPC/NFS XDR source
        +
semantic annotations
        |
        v
Protocol Schema Normalizer
        |
        v
ProtocolSchema(schema_id)
```

M2에서 normalizer language와 generated artifact format을 정했다. Python 표준 라이브러리 script
(`tools/nfs-proxy/schema/normalize.py`)가 commit된 C table을 만들고, `build.sh`가 table이 최신인지
확인한다. 상세는 `02-semantic-decoder.md`의 한계와 미결 사항에 있다. NFSv4.0/4.1/4.2 XDR은 RFC
7531/5662/7863에서 pin해 반입했고, 4.2에는 knfsd가 구현하는 RFC 8276, RFC 9754 확장을, 4.1과 4.2에는
pNFS layout type RFC 8435, RFC 8154를 합쳤다
(`tools/nfs-proxy/schema/nfs4/`). NFSv3 source는 남았다.

### 6. NFS Semantic Decoder

#### Current

`walk.h`가 의도적으로 선언한다.

```text
Schema layer -- NOT here.
Per-op field tables are a later addition.
```

Current NFSv4 walk는:

```text
COMPOUND status/tag/minor/op count
first opcode
remaining op-array body = raw region
```

수준이다.

NFSv3 body는 semantic decode하지 않는다.

#### Gap

Target `DecodedRpcMessage`, `SemanticField`, `WireRef`를 생성할 component가 없다.

#### Reuse

- checked cursor patterns.
- XDR padded-length checks.
- auth/body-boundary tests.
- truncation regression methodology.

#### New implementation

- ProtocolSchema-driven type walker/decoder.
- NFSv3 procedure request/reply bodies.
- NFSv4.0/4.1/4.2 COMPOUND operation arrays.
- semantic annotation/path lookup.
- exact `encoded_span/value_span/metadata_spans`.
- target contract의 fail-closed status.

Current `nfsp_walk`을 무리하게 확장해 semantic tree까지 넣기보다 legacy Layer 0 walk를
유지하고 target semantic decoder를 별도 component로 추가하는 편이 migration risk가
낮다.

### 7. ConnectionRef

#### Current

`proxy.c::struct conn`은 한 accepted client socket과 backend socket을 묶는다.

```text
client_fd
backend_fd
client
backend
c2s/s2c framing
to_backend/to_client queues
```

Slot은 `conns[NFSP_MAX_CONNS]`에서 재사용된다.

`on_record` callback에는:

```c
client, backend, dir, record, len
```

만 전달된다.

#### Gap

Target Transaction Context에는 slot/fd reuse와 독립적인 stable runtime
`connection_id`가 필요하다.

#### Required change

- `state`에 monotonic/generation-safe next connection ID.
- `struct conn`에 `connection_id`.
- new TCP accept마다 새 ID.
- record callback/lifecycle callback에 ConnectionRef 전달.
- close/reconnect test에서 old ID를 재사용하지 않음.

구체적인 integer width/generation algorithm은 implementation에서 정하되 job 내 uniqueness를
보장한다.

### 8. Transaction Context

#### Current

없다.

Current relay event loop가 control IPC와 record callback을 같은 thread에서 실행한다는 점은
유용하다. 초기 implementation은 lock-free/single-thread context table로 시작할 수 있다.

#### Required change

새 table:

```text
key:
    connection_id
    call_direction
    xid
```

필요 기능:

- CALL minimal insert.
- semantic request enrichment.
- REPLY lookup.
- NFSv3 procedure recovery.
- NFSv4 request/result operation correlation.
- duplicate/reuse ambiguity.
- timeout.
- connection-close purge.
- per-connection/global bounds.

v4.1+ same-connection backchannel은 existing bidirectional relay가 transport substrate로
재사용 가능하다.

v4.0 separate callback TCP connection은 current listener/routing topology가 proxy한다고
가정할 수 없으므로 initial semantic capability에서 별도 gap으로 유지한다.

### 9. Semantic control ABI

#### Current

`control.h` defines two concrete arm packet formats: `NFSPARM1`, `NFSPARM2`.

Useful current properties:

- Unix `SOCK_SEQPACKET` control transport.
- one registration message per control FD.
- ACK after durable rule write.
- arm lifetime bound to FD.
- replay mode mutually exclusive with live control mode.

#### Gap

Target rule is `CompiledMutationRule[]`, not anchor/offset/original bytes.

New semantic registration must carry format/runtime version, schema_id, rule identity,
traffic scope, RPC/NFS selector, semantic target, typed predicates/transform,
structure policy, context dependencies, and `all_matches` application semantics.

The ownership model also changes (issue #2). The current arm is registered by the syz program
through `syz_arm_nfs_proxy*` and lives as long as that program's FD. In the target, the Runner
installs one immutable `CompiledMutationRule[]` per proxy session (`rule_set_id`), and the
executor activates it per remote-KCOV program generation with ACK barriers
(`01-architecture.md` §16). The current control socket is reachable only from the executor
sandbox, so Runner installation needs its own path.

#### Required change

Keep the control transport, but add:

- a versioned semantic rule-set serialization and a Runner-only installation path per proxy session;
- executor-only activation(G)/deactivation(G) messages with ACK, unreachable from fuzz program code;
- barrier-failure handling: activation ACK missing → program not executed, generation ABORT; deactivation ACK missing or unconfirmed inactive state → no lane reuse until cleared, otherwise quarantine/restart;
- refusal of legacy arm registration while a target rule set is installed (legacy and target are mutually exclusive per lane).

NFSPARM1/2 remain legacy compatibility messages. Do not overload NFSPARM2 fields to smuggle
semantic paths or dynamic transforms.

### 10. Semantic Rule Resolver

#### Current

없다. Current matching lives directly inside `nfsp_apply_rule()` and
`nfsp_apply_edit_rules()` and is byte-oriented: route, first opcode, literal anchor,
recorded offset/original.

#### Required change

새 component가 `CompiledMutationRule[] + DecodedRpcMessage + TransactionEntry?`를 받아
semantic scope/selector, typed predicate, typed transform, live WireRef를 resolve하고
`ResolvedMutation[]`을 생성해야 한다.

Current route match code는 helper concept로 재사용할 수 있지만 semantic matching을
`delta.c/edit.c`에 계속 남겨두면 target 책임 분리가 깨진다.

### 11. Edit Applier

#### Current reusable substrate

`edit.c::nfsp_apply_edit_rules()`는 original-record coordinate edit aggregation,
verify-before-patch, overlap refusal, variable-length rebuild, OP_APPEND/OP_PREPEND,
final record-marker rebuild를 이미 가진다.

`delta.c::nfsp_apply_rule()`는 fixed-width verify-before-patch foundation을 가진다.

#### Gap

Current edit API는 semantic resolution과 concrete apply가 섞여 있다.
`nfsp_apply_edit_rules()`는 route/first-opcode/anchor predicate를 다시 평가하고,
op-array boundary를 `nfsp_walk`에서 다시 resolve하며, equal-offset insert ordering에
rule/edit traversal order를 사용한다.

Target Edit Applier는 이미 conflict-free하게 resolve된 concrete batch만 받아야 한다.

#### Required refactor

Core rebuild logic을 `ConcreteEditBatch`를 받는 lower-level apply API로 추출한다.
이 layer는 semantic selector/rule order를 모르고, replay-current original bytes를
verify하고, defensive overlap validation과 one final rebuild만 수행한다.

Current internal resolved-edit sort/rebuild code가 가장 직접적인 reuse substrate다.

### 12. Same-snapshot preflight

#### Current conflict

`control.c`는 original -> NFSPARM1 apply -> `v1_buf` -> NFSPARM2 resolve/apply 순서다.
Code comment도 v2가 same-width v1 patch 이후 buffer를 본다고 명시한다.

또한 `edit.c::resolved.order`는 equal-offset tie-break에 traversal order를 사용한다.

#### Target

모든 semantic rule은 original R0에서 resolve한 뒤 global conflict/structure preflight를
통과하고 one final apply를 수행한다.

#### Required change

Target semantic path에서는 v1/v2 pass 자체가 semantic ordering unit이 되어서는 안 된다.
Legacy NFSPARM1/2 path는 existing behavior를 compatibility mode로 유지할 수 있다.

### 13. Structure derivation

#### Current

`edit.c`는 OP_APPEND/OP_PREPEND boundary를 live walk에서 계산하고 STRUCT mode에서
COMPOUND op count를 live value + bump으로 계산하며 final record marker를 rebuild한다.

#### Gap

Target preserve policy는 XDR length, array count, discriminant where required, padding,
COMPOUND op count를 ProtocolSchema/final semantic structure 기준으로 derive해야 한다.

#### Required change

Semantic Resolver/schema encoder가 final desired structure와 derived concrete edits를
계산하고 Edit Applier는 이를 한 batch로 적용한다. Current op-count/marker logic은
regression reference/substrate로 유지한다.

### 14. Delta Recorder

#### Current

NFSPDLT1/2 writer는 O_SYNC file, durable-before-ACK rule write, in-place applied_count,
bounded binary format, corrupt/truncated refusal을 가진다. `control.c`는 apply 직후 count
write가 성공해야 mutated output을 relay에 반환한다.

#### Gap

Target MutationDelta는 one `ProgramGenerationExecution`, recorded CompiledMutationRule[],
append-only RULESET/GENERATION_OPEN/GENERATION_DRAINING/EXPOSURE_INTENT/APPLY_REFUSAL/FORWARD_*/GENERATION_COMPLETE journal, generation
correlation, batch signatures와 concrete evidence를 요구한다.

Current one-arm file + in-place count model은 이 lifecycle을 표현하지 못한다.

durability 위치도 맞지 않는다. Current delta file은 guest 안에 있다(`bundle/lane/lane.sh`의
`--delta-dir "$lane_root/server/deltas"`, root는 `/tmp/frozen-phase9.manager`). guest kernel crash나
VM 종료(qemu `-snapshot` 기본값)가 일어나면 그 file이 사라질 수 있으므로 guest `O_SYNC`는 target
durability 기반이 아니다(issue #3).

#### Required change

새 semantic journal writer/reader를 구현하고, event를 Runner host journal sink로 보낸다. `(D)`는
host sink가 framed event append 전체를 마친 뒤 보내는 ACK다. Endian helpers, bounded validation,
corruption refusal patterns는 재사용할 수 있다. NFSPDLT1/2 format과 guest `O_SYNC` writer는
legacy compatibility와 host unit test 기반으로 유지한다.

### 15. Forward completion lifecycle

#### Current

`proxy.c` queue는 flat byte buffer와 `pending_records` count를 가진다.
`flush()`는 queue 전체가 drain되면 aggregate `stats->delivered[...]`를 증가시킨다.

이 구현은 throughput/statistics에는 충분하지만 어느 mutated RPC record가 정확히 언제
full-write 되었는지 Delta Recorder에 알려주지 못한다.

#### Gap

Target Delta contract는 `EXPOSURE_INTENT` batch와 이후 `FORWARD_COMPLETE` 또는
`FORWARD_FAILED`를 연결해야 한다.

#### Required change

Queue에 record boundary/token metadata가 필요하다.

예:

```text
queued record
    bytes span
    delivery token?      # unmutated record는 없어도 됨

flush progress
    -> record boundary crossed
    -> on_forward_complete(token)
```

Fatal/partial-write failure 시 아직 complete되지 않은 token에 failure notification을 보낼
수 있어야 한다.

Flat byte queue 자체는 유지할 수 있지만 sidecar record descriptor queue가 필요하다.

### 16. Semantic Replay loader/runtime

#### Current

`nfsp_control_open(... replay_path)`는 file magic으로 NFSPDLT1/2를 읽고 concrete rule을
`arms[]`에 설치한다. Live traffic은 produce와 같은 concrete apply function을 사용한다.

종료 시:

```text
applied == recorded applied_count
refused_orig_diff == 0
```

를 gate로 검사한다.

#### Gap

Target replay는 recorded semantic `CompiledMutationRule[]`을 로드하고 Decoder ->
Transaction Context -> Resolver -> Edit Applier의 same path를 사용해야 한다.

또한 production Delta는 immutable이고 replay execution journal / ReplayResult는 별도다.
crash replay는 crashing program 하나가 아니라 `CrashContextWindow`의 순서 있는 generation 목록을
실행하고 위치별로 비교한다(issue #2).

#### Required change

새 semantic replay loader/runtime를 추가한다. recorded rule set을 설치하고 window의 program을 순서대로
실행하며, replay journal도 host sink에 기록한다.

Legacy `--replay NFSPDLT1/2` path는 compatibility mode로 유지 가능하다.
CLI/file magic dispatch가 semantic delta를 별도 target path로 선택하게 해야 한다.

### 17. ReplayResult comparator

#### Current

없다. Current replay verdict는 concrete per-rule count/original mismatch로만 결정된다.

#### Required change

새 comparator가 window 위치별로 production/replay의 record-level semantic batch signature
multiset, hard refusal과 그 evidence 완전성, delivery evidence를 비교해:

```text
REPLAY_EQUIVALENT
REPLAY_DIVERGED
REPLAY_INCONCLUSIVE
REPLAY_INVALID
```

를 생성해야 한다. refusal 분류와 판정 순서는 `05-mutation-delta-replay.md` §29가 소유한다.

Comparator는 crash/sanitizer Q2를 판단하지 않는다. Comparator는 Proxy가 아니라 Controller 측
validation layer에서 봉인된 production/replay evidence를 비교한다(`../02-llm-agent/01` §11.1,
issue #11).

### 18. Runner / main integration

#### Current

`main.c`는:

```text
plain relay
--control PATH --delta-dir DIR
--replay DELTA_FILE
```

세 mode를 제공한다.

#### Gap

Target semantic runtime에는 최소 다음 input/output이 추가된다.

```text
ProtocolSchema artifact / schema_id
semantic ruleset registration
semantic delta path
semantic replay artifact
replay execution log / ReplayResult output
```

#### Required change

CLI를 곧바로 복잡한 option surface로 확장하기보다 Runner-owned config/artifact path를
명확히 정하고 `main.c`는 그 runtime inputs를 Proxy subsystem에 전달하게 한다.

Exact CLI/config serialization은 implementation milestone에서 결정한다.

### 19. callback / backchannel routing

#### Current

Current accepted connection은 configured backend listener에서 client source IP를 확인한 뒤
해당 backend로 outbound connect하는 model이다.

따라서 같은 TCP connection의 양방향 bytes는 relay하므로 NFSv4.1+ backchannel은 transport
substrate상 통과할 수 있다.

반면 NFSv4.0 server-opened separate callback TCP connection을 Proxy가 reverse-listen/route
한다는 구현 evidence는 없다.

#### Gap

Transaction Context contract는 proxied callback connection이면 처리할 수 있지만 current
topology가 그 connection을 반드시 관찰한다고 가정하면 안 된다.

#### Required change

Initial implementation scope를 명시한다.

```text
v4.1+ same-connection backchannel
    -> target initial support 후보

v4.0 separate callback connection
    -> routing extension until proven otherwise
```

Candidate가 v4.0 callback semantic mutation을 요구하면 current harness에서 지원된다는
HCAP evidence가 생기기 전까지 HarnessGapIssue 대상이다.

### 20. Tests

#### Current reusable tests

```text
test_framing.c
    framing bounds / fragmentation / errors

test_proxy.c
    relay/order/route behavior

test_walk.c
    RPC/NFSv4 header walk + truncation invariants

test_delta.c
    verify-before-patch, durable format, concrete replay

test_edit.c
    variable edit rebuild, overlap, struct/raw behavior

test_control.c
    control lifetime, ACK, durability, replay, v1->v2 chain

guest-delta-replay.c
    deterministic guest replay traffic source
```

이 테스트는 삭제하지 않고 legacy/Layer 0 regression suite로 유지한다.

#### New required test families

```text
schema normalization
RPC decoder payload-coordinate vectors
semantic decoder golden/truncation/malformed vectors
Transaction Context correlation/backchannel/lifetime
semantic rule type validation
selector/predicate/transform resolution
same-snapshot registration-order invariance
cross-rule conflict refusal
preserve/raw structure derivation
semantic journal crash cuts
relay full-write completion
dynamic semantic replay
ReplayResult batch multiset comparison
guest/runtime semantic mutation + replay
```

### 21. Harness Capability Specification mapping

Current HCAP-07/08/09는 이미 검증된 concrete Layer 0 기능을 설명한다.

Gap analysis 결과만으로 semantic capability를 current support로 올리지 않는다.

semantic capability의 세부 범위는 HCAP entry에 나열하지 않는다. Proxy build가 semantic capability registry를
생성하고, implementation + host tests + guest/runtime validation(M7, §30)을 통과한 subset의 registry digest와
scope만 promotion한다. HCAP은 promoted registry를 digest로 참조한다
(`../02-llm-agent/04-harness-capability-spec.md` §4, issue #14). registry가 기술하는 범주는 다음과 같다.

```text
semantic decode coverage
transaction correlation coverage
supported predicates/transforms
semantic mutation kinds/structure policies
semantic delta/replay
callback/backchannel coverage
```

HCAP ID를 지금 임의로 예약하지 않는다.

### 22. Implementation dependency order

```text
M0  Legacy baseline lock
        |
        v
M1  Canonical RpcRecord + RPC Decoder + ConnectionRef
        |
        v
M2  ProtocolSchema + NFS Semantic Decoder
        |
        v
M3  Transaction Context (+ activation_generation)
        |
        v
M4  Semantic rule ABI + Resolver + concrete edit adapter   <-- S1a
        |
        v
M5  Semantic Delta journal (host sink) + relay completion  <-- S1b
        |
        v
M6  Semantic Replay + ReplayResult                         <-- S1c
        |
        v
M7  Guest/runtime validation + HCAP update

S1  syzkaller / Runner integration (병행 track, §34)
    S1a rule set 설치 경로, executor activation/deactivation barrier
    S1b Runner host journal sink + guest-to-host channel
    S1c CrashContextWindow + replay sequence 실행
```

각 milestone은 다음 단계의 input contract를 실제 코드/테스트로 제공한다. 화살표의 S1 항목은 해당
milestone을 완료하기 전에 있어야 한다. 단 M4/S1a는 component 단계이고 host-durable sink를 쓰는 live
target-mode 통합은 M5/S1b gate다(§27, issue #18 F8). M4/M5 전에 M1 판정 계약
(`../02-llm-agent/01-two-stage-agent-architecture.md` §7)이 고정되어 있어야 하며, issue #4에서 고정됐다.

### 23. M0 — Legacy baseline lock

Current host unit tests/build/guest replay smoke path를 기준선으로 고정한다.
NFSPARM1/2와 NFSPDLT1/2 behavior를 regression baseline으로 보존한다.

### 24. M1 — Canonical RpcRecord / RPC Decoder / ConnectionRef

Required output:

```text
ConnectionRef.connection_id
canonical marker-free RpcRecord.rpc_payload
RPC envelope metadata
```

Decoder WireRef coordinate와 Transaction Context key가 이 boundary에 의존하므로 먼저 한다.
Legacy `on_record` path를 바로 깨뜨리지 말고 semantic callback/API 또는 adapter를 추가한다.

### 25. M2 — ProtocolSchema / Semantic Decoder

Required output:

```text
ProtocolSchema(schema_id)
DecodedRpcMessage
SemanticField
WireRef
```

Initial coverage는 current scenarios에 필요한 protocol subset부터 구현할 수 있지만
unsupported schema/op는 fail closed해야 한다. Partial support를 full HCAP support라고
표시하지 않는다.

reply decode를 포함하는 subset은 `reply_dispatch` 입력으로만 REPLY schema를 고른다(`02-semantic-decoder.md`
§6, §14, issue #18 F4). M2 test는 fixture CALL로 dispatch를 공급하고, live dispatch는 M3의 TransactionEntry가
공급한다. request-only subset은 이 조건과 무관하다.

### 26. M3 — Transaction Context

M1의 ConnectionRef/RPC metadata와 M2의 request semantic summary 위에 구현한다.

Required output:

```text
connection_id + call_direction + xid lookup
NFSv3 reply procedure context
NFSv4 request/result context
bounded lifecycle/expiry
```

초기에는 existing single-thread event loop를 활용해 ordering/concurrency complexity를 줄인다.

구현 상태: `src/txn.*`(table), `src/semantic.*`(observer), `main.c --semantic`. NFSv4
request/result context와 bounded lifecycle/expiry가 구현됐다. NFSv3 reply procedure context는
entry가 procedure를 보존하므로 준비됐지만 NFSv3 schema가 없어 decode는 `unsupported_schema`다.
`request.forwarded`는 M4 Resolver 전까지 original 또는 unknown이다(`03` 한계와 미결 사항).

### 27. M4 — Semantic rule ABI / Resolver / concrete edit adapter

```text
CompiledMutationRule serialization + validation
        |
        v
Semantic Rule Resolver
        |
        v
ResolvedMutation[]
        |
        v
global conflict/structure preflight
        |
        v
ConcreteEditBatch adapter
        |
        v
existing rebuild substrate
```

Critical acceptance criterion:

```text
semantic rule registration order permutation
    -> same resolution/conflict/output
```

Legacy v1->v2 chain behavior는 compatibility path에만 남긴다.

**M4 / S1a acceptance 범위 (issue #18 F8).** target rule 설치는 host-durable `RULESET`을, activation ACK는
host-durable `GENERATION_OPEN`을, deactivation ACK는 host-durable `GENERATION_DRAINING`을, mutated output 노출은 host-durable `EXPOSURE_INTENT`를 요구한다
(`05-mutation-delta-replay.md` §7, §11, §21). 그 sink는 M5/S1b에서 생긴다. 그래서 M4와 S1a의 완료는 다음
범위로 한정한다.

| 범위 | M4 / S1a에서 | 어디서 완료하는가 |
|---|---|---|
| Resolver, preflight, concrete edit adapter, eligibility, closure 판정 | host component test. sink는 test double로 바꿀 수 있다 | M4 |
| executor barrier, activation endpoint 격리, barrier 실패 처리 | syzkaller/Runner component test. Proxy 쪽 ACK는 test double로 바꿀 수 있다 | S1a |
| RULESET 설치, `GENERATION_OPEN` 뒤 activation ACK, `GENERATION_DRAINING` 뒤 deactivation ACK, `EXPOSURE_INTENT` 뒤 노출을 실제 host sink로 하는 live target-mode 실행 | 하지 않는다 | M5 / S1b gate |

- test double로 얻은 성공은 component 결과로만 기록한다. host/guest durability, Agent 사용 가능성, M7
  promotion의 근거가 아니다.
- 실제 sink가 없거나 거부하는 상태의 target mode는 mutated output을 노출하지 않는다. M4 build도 이 규칙을
  지킨다. sink 없이 노출하는 test-only 경로를 production build에 두지 않는다.

M4는 activation 창 eligibility도 구현한다. 새 CALL은 activation ACK와 deactivation ACK 사이에서만,
REPLY는 CALL의 `activation_generation`으로 판단하며, 창 밖 record는 `outside_activation_window`로
센다(`01-architecture.md` §16). resolver 결과는 rule별로 집계해 M5의 `GENERATION_COMPLETE`에 넘긴다.

M4는 generation의 admitting/draining/closed 단계와 closure 판정도 구현한다(`01-architecture.md` §16,
issue #18 F1). deactivation은 CALL admission만 닫고, draining G의 REPLY는 G로 처리하며, closure 뒤 G
REPLY는 변조하지 않는다. closure reason과 `reply_unresolved_count`를 만든다.

구현 상태: M4는 M4a(rule set serialization/validation), M4b(Resolver), M4c(preflight와 concrete edit
adapter), M4d(activation 창과 generation 단계, sink는 test double)로 나눠 진행한다. M4a가 구현됐다.
`src/rule.*`는 `NFSPRUL1`(`04-semantic-mutation-runtime.md` §35)을 읽고 schema에 대해 all-or-nothing으로
검증하며, `src/schema.*`의 `nfsp_schema_resolve()`가 semantic path를 type graph에서 찾는다. 설치 경로와
`RULESET` 기록은 아직 없다(§9, S1a).

### 28. M5 — Semantic Delta journal / relay completion

Required:
- semantic RULESET durable registration (host sink `(D)`).
- EXPOSURE_INTENT host ACK before enqueue/exposure.
- every event carries the host-stamped `session_binding`; generation-scoped events also carry `program_generation_correlation`, session-scoped `RULESET`/`RUN_COMPLETE` do not.
- sink admission per `05` §6: event scope table, per-session `event_seq`/`batch_id` ranges, idempotent re-ACK of identical retransmissions, rejection and host record of conflicts, stale sessions and wrong lanes, Proxy/Runner restart rules.
- `GENERATION_OPEN` host ACK before activation ACK; `GENERATION_OPEN` rejected while the lane still has an admitting generation, and its `draining_generations[]` must equal the host's draining set.
- `GENERATION_DRAINING` host ACK before deactivation ACK; the host moves G from admitting to draining and then rejects and records G's CALL-context `EXPOSURE_INTENT`/`APPLY_REFUSAL` while still accepting G's REPLY-context events, with or without G+1. A missing or rejected ACK means no deactivation ACK and the barrier-failure path (`01` §16, `05` §21, PR #22 review).
- one outstanding event per session, sent in `event_seq` order; record relay waits only on the same connection·direction, so other connections keep relaying records that need no event (`05` §6, §21).
- first hard refusal per (generation, rule) as a write-ahead `APPLY_REFUSAL` before the refused record is relayed, including same-rule refusals on other connections while that first event is unACKed; no relay of the refused record without a host response (retransmit the same event on timeout); `evidence_path_degraded` marking on explicit sink rejection (`05` §21).
- GENERATION_COMPLETE as the generation's last event, with per-rule resolver summary, `outside_activation_window`, evidence-path failure counters and closure (`05` §21).
- sink rejects and records G events after G's summary; Runner seals G only after the summary or session/channel/VM end.
- queue record/token metadata.
- full-write complete/failure callback.
- FORWARD_COMPLETE/FORWARD_FAILED append.
- torn-tail/corruption handling.
- S1b host journal sink and guest-to-host channel.

이 단계 전에는 target M1 delivery evidence contract가 구현됐다고 볼 수 없다.

M5 gate는 M4/S1a component와 실제 S1b sink를 묶은 live target-mode 실행을 포함한다(§27). 이 gate에서 처음으로
target rule 설치, activation, mutated output 노출을 host durability와 함께 검증한다.

### 29. M6 — Semantic Replay / ReplayResult

M1-M5의 같은 runtime components를 replay mode에서도 사용한다.
새 replay-only byte mutation engine을 만들지 않는다.

Required:
- semantic Delta reader.
- recorded CompiledMutationRule[] registration.
- matching schema/runtime compatibility gate.
- separate replay execution journal (host sink).
- ordered `CrashContextWindow` program sequence execution (S1c).
- per-position batch-signature multiset comparator.
- refusal classification, per-position refusal evidence completeness and the verdict order (`05` §29).
- REPLAY_EQUIVALENT / DIVERGED / INCONCLUSIVE / INVALID result.

Legacy NFSPDLT1/2 replay는 compatibility path로 계속 regression test한다.

### 30. M7 — Guest/runtime validation / capability promotion

Host unit tests만으로 target semantic capability를 current HCAP으로 올리지 않는다. M4/S1a의 test double 결과도
promotion evidence가 아니다(§27).

M7은 subset 단위로 반복하는 promotion gate다(issue #8). semantic subset S는 S에 필요한 M1–M6
구성요소, host test, S의 guest/runtime 검증, target 계약이 요구하는 semantic replay/evidence 검증을
통과한 뒤에만 Agent 사용 가능으로 등록한다. 다른 subset T는 같은 gate를 따로 통과한다. mutation
적용과 journal만 있고 replay/evidence 계약을 만족하지 못하는 subset은 promotion하지 않는다.

전체 semantic runtime의 guest/runtime validation은 최소 semantic request/response mutation, dynamic
state value, v4.1+ backchannel correlation, preserve/raw behavior, semantic Delta crash survival,
dynamic-original semantic replay를 포함해야 한다. 모든 subset은 semantic Delta crash survival과
semantic replay를 통과하고, 나머지 항목은 subset이 다루는 기능에 해당할 때 통과한다.

Validation evidence를 HCAP `evidence_refs`에 추가하고 subset의 registry digest와 scope를 promotion한 뒤에만
Harness Capability Specification을 갱신한다(§21).

### 31. Compatibility / cutover strategy

```text
legacy path
    NFSPARM1/2
    NFSPDLT1/2
    existing unit/guest tests

semantic path
    new rule-set ABI
    ProtocolSchema / Decoder / Context / Resolver
    semantic Delta / Replay
```

두 path는 lower-level framing/relay/concrete rebuild substrate를 공유할 수 있다.
Semantic path가 guest/runtime validation되기 전까지 legacy path는 known-good baseline이다.

### 32. Proposed module boundaries

Exact filenames은 구현 단계에서 조정할 수 있지만 responsibility boundary는 다음이 적절하다.

```text
framing.*            existing transport record parser
proxy.*              connection/relay/forward lifecycle
walk.*               legacy Layer 0 walk

schema.*             ProtocolSchema load/lookup
rpc_decode.*         target RPC envelope decoder
nfs_decode.*         target semantic decoder
transaction.*        Transaction Context
semantic_rule.*      serialization/validation/resolver
mutation_apply.*     concrete batch adapter/rebuild boundary
semantic_delta.*     target journal reader/writer
semantic_replay.*    replay comparison/orchestration
```

이 이름들은 implementation guide이지 이미 존재하는 path가 아니다.

### 33. Highest-risk implementation seams

1. marker-inclusive legacy coordinate와 marker-free target WireRef 혼합.
2. wrong semantic field를 valid WireRef로 만드는 schema false positive.
3. opposite CALL direction/XID transaction mis-correlation.
4. registration order가 semantic result에 새는 문제.
5. count/length/padding을 stale literal로 고치는 structure drift.
6. durable EXPOSURE_INTENT 없이 mutated bytes를 enqueue하는 문제.
7. missing completion을 definite delivery로 overclaim하는 문제.
8. semantic refactor가 existing NFSPARM1/2 regression을 깨뜨리는 문제.
9. activation ACK 유실을 비활성으로 오인해 target mode program을 실행하는 문제.
10. host ACK 없이 guest 파일 기록만으로 durability를 주장하는 문제.

이 seams는 implementation review/test plan의 우선 관측점이다.

### 34. syzkaller / Runner integration (S1)

target semantic 경로는 `tools/nfs-proxy`만으로 완성되지 않는다. issue #2와 #3에서 합의한 다음 작업은
syzkaller patch series와 Runner에 속한다.

#### S1a — rule set 설치와 executor activation

- Runner가 Proxy session마다 불변 `CompiledMutationRule[]`을 설치하는 경로. 현재 control socket은
  executor sandbox에만 bind되므로 별도 경로가 필요하다.
- executor가 remote-KCOV BEGIN 뒤 activation(G)를 보내고 ACK를 받은 다음 program syscall을 실행하며,
  FINISH/ABORT 전에 deactivation(G)를 보내고 ACK를 받는다(syzkaller 0001/0002의 generation 경계 위).
  deactivation ACK는 Proxy가 CALL admission을 닫고 `GENERATION_DRAINING(G)`의 host ACK를 받았다는 뜻이다.
  executor는 G의 drain/closure를 기다리지 않는다(`01-architecture.md` §16). S1a에서 이 host ACK는 test
  double이다(위 M4/S1a acceptance 범위).
- activation ACK가 없으면 program을 실행하지 않고 generation을 ABORT한다. deactivation ACK가 없거나 비활성
  상태를 확인할 수 없으면 lane을 재사용하지 않고 격리/재시작한다. 기존 0008 fail-closed runner 경로를
  쓸 수 있다.
- fork-server parent의 orphan cleanup도 ABORT 전에 deactivation을 시도한다.
- activation endpoint는 executor 전용이며 fuzz program syscall로 도달할 수 없다.
- exec result에 generation id와 barrier 결과를 보고한다.
- target semantic rule struct를 syzlang에 추가하지 않는다. legacy `syz_arm_nfs_proxy*`는 legacy campaign용으로
  그대로 두고, target campaign에서는 manager call filtering으로도 막는다.

#### S1b — Runner host journal sink

- guest Proxy의 journal event를 받는 Runner 소유 sink와 guest-to-host channel.
- framed event append 전체를 마친 뒤 host-generated ACK를 보낸다. guest write-back cache로는 ACK를 만족할
  수 없다.
- channel identity(`vm_instance_id` 등)를 host가 기록하고, guest event는 untrusted data로 검증한다.
- `GENERATION_OPEN`/`GENERATION_DRAINING`/`GENERATION_COMPLETE`로 generation별 admitting/draining/closed
  binding을 유지하고, draining G의 CALL-context event는 거부하며 REPLY event는 그 binding으로 검증한다(`05-mutation-delta-replay.md` §21).

#### S1c — CrashContextWindow와 replay sequence

- syz-manager `pkg/rpcserver`의 `LastExecuting` ring(pinned commit 기준 proc별 6개)을 확장해
  executor가 보고한 generation id, host-known original lane/proc, MutationDelta 참조를 함께 보존한다.
  `Hanged()`가 `ExecRecord.Proc`를 synthetic 값으로 바꾸므로 lane을 그 필드에서 유도하지 않는다.
- window bound는 job policy로 명시하고 evidence에 기록한다. window는 VM instance를 넘지 않는다.
- replay는 window의 program을 순서대로 실행한다.

S1 변경은 syzkaller patch family로 들어가며 AGENTS.md의 pseudo-syscall/executor 규칙(executor,
`pkg/vminfo`, syzlang, test를 한 patch family로 조정하고 `series`를 갱신)을 따른다.

## 설계 근거

| 결정 | 근거 |
|---|---|
| current Proxy를 폐기하지 않고 Layer 0 substrate로 재사용 | framing/edit/delta safety invariants와 regression tests가 이미 존재 |
| marker-free semantic RpcRecord adapter 추가 | target WireRef coordinate와 multi-fragment RPC를 transport marker에서 분리 |
| legacy `walk.*`와 target semantic decoder 분리 | current walk의 partial/raw contract를 깨뜨리지 않고 full schema decode 추가 |
| stable ConnectionRef를 relay lifecycle에 추가 | Transaction Context가 fd/slot reuse와 독립적인 key를 요구 |
| semantic control ABI를 NFSPARM2와 분리 | current byte fields가 target semantic model을 제한하지 않게 함 |
| concrete rebuild core만 edit engine에서 추출 | verify-before-patch/one-pass rebuild는 살리고 byte-oriented matching은 분리 |
| semantic path를 legacy v1/v2 chain과 분리 | target same-snapshot/order-independent invariant 보존 |
| new append-only semantic journal | current applied_count만으로 crash-cut/delivery state를 표현할 수 없음 |
| relay에 per-record completion token 추가 | FORWARD_COMPLETE를 aggregate delivered counter로 추론할 수 없음 |
| legacy ABI/replay 유지 | existing validated campaigns와 regression baseline을 보존 |
| implementation을 dependency milestone로 진행 | 각 semantic layer의 input contract가 이전 milestone output에 의존 |

## 검토한 대안

| 선택지 | 얻는 것 | 비용·한계 | 채택 여부와 이유 |
|---|---|---|---|
| tools/nfs-proxy 전면 rewrite | clean codebase | framing/edit/durability regression risk 큼 | 비채택 |
| current NFSPARM2를 계속 확장 | 적은 new ABI | semantic path/type/context를 byte packet에 억지로 넣게 됨 | 비채택 |
| `nfsp_walk`에 full schema decoder를 직접 합침 | file 수 감소 | legacy marker-inclusive/raw contract와 target decoder가 강결합 | 비채택 |
| current edit engine을 그대로 Semantic Resolver로 사용 | 코드 재사용 극대화 | selector/anchor/order semantics가 target과 충돌 | 비채택 |
| lower-level concrete rebuild만 재사용 | tested safety property 보존 | adapter/refactor 필요 | 채택 |
| current applied_count를 semantic replay gate로 유지 | 구현 단순 | record-level batch grouping/delivery state를 잃음 | 비채택 |
| legacy path를 즉시 제거 | implementation 단순화 | current campaigns/tests의 known-good fallback 상실 | 비채택 |
| legacy + semantic path 병행 후 validation cutover | migration 안전 | 일정 기간 두 path 유지 비용 | 채택 |

## 영향

### 코드 구조

새 semantic components가 추가되지만 framing/relay/edit core를 가능한 한 유지한다.
가장 큰 API 변화는:

```text
stable ConnectionRef
marker-free RpcRecord payload
semantic rule-set registration
ConcreteEditBatch apply boundary
forward-completion callback/token
semantic journal/replay interfaces
```

이다.

### Legacy compatibility

NFSPARM1/2, NFSPDLT1/2와 existing tests는 semantic implementation 동안 regression gate다.

Target path가 검증되기 전에 current ABI를 제거하거나 의미를 바꾸지 않는다.

### Runner / harness

Runner는 추가로 ProtocolSchema artifact, semantic ruleset, semantic Delta와 replay journal을 봉인해
job artifact lineage에 포함해야 한다. ReplayResult는 validation layer가 만든다. 또한 Proxy session마다 rule set을 설치하고, host journal
sink와 `CrashContextWindow` execution history를 소유한다(§34, issue #2/#3).

HCAP는 implementation gap이 닫히고 guest/runtime evidence가 생긴 뒤 갱신한다.

### Performance

Full semantic decode, transaction table, semantic rule resolution, synchronous journal event는
current Layer 0보다 CPU/I/O cost가 크다.

Correctness contract를 약화해 최적화하지 않는다. 먼저 bounded implementation을 만들고
real manager workload에서 비용을 측정한다.

## 신뢰성 요구

Gap closure가 target invariant를 약화시키면 구현 완료로 인정하지 않는다.

| seam | 반드시 유지할 invariant |
|---|---|
| framing adapter | semantic payload에서 fragment header가 field bytes로 보이지 않음 |
| RPC/NFS decode | unknown layout을 semantic field로 추측하지 않음 |
| ConnectionRef | reconnect/fd-slot reuse가 old transaction namespace를 재사용하지 않음 |
| Transaction Context | same conn opposite CALL direction XID collision 분리 |
| Resolver | all rules same pre-mutation snapshot |
| Edit Applier | replay-current original verify-before-apply |
| conflict handling | registration order로 silent winner 선택 금지 |
| Delta | unrecorded mutated output exposure 금지 |
| relay completion | missing completion을 definite success로 해석 금지 |
| Replay | production concrete bytes를 dynamic replay identity로 강제하지 않음 |
| compatibility | existing Layer 0 test behavior를 의도 없이 변경하지 않음 |

## 검증 오라클

### 1. M0 legacy baseline

Existing proxy unit tests가 semantic implementation 전후 동일하게 통과해야 한다.

### 2. canonical payload / multi-fragment

동일 RPC message를 single-fragment와 multi-fragment record로 전달한다.

Expected:
- identical marker-free rpc_payload;
- identical RPC/NFS semantic decode;
- WireRef coordinates identical;
- forwarding은 valid record framing.

### 3. ConnectionRef reuse

한 connection을 닫고 같은 `conns[]` slot/fd가 재사용되는 상황을 만든다.

Expected:
- new connection_id;
- old TransactionEntry lookup 불가.

### 4. Semantic decoder coverage

02 contract의 golden/truncation/malformed vectors를 구현 coverage subset별로 통과한다.

### 5. Transaction Context

03 contract의 out-of-order reply, duplicate XID, opposite CALL direction, timeout/close tests를
통과한다.

### 6. Same-snapshot rule invariance

Semantic rule registration order를 permutation한다.

Expected:
- same matched set;
- same conflict result;
- same final output.

### 7. Concrete edit adapter

Target Resolver가 생성한 concrete batch와 legacy edit engine의 equivalent lower-level edit를
비교한다.

Expected:
- same verify/refusal result;
- same final bytes where semantics are equivalent.

### 8. Structure derivation

Variable-length field와 op insertion에서 preserve/raw contract를 검증한다.

### 9. Delta write-ahead

EXPOSURE_INTENT durable write를 실패시킨다.

Expected:
- mutated record enqueue 없음.

### 10. Forward completion

Partial nonblocking writes를 강제한다.

Expected:
- token completion은 full record boundary에서 한 번만 발생;
- fatal partial write는 failure;
- unrelated record token과 섞이지 않음.

### 11. Semantic replay

Production/replay dynamic field bytes를 다르게 만들고 05 contract의
REPLAY_EQUIVALENT/DIVERGED/INCONCLUSIVE/INVALID oracle을 통과한다. 05 검증 오라클 §20의
crash-cut hard refusal case를 포함한다.

### 12. Guest/runtime promotion

Host tests 뒤 실제 lane/guest에서 semantic request/response mutation과 replay를 검증한다.

이 단계 전에는 target semantic HCAP support로 promotion하지 않는다.

## 실패 양상과 진단

| 증상 | 가능 gap | 우선 확인 |
|---|---|---|
| semantic offsets가 multi-fragment에서 달라짐 | marker-inclusive coordinate leakage | framing adapter / RpcRecord payload |
| NFSv3 reply target을 못 찾음 | Transaction Context/procedure recovery missing | CALL insert / REPLY lookup |
| v4.1 callback reply가 wrong request와 연결 | call_direction key bug | ConnectionRef + TransactionKey |
| rule order를 바꾸면 output 변화 | current sequential/edit-order semantics leakage | Resolver/preflight/apply boundary |
| preserve mutation 후 malformed XDR | derived metadata coverage gap | schema encoder/metadata edits |
| delta는 있는데 peer write 상태 불명확 | forward completion API missing | queue token lifecycle |
| replay가 dynamic stateid orig mismatch로 실패 | legacy replay path selected | semantic Delta loader/runtime |
| same applied count인데 replay diverges | batch grouping lost | semantic batch signature comparator |
| legacy test regression | shared substrate refactor bug | framing/edit/control compatibility tests |

## 한계와 미결 사항

- **결정됨:** current framing/relay/concrete edit safety code는 가능한 한 재사용한다.
- **결정됨:** target semantic decoder/Transaction Context/Resolver는 current code에 없다.
- **결정됨:** marker-inclusive current record coordinates와 marker-free target WireRef 사이 adapter가 필요하다.
- **결정됨:** semantic rule ABI는 NFSPARM1/2와 별도여야 한다.
- **결정됨:** semantic path는 current v1->v2 sequential semantics를 사용하지 않는다.
- **결정됨:** semantic Delta/Replay는 current NFSPDLT1/2 top-level format을 그대로 확장하지 않는다.
- **결정됨:** relay full-write completion tracking은 새 기능이 필요하다.
- **결정됨:** legacy NFSPARM/NFSPDLT path는 migration 중 유지한다.
- **결정됨:** implementation order는 M0-M7 dependency sequence를 따르고, S1 track이 M4/M5/M6 완료의
  선행 조건이다(§22, §34).
- **결정됨:** rule 내용은 Runner가 Proxy session마다 설치하고 활성 구간은 executor가 generation마다
  barrier로 정한다(issue #2).
- **결정됨:** target durability는 Runner host journal sink의 ACK다. guest `O_SYNC` writer는 legacy다(issue #3).
- **결정됨:** M1 판정 계약은 M4/M5의 선행 조건이며 `../02-llm-agent/01-two-stage-agent-architecture.md`
  §7에 고정됐다(issue #4).
- **미결:** exact ProtocolSchema source/artifact paths.
- **미결:** concrete new source filenames/API naming.
- **미결:** semantic rule serialization binary/text format.
- **미결:** semantic journal binary format/magic.
- **미결:** legacy/semantic CLI mode exact flags/config format.
- **미결:** initial protocol operation coverage subset.
- **미결:** numeric limits for context/rules/resolved edits/journal snapshots.
- **미결:** v4.0 separate callback routing을 initial implementation에 포함할지 별도 milestone로 둘지.
- **미결:** guest-to-host journal transport, rule set 설치 경로, activation 메시지 형식.
- **미검증:** current source refactor 후 syz-manager workload performance.

## 참조

- `docs/design/03-nfs-proxy/01-architecture.md`
- `docs/design/03-nfs-proxy/02-semantic-decoder.md`
- `docs/design/03-nfs-proxy/03-transaction-context.md`
- `docs/design/03-nfs-proxy/04-semantic-mutation-runtime.md`
- `docs/design/03-nfs-proxy/05-mutation-delta-replay.md`
- `docs/design/02-llm-agent/04-harness-capability-spec.md`
- `docs/design/02-llm-agent/08-mutation-rule-set.md`
- `tools/nfs-proxy/src/framing.h`
- `tools/nfs-proxy/src/framing.c`
- `tools/nfs-proxy/src/proxy.h`
- `tools/nfs-proxy/src/proxy.c`
- `tools/nfs-proxy/src/walk.h`
- `tools/nfs-proxy/src/walk.c`
- `tools/nfs-proxy/src/control.h`
- `tools/nfs-proxy/src/control.c`
- `tools/nfs-proxy/src/edit.h`
- `tools/nfs-proxy/src/edit.c`
- `tools/nfs-proxy/src/delta.h`
- `tools/nfs-proxy/src/delta.c`
- `tools/nfs-proxy/src/main.c`
- `tools/nfs-proxy/test/`

## Agent 사용 지침

### 지원 범위

이 문서는 target semantic capability가 이미 구현됐다는 선언이 아니다.

Agent/Controller는 Harness Capability Specification의 current validated subset만 사용할 수
있다.

Gap matrix의 `missing`, `replace`, `extend` 항목이 구현/검증되기 전에는 target design의
semantic feature를 current harness support라고 가정하지 않는다.

### 비지원 범위

다음 reasoning은 금지한다.

```text
design contract exists
    -> implementation exists

current NFSPARM2 supports variable edit
    -> arbitrary semantic target supported

current NFSPDLT2 replay works
    -> semantic dynamic replay supported
```

필요한 candidate가 아직 닫히지 않은 gap을 요구하면 기존 정책대로
`HarnessGapIssue(gap_class=mutation_engine)`에 연결한다.

### 구현 진행 기준

Proxy implementation은 M0부터 순서대로 진행하되 하나의 milestone에서 다음 milestone의
target contract를 우회하는 temporary semantic shortcut을 만들지 않는다.

각 milestone은:

```text
host tests
legacy regression tests
new target-specific oracle
git/whitespace checks
```

를 통과한 뒤 다음으로 넘어간다.

Guest/runtime capability promotion은 M7에서만 한다.

### 다음 단계

이 gap analysis 이후에는 새 architecture contract가 아니라 **Proxy implementation**이
다음 단계다.

```text
M0 legacy baseline
    -> M1 canonical record/RPC/connection
    -> M2 schema/decoder
    -> M3 transaction context
    -> M4 semantic runtime/apply adapter
    -> M5 semantic delta/delivery lifecycle
    -> M6 replay/result
    -> M7 guest validation/HCAP promotion
```
