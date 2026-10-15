# M5 prerequisite: canonical journal events and pure admission

Status: independently testable **scalar-literal-v1 prerequisite**, with partial
M5 payload coverage. This is not a durable sink, semantic approval, or completion
of M5/S1b. S1a remains held. The implementation is limited to
`agent_pipeline/journal_events.py` and `agent_pipeline/journal_admission.py`.

The parent contracts are [05 §§2–24 and §45](05-mutation-delta-replay.md),
[04 §35 NFSPRUL1](04-semantic-mutation-runtime.md), and the existing
`journal_framing.py` codec. The M1 models are deliberately lossy sealed-evidence
projections; none is used as a full journal payload here.

## Dependency and trust boundary

Three separate checks must remain distinguishable:

1. `decode_event` establishes bounded, canonical encoding and internal evidence
   consistency. It does not establish host identity or approve compiled rules.
2. `prepare_event` additionally compares the event against independently supplied
   host session, snapshot and generation selections, and checks journal lifecycle.
   `HostAuthority` is the caller's input, not an authenticated credential or a
   semantic approval token. Never construct it from the request under evaluation.
3. Schema-aware approval and evidence verification remain separate prerequisites.
   The C runtime's `nfsp_ruleset_load` performs schema/capability validation.
   There is no Python bridge here proving that load occurred, that the selected
   bytes were installed, or that a reported semantic path/occurrence resolves to
   the reported WireRef. A structurally consistent event can still make false
   semantic claims. No generic acceptance callback or `verified=True` flag fills
   that gap.

The exact blocked semantic checks include ProtocolSchema availability and identity,
schema type/path resolution, selector compatibility, mapping field/operation
indices to live bytes, preserve-policy structural verification, transaction-derived
REPLY dispatch provenance, and completeness of `all_matches` occurrences. The code
does not decode RPC/NFS or independently observe a socket write. Rule/record fixtures
do not grant approval to live traffic. Full semantic evidence admission cannot be
claimed until those independent sources and their bridge exist.

No durable writer, append result, ACK issuance, channel authentication, transport,
live relay, activation, M1 projection, semantic replay execution, or promotion is
implemented. `reconstruct` means state reconstruction from journal events, not
semantic replay. Host rejection persistence/encoding is also deferred; errors
must not be silently omitted by a future sink.

## Supported NFSPRUL1 profile

`parse_ruleset(bytes)` reads the existing big-endian XDR contract, including magic,
runtime version, length bounds, zero padding, visible ASCII names, exact EOF,
enum/bool ranges and strictly ascending rule IDs. The SHA-256 of **all exact
NFSPRUL1 bytes** is `rule_set_id`. It is not a JSON hash, M1 projection hash, or
hash of a normalized replacement. There is no guest-supplied alternate rule index.

The entire snapshot must fit this profile:

| Component | Accepted |
|---|---|
| Runtime / rules | version 1; 1–256 rules, immutable for a session |
| Selector | C2S/S2C independent of CALL/REPLY; exact route, RPC/protocol fields, optional operation |
| Target | `FIELD`, `VALUE` only |
| Predicates | empty |
| Mutation | `REPLACE`, present `LITERAL` transform |
| Literal / observed values | signed int32/int64, unsigned uint32/uint64, boolean, unsigned enum word |
| Policy | preserve or raw; journal checks recorded policy equality only |
| Dependencies | forwarded `rpc_procedure` exactly when REPLY has selected procedure; other dependency flags and field lists empty |
| Application mode | `ALL_MATCHES`; completeness cannot be independently verified here |

Copy and builtin transforms, predicates, opaque/string values (even fixed-length
opaque), variable-size/derived edits, metadata/encoded parts, non-leaf/operation
targets, insert/delete/op-append/op-prepend and other runtime versions are refused
as whole snapshots. Empty rulesets are outside this profile. No rules or evidence
fields are dropped to make an unsupported snapshot fit. `UnsupportedRuleProfile`
is a `JournalEventError`; early refusal of an unsupported discriminator does not
claim the unparsed remainder is a valid NFSPRUL1 document.

This is a journal-format reader for the restricted profile, not a new semantic
compiler or substitute for `nfsp_ruleset_load`. Extending evidence to other
capabilities requires a complete bounded contract and matching independent
validation sources first.

## Canonical envelope and limits

Each event is the UTF-8 JSON payload of a `FrameKind.JOURNAL_EVENT` frame. Encoding
is repository `canonical_json`: sorted object keys, no whitespace, UTF-8 without
ASCII escaping, no nonfinite numbers. Decode requires byte-for-byte re-encoding
equality. Duplicate keys, additional fields, missing fields, invalid UTF-8,
alternate escaping, floating/string/bool integer substitutions, and unknown
versions/types are refused. Nested models are strict and frozen; collections are
immutable tuples internally and JSON arrays on the wire. There is no `Any` payload.

```text
schema_version = "nfs-proxy-journal-event.v1"
session_binding = HostSessionBinding
event_seq = uint64
event_type = one of the nine event names
payload = the corresponding event-specific object
program_generation_correlation = GenerationCorrelation  # generation events only
```

`session_binding` has exactly `vm_instance_id`, `channel_id`, `proxy_session_id`
and `rule_set_id`, using the existing framing type. The first three are 1–256
ASCII characters `[A-Za-z0-9_.:/-]`; the last is 64 lowercase hexadecimal digits.
Host identity is compared, never substituted into an otherwise mismatched event.

`GenerationCorrelation` has exactly `vm_instance_id`, `lane_id`, `proc_id`,
`kcov_generation`, `rule_set_id`, and `program_digest`. VM and ruleset must agree
with the enclosing session; lane/proc are uint64, generation is 1..2^64−1, and
program digest is 64 lowercase hex digits. Host authority separately selects the
entire correlation, including lane/proc/digest. Generation IDs cannot repeat
within a session, and a host-selected lane has one proc identity. Session events
forbid generation correlation. Generation correlation occurs once at envelope
level, so nested record evidence cannot select another generation.

| Resource | Ceiling / encoding |
|---|---|
| One canonical event | 4 MiB, matching framing |
| Exact NFSPRUL1 snapshot | 1 MiB raw; inline lowercase even-length hex |
| Rule count | 256 |
| Rule, intent, candidate, batch IDs | 1–128 visible ASCII characters `!` through `~` |
| Schema ID / semantic path | 1–256 / 1–512 visible ASCII characters |
| Protocol family / operation name | 1–32 / 1–64 visible ASCII characters |
| Original marker-free RPC payload | 4 bytes–256 KiB, lowercase even-length hex |
| Final framed record | 8 bytes–256 KiB + 4 bytes, lowercase even-length hex |
| Applications / signature members | 1–64 per exposure |
| Concrete edits | exactly one scalar edit per application |
| Selected span / edit width | 4 or 8 bytes; offset <256 KiB and divisible by 4 |
| Host-authorized generations / draining set | 64 per session / per OPEN |
| Batch states | 4,096 per session, including closed batches |
| Accepted requests retained per session | 16,384 and 64 MiB including 80-byte frame headers |
| Resolver counts / sequence / counts / drain bound | uint64 |
| Route and RPC integers / occurrence indices | uint32; connection ID is nonzero uint64 |
| Forward failure reason | 1–256 printable ASCII characters, including space |

These are fixed profile limits, not negotiable guest settings. The session limits
are cumulative even if an eventual writer rotates segments. Exhaustion refuses
the next event; it never evicts retransmission history or silently closes a batch.
The pure module does not impose a limit on the number of sessions a caller keeps;
host-wide allocation remains a future sink responsibility.

## Event-specific payloads

All fields shown below are required, including empty arrays, empty objects, and
explicit `null` values for nullable fields. No event has extension dictionaries.

| Event | Exact payload fields |
|---|---|
| RULESET | `profile="scalar-literal-v1"`, `semantic_runtime_version=1`, `schema_id`, `candidate_id`, `rule_set_id`, `snapshot_hex` |
| GENERATION_OPEN | `draining_generations`: sorted unique nonzero generation IDs |
| GENERATION_DRAINING | empty object `{}` |
| EXPOSURE_INTENT | `batch_id`, `record_context`, `semantic_signature`, `applications`, `original_record_hex`, `output` |
| APPLY_REFUSAL | `rule_id`, `refusal`, `record_context` |
| FORWARD_COMPLETE | `batch_id`, `forwarded_length` |
| FORWARD_FAILED | `batch_id`, `reason`, `bytes_written` (nonnegative or null) |
| GENERATION_COMPLETE | `records_seen`, `exposure_batch_count`, `outside_activation_window`, `evidence_path_failures`, `resolver_summary`, `closure` |
| RUN_COMPLETE | `rule_summaries`, `batch_count`, `forward_complete_count`, `forward_failed_count` |

RULESET metadata and its session digest must equal the parsed inline snapshot.
Admission also requires equality with the exact host-selected bytes. It confers
no semantic approval or installation/registration success.

`RecordContext` contains `direction` (`C2S`/`S2C`), `backend`, `client`,
`connection_id`, `rpc_message_type` (`call`/`reply`), `rpc_program`, `rpc_version`,
`rpc_procedure`, `protocol_family`, `nfs_version`, and `minor_version`. The last
six fields are nullable to retain refusals that precede decode/transaction lookup.
An exposure must supply every selected dispatch value; known refusal dispatch
values must agree with the rule. Both event types require exact selected route
and message type. Direction never determines message type.

Each `Application` contains:

```text
rule_id
semantic_target
    kind = "field"
    semantic_path
    part = "value"
    field_index
    operation_index        # uint32 or null
    operation              # name or null; present together with operation_index
    wire_span {offset, length}
mutation_kind = "replace"
structure_policy = "preserve" | "raw"
predicate_values = []
transform_source_values = []
original_value_snapshot {kind, value}
mutated_value_snapshot {kind, value}
concrete_edits[1]
    offset
    remove_length
    original_hex
    replacement_hex
```

Scalar `kind` is `int`, `uint`, `hyper`, `uhyper`, `bool`, or `enum`, with exact
signedness/width and JSON boolean for bool. Original and mutated kinds must match;
concrete bytes must equal their big-endian XDR values. Wire span and edit range
must agree. Reported target path, selected operation, policy and mutated literal
are compared against the exact snapshot. These comparisons do not prove a schema
node's type, location or occurrence.

Applications are strictly sorted and unique by `(rule_id, field_index)`.
`semantic_signature` is the sorted multiset of objects with `rule_id`,
`semantic_path`, `part="value"`, `mutation_kind="replace"`, sorted by that tuple.
It must equal the applications' multiset exactly; repeated occurrences preserve
multiplicity. It is not a replay selector or hash of lossy M1 membership.

`original_record_hex` preserves the complete **marker-free** RPC payload.
All edit offsets start at its first byte, as in `rpc_record.h`. Edits must be
in bounds, nonoverlapping, and match original bytes in that one immutable input.
The codec rebuilds the scalar replacements and compares all output bytes with
`output.framed_record_hex`. `output.final_record_length` includes the **four-byte
last-fragment marker**, matching `mutation_apply.h`'s single-fragment output.
No original/output artifact references or optional omitted snapshots are supported.
Record byte consistency does not assert RPC validity or NFS semantics.

The first hard refusal per `(generation, rule_id)` has an APPLY_REFUSAL event.
The initial classification from 05 §29 is fixed here:
`schema_mismatch`, `decode_unavailable`, `transaction_context_missing`,
`transaction_context_unusable`, `target_ambiguous`, `predicate_reference_ambiguous`,
`transform_failed`, `conflict`, `structure_constraint_failed`, or
`apply_precondition_failed`. Normal misses and `transform_unsupported` are not
APPLY_REFUSAL values; all taxonomy values remain available in summaries.

Each summary list is sorted uniquely by rule ID and covers every and only
snapshot rule. Each element is `{rule_id, counts}`, where `counts` explicitly
contains every following uint64 field, even if zero:

```text
scope_miss, rpc_selector_miss, schema_mismatch, decode_unavailable,
transaction_context_missing, transaction_context_unusable, target_not_found,
target_ambiguous, predicate_false, predicate_reference_ambiguous,
transform_unsupported, transform_failed, resolved, conflict,
structure_constraint_failed, apply_precondition_failed
```

`closure` contains `reason` (`drained`, `reply_unresolved`, `aborted`),
`drain_bound` (milliseconds), and `reply_unresolved_count`. Drained requires zero
unresolved replies; reply_unresolved requires a positive count. Aborted preserves
the reported count and can close an admitting generation without a prior draining
event. Counts describe claimed observations, not independent semantic measurements.

## Pure transitions and reconstruction

`initial_state(HostAuthority(...))` creates immutable empty state. Authority takes
the host-selected `HostSessionBinding`, exact `snapshot_bytes`, and a bounded tuple
of allowed `GenerationCorrelation` values. Membership/facts come from the snapshot;
there is no externally supplied lossy rule projection. Authorizations are a fixed
set for this bounded session; this module implements no live activation or grant
extension API.

`prepare_event(state, canonical_request_bytes)` returns `PreparedEvent(event,
request_sha256, duplicate, next_state)` or raises `AdmissionError` with a reason
code. Neither success nor failure changes the input state, nested authority, or
previously returned states. `next_state` is a **candidate value**, not a commit.
The future serialized writer must retain the previous state until append succeeds;
concurrent preparations cannot independently commit against the same old state.
There is no `commit()` method or implicit success/durable ACK.

The transition checks are:

1. Exact host session/channel/VM/ruleset equality; sequence starts at zero and is
   contiguous per session. RULESET must be first and can occur only once.
2. A byte-identical request at an already accepted sequence returns `duplicate=True`
   and the same state object. It consumes no bounds and creates no application.
   Different bytes at that sequence are `event_conflict`; a gap is
   `sequence_violation`. Exact retries remain identifiable after terminal events,
   including RUN_COMPLETE. Any new event after RUN_COMPLETE is refused.
3. OPEN must equal a host-authorized correlation that has never opened before.
   No other generation on its lane may be admitting. Its sorted draining set must
   equal all and only that lane's draining, not-yet-complete generations.
4. DRAINING applies once to an admitting generation. While draining,
   EXPOSURE_INTENT/APPLY_REFUSAL must be REPLY context; CALL is refused even if a
   successor has not opened. A draining predecessor and admitting successor may
   coexist. Different lanes operate independently.
5. Exposure batch IDs are unique for the session. Forward outcomes reference an
   admitted batch in the same exact generation and occur once. Complete length
   equals the framed output length; failed bytes are unknown (`null`) or strictly
   less than that length, including zero. Already closed batches stay indexed.
6. GENERATION_COMPLETE requires all its batches forward-closed and exact exposure
   count. Non-aborted closure requires draining. Each rule's `resolved` count
   cannot omit witnessed applications, but may exceed them (resolver results are
   not all guaranteed exposures). Positive hard refusal counts require a recorded
   first refusal, and its specific kind must have a positive count. Later refusal
   kinds may appear only in summary counts. Completion closes only this generation.
7. RUN_COMPLETE requires all opened generations closed, exact batch/outcome totals,
   and exact per-rule sums of generation summaries. Host-authorized generations
   that never opened need no invented summary. This event is final.

Rejected events produce no new state or success response. A future writer must
preserve rejection/conflict evidence (and mark affected evidence inconsistent as
05 §6 requires), or fail the channel if it cannot. The pure module is not an audit
store; catching its error and continuing without recording it would lose evidence.

`reconstruct(authority, frames)` starts empty and applies **the same**
`prepare_event` checks to complete event frames. It rejects gaps, identity changes,
invalid lifecycle, and duplicates stored as a second frame. Network retransmission
is legal; a second stored append is not. `HOST_REJECTION` and `ACK` frames are
explicitly unsupported here and cannot be silently skipped. Reconstruction of a
mixed rejection/event journal needs the future rejection contract.

Use the framing reader first to check frame integrity and separate an incomplete
last frame. Reconstruction accepts a valid unfinished prefix: an exposure without
a forward outcome remains open with unknown delivery, and a generation without a
summary remains admitting/draining. It never fabricates closure after a crash,
rolls a draining generation back to admitting, truncates a file, resumes traffic,
or interprets a framing-valid prefix as proof of durability/approval.

## Independent verification

The two new test files cover the nine schemas, strict JSON, scalar/XDR boundaries,
all snapshot cuts, unsupported shapes, exact hash binding, original-byte/rebuild
consistency, signature multiplicity, identity and sequence conflicts, immutable
preparation, session capacity, multi-lane/multi-generation draining, terminal
summaries, first refusal witnesses, aborted closure and unfinished crash prefixes.

`test_journal_events.py` embeds two independent NFSPRUL1 byte vectors generated by
the existing C test builder and accepted by production `nfsp_ruleset_load` during
the parent's cross-language check: CALL SEQUENCE uint/preserve and REPLY OPEN
status enum/raw. Python tests consume those bytes without invoking the C loader
or claiming it ran in this module. Other builder fixtures test format boundaries
and are not claims of schema validation.

Focused command (from the worktree, using the supplied interpreter):

```sh
PYTHONPATH="$PWD" /tmp/knfsd-runner-next.jo09sprm/integration/.venv/bin/python -W error -m pytest -q \
  tests/agent_pipeline/test_journal_events.py \
  tests/agent_pipeline/test_journal_admission.py \
  tests/agent_pipeline/test_journal_framing.py
```

No full suite or live workload is required for this prerequisite. The parent owns
shared documentation/exports, baseline integration and independent review.
