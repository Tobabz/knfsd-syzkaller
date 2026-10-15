"""Bounded canonical journal evidence, without semantic approval or durability.

The scalar-literal-v1 profile is deliberately smaller than NFSPRUL1. Its reader
checks the binary contract and extracts exact rule facts; it does NOT resolve
schema paths, approve compiled rules, or prove a guest observed these bytes.
See docs/design/03-nfs-proxy/07-journal-event-contract.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from .data import canonical_json, parse_json
from .journal_framing import HostSessionBinding, MAX_PAYLOAD_BYTES

MAX_RULESET_BYTES = 1024 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_RULES = 256
MAX_APPLICATIONS = 64
MAX_GENERATIONS = 64
PROFILE = "scalar-literal-v1"

U32 = Annotated[int, Field(ge=0, le=2**32 - 1)]
U64 = Annotated[int, Field(ge=0, le=2**64 - 1)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[!-~]+$")]
Path = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[!-~]+$")]
SchemaId = Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[!-~]+$")]
Family = Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[!-~]+$")]
Operation = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[!-~]+$")]
Direction = Literal["C2S", "S2C"]
MessageType = Literal["call", "reply"]


class JournalEventError(ValueError):
    """Malformed, noncanonical, inconsistent or out-of-bounds event evidence."""


class UnsupportedRuleProfile(JournalEventError):
    """A rule needs evidence/validation beyond the supported journal profile."""


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              validate_default=True, revalidate_instances="always",
                              allow_inf_nan=False)


class IntValue(_Record):
    kind: Literal["int"]
    value: Annotated[int, Field(ge=-(2**31), lt=2**31)]


class UIntValue(_Record):
    kind: Literal["uint"]
    value: U32


class HyperValue(_Record):
    kind: Literal["hyper"]
    value: Annotated[int, Field(ge=-(2**63), lt=2**63)]


class UHyperValue(_Record):
    kind: Literal["uhyper"]
    value: U64


class BoolValue(_Record):
    kind: Literal["bool"]
    value: bool


class EnumValue(_Record):
    kind: Literal["enum"]
    value: U32


ScalarValue = Annotated[
    IntValue | UIntValue | HyperValue | UHyperValue | BoolValue | EnumValue,
    Field(discriminator="kind"),
]


def scalar_bytes(value: ScalarValue) -> bytes:
    """XDR scalar value bytes (no record marker, length word or padding)."""
    width = 8 if value.kind in ("hyper", "uhyper") else 4
    return int(value.value).to_bytes(width, "big", signed=value.kind in ("int", "hyper"))


@dataclass(frozen=True)
class ScalarRule:
    rule_id: str
    intent_id: str
    direction: Direction
    backend: int
    client: int
    message_type: MessageType
    program: int
    version: int
    procedure: int | None
    family: str
    nfs_version: int | None
    minor_version: int | None
    operation: str | None
    target_path: str
    literal: ScalarValue
    structure_policy: Literal["preserve", "raw"]


@dataclass(frozen=True)
class RuleSnapshot:
    raw: bytes
    schema_id: str
    candidate_id: str
    rules: tuple[ScalarRule, ...]

    @property
    def rule_set_id(self) -> str:
        return sha256(self.raw).hexdigest()


class _XDR:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.pos = 0

    def take(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.raw):
            raise JournalEventError("truncated NFSPRUL1 snapshot")
        result = self.raw[self.pos:end]
        self.pos = end
        return result

    def word(self, maximum: int = 2**32 - 1) -> int:
        value = int.from_bytes(self.take(4), "big")
        if value > maximum:
            raise JournalEventError("NFSPRUL1 word outside its bound")
        return value

    def name(self, maximum: int) -> str:
        length = self.word(maximum)
        value = self.take(length)
        if not value or any(c < 0x21 or c > 0x7e for c in value):
            raise JournalEventError("NFSPRUL1 requires nonempty visible ASCII names")
        if any(self.take((-length) % 4)):
            raise JournalEventError("nonzero NFSPRUL1 padding")
        return value.decode("ascii")

    def optional_word(self) -> int | None:
        return self.word() if self.word(1) else None

    def require(self, actual: object, expected: object, feature: str) -> None:
        if actual != expected:
            raise UnsupportedRuleProfile(f"unsupported scalar-literal-v1 rule: {feature}")


def parse_ruleset(raw: bytes) -> RuleSnapshot:
    """Parse exact NFSPRUL1 bytes for this profile, never semantic approval.

    There is no callback, opaque acceptance token, or alternate rule index.
    Membership and scalar facts are derived exclusively from these bytes.
    Unsupported forms fail the entire snapshot, without dropping any rules.
    """
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_RULESET_BYTES:
        raise JournalEventError("NFSPRUL1 snapshot byte bound")
    rd = _XDR(raw)
    if rd.take(8) != b"NFSPRUL1":
        raise JournalEventError("invalid NFSPRUL1 magic")
    rd.require(rd.word(), 1, "semantic runtime version")
    schema_id, candidate_id = rd.name(256), rd.name(128)
    count = rd.word(MAX_RULES)
    if not count:
        raise UnsupportedRuleProfile("scalar-literal-v1 requires at least one rule")
    rules: list[ScalarRule] = []
    for _ in range(count):
        rule_id, intent_id = rd.name(128), rd.name(128)
        if rules and rule_id <= rules[-1].rule_id:
            raise JournalEventError("NFSPRUL1 rule IDs must be strictly ascending")
        direction = ("C2S", "S2C")[rd.word(1)]
        backend, client = rd.word(), rd.word()
        message_type = ("call", "reply")[rd.word(1)]
        program, version, procedure = rd.word(), rd.word(), rd.optional_word()
        family = rd.name(32)
        nfs_version, minor_version = rd.optional_word(), rd.optional_word()
        operation = rd.name(64) if rd.word(1) else None
        rd.require(rd.word(1), 0, "operation-array target")
        target_path = rd.name(512)
        rd.require(rd.word(5), 0, "non-value target part")
        rd.require(rd.word(16), 0, "predicates")
        rd.require(rd.word(4), 0, "non-replace mutation")
        rd.require(rd.word(1), 1, "absent transform")
        rd.require(rd.word(2), 0, "copy/builtin transform")
        kind = rd.word(7)
        if kind >= 6:
            raise UnsupportedRuleProfile("opaque/string literal needs a different evidence profile")
        classes = (IntValue, UIntValue, HyperValue, UHyperValue, BoolValue, EnumValue)
        names = ("int", "uint", "hyper", "uhyper", "bool", "enum")
        number = int.from_bytes(rd.take(8 if kind in (2, 3) else 4), "big",
                                signed=kind in (0, 2))
        if kind == 4:
            if number not in (0, 1):
                raise JournalEventError("noncanonical NFSPRUL1 bool")
            number = bool(number)
        literal = classes[kind](kind=names[kind], value=number)
        policy = ("preserve", "raw")[rd.word(1)]
        for forwarded in (True, False):
            expected = int(forwarded and message_type == "reply" and procedure is not None)
            if rd.word(1) != expected:
                raise JournalEventError("NFSPRUL1 rpc_procedure dependency mismatch")
            rd.require(rd.word(1), 0, "request operation dependency")
            rd.require(rd.word(16), 0, "request field dependencies")
        rd.word(0)  # ALL_MATCHES is the only canonical application mode.
        rules.append(ScalarRule(rule_id, intent_id, direction, backend, client,
                                message_type, program, version, procedure, family,
                                nfs_version, minor_version, operation, target_path,
                                literal, policy))
    if rd.pos != len(raw):
        raise JournalEventError("trailing NFSPRUL1 bytes")
    return RuleSnapshot(raw, schema_id, candidate_id, tuple(rules))


class RulesetPayload(_Record):
    profile: Literal["scalar-literal-v1"]
    semantic_runtime_version: Literal[1]
    schema_id: SchemaId
    candidate_id: Name
    rule_set_id: Digest
    snapshot_hex: Annotated[str, Field(min_length=2, max_length=MAX_RULESET_BYTES * 2,
                                      pattern=r"^(?:[0-9a-f]{2})+$")]

    @model_validator(mode="after")
    def _snapshot(self) -> Self:
        snapshot = parse_ruleset(bytes.fromhex(self.snapshot_hex))
        if (self.schema_id, self.candidate_id, self.rule_set_id) != (
                snapshot.schema_id, snapshot.candidate_id, snapshot.rule_set_id):
            raise ValueError("RULESET metadata/hash differs from exact NFSPRUL1 bytes")
        # Literal[1] alone accepts True in Pydantic; the wire must not.
        if type(self.semantic_runtime_version) is not int:
            raise ValueError("runtime version must be an integer")
        return self


class GenerationCorrelation(_Record):
    vm_instance_id: Annotated[str, Field(min_length=1, max_length=256,
                                        pattern=r"^[A-Za-z0-9_.:/-]+$")]
    lane_id: U64
    proc_id: U64
    kcov_generation: Annotated[int, Field(ge=1, le=2**64 - 1)]
    rule_set_id: Digest
    program_digest: Digest


class GenerationOpenPayload(_Record):
    draining_generations: Annotated[tuple[U64, ...], Field(max_length=MAX_GENERATIONS)]

    @model_validator(mode="after")
    def _set_order(self) -> Self:
        if self.draining_generations != tuple(sorted(set(self.draining_generations))):
            raise ValueError("draining generations must be sorted and unique")
        if 0 in self.draining_generations:
            raise ValueError("generation zero is reserved")
        return self


class GenerationDrainingPayload(_Record):
    pass


class RecordContext(_Record):
    direction: Direction
    backend: U32
    client: U32
    connection_id: Annotated[int, Field(ge=1, le=2**64 - 1)]
    rpc_message_type: MessageType
    rpc_program: U32 | None
    rpc_version: U32 | None
    rpc_procedure: U32 | None
    protocol_family: Family | None
    nfs_version: U32 | None
    minor_version: U32 | None


class WireSpan(_Record):
    offset: Annotated[int, Field(ge=0, lt=MAX_RECORD_BYTES, multiple_of=4)]
    length: Literal[4, 8]


class SemanticTarget(_Record):
    kind: Literal["field"]
    semantic_path: Path
    part: Literal["value"]
    field_index: U32
    operation_index: U32 | None
    operation: Operation | None
    wire_span: WireSpan

    @model_validator(mode="after")
    def _operation(self) -> Self:
        if (self.operation is None) != (self.operation_index is None):
            raise ValueError("operation name and index must be present together")
        return self


class ConcreteEdit(_Record):
    offset: Annotated[int, Field(ge=0, lt=MAX_RECORD_BYTES, multiple_of=4)]
    remove_length: Literal[4, 8]
    original_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{8}|[0-9a-f]{16})$")]
    replacement_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{8}|[0-9a-f]{16})$")]


class Application(_Record):
    rule_id: Name
    semantic_target: SemanticTarget
    mutation_kind: Literal["replace"]
    structure_policy: Literal["preserve", "raw"]
    predicate_values: tuple[()]
    transform_source_values: tuple[()]
    original_value_snapshot: ScalarValue
    mutated_value_snapshot: ScalarValue
    concrete_edits: tuple[ConcreteEdit]

    @model_validator(mode="after")
    def _scalar_evidence(self) -> Self:
        old, new = self.original_value_snapshot, self.mutated_value_snapshot
        edit, = self.concrete_edits
        span = self.semantic_target.wire_span
        if old.kind != new.kind:
            raise ValueError("replacement cannot reinterpret a scalar type")
        if (edit.original_hex, edit.replacement_hex) != (scalar_bytes(old).hex(), scalar_bytes(new).hex()):
            raise ValueError("semantic scalar and concrete bytes disagree")
        if (span.offset, span.length) != (edit.offset, edit.remove_length):
            raise ValueError("WireRef-derived span and concrete edit disagree")
        if edit.remove_length != len(scalar_bytes(old)):
            raise ValueError("scalar edit width mismatch")
        return self


class SignatureMember(_Record):
    rule_id: Name
    semantic_path: Path
    part: Literal["value"]
    mutation_kind: Literal["replace"]


def signature_for(applications: tuple[Application, ...]) -> tuple[SignatureMember, ...]:
    members = (SignatureMember(rule_id=a.rule_id, semantic_path=a.semantic_target.semantic_path,
                               part="value", mutation_kind="replace") for a in applications)
    return tuple(sorted(members, key=lambda m: (m.rule_id, m.semantic_path, m.part, m.mutation_kind)))


class ConcreteOutput(_Record):
    final_record_length: Annotated[int, Field(ge=8, le=MAX_RECORD_BYTES + 4)]
    framed_record_hex: Annotated[str, Field(min_length=16, max_length=(MAX_RECORD_BYTES + 4) * 2,
                                           pattern=r"^(?:[0-9a-f]{2})+$")]


class ExposurePayload(_Record):
    batch_id: Name
    record_context: RecordContext
    semantic_signature: Annotated[tuple[SignatureMember, ...],
                                  Field(min_length=1, max_length=MAX_APPLICATIONS)]
    applications: Annotated[tuple[Application, ...], Field(min_length=1, max_length=MAX_APPLICATIONS)]
    original_record_hex: Annotated[str, Field(min_length=8, max_length=MAX_RECORD_BYTES * 2,
                                             pattern=r"^(?:[0-9a-f]{2})+$")]
    output: ConcreteOutput

    @model_validator(mode="after")
    def _complete_evidence(self) -> Self:
        if self.semantic_signature != signature_for(self.applications):
            raise ValueError("semantic signature must be the exact sorted application multiset")
        keys = tuple((a.rule_id, a.semantic_target.field_index) for a in self.applications)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("applications must be unique and sorted by rule_id/field_index")
        original = bytes.fromhex(self.original_record_hex)
        result = bytearray(original)
        edits = sorted((a.concrete_edits[0] for a in self.applications), key=lambda e: e.offset)
        end = 0
        for edit in edits:
            if edit.offset < end:
                raise ValueError("overlapping concrete edits")
            end = edit.offset + edit.remove_length
            if end > len(original) or original[edit.offset:end].hex() != edit.original_hex:
                raise ValueError("concrete original precondition mismatch")
            result[edit.offset:end] = bytes.fromhex(edit.replacement_hex)
        # M4c's output contract is one last fragment. Lengths include its marker;
        # all edit coordinates and original bytes are marker-free RPC payload.
        framed = (0x80000000 | len(result)).to_bytes(4, "big") + result
        if (self.output.final_record_length != len(framed)
                or self.output.framed_record_hex != framed.hex()):
            raise ValueError("final framed output differs from the complete concrete rebuild")
        return self


HardRefusal = Literal[
    "schema_mismatch", "decode_unavailable", "transaction_context_missing",
    "transaction_context_unusable", "target_ambiguous", "predicate_reference_ambiguous",
    "transform_failed", "conflict", "structure_constraint_failed", "apply_precondition_failed",
]
HARD_REFUSALS = (
    "schema_mismatch", "decode_unavailable", "transaction_context_missing",
    "transaction_context_unusable", "target_ambiguous", "predicate_reference_ambiguous",
    "transform_failed", "conflict", "structure_constraint_failed", "apply_precondition_failed",
)


class RefusalPayload(_Record):
    rule_id: Name
    refusal: HardRefusal
    record_context: RecordContext


class ForwardCompletePayload(_Record):
    batch_id: Name
    forwarded_length: Annotated[int, Field(ge=8, le=MAX_RECORD_BYTES + 4)]


class ForwardFailedPayload(_Record):
    batch_id: Name
    reason: Annotated[str, Field(min_length=1, max_length=256, pattern=r"^[ -~]+$")]
    bytes_written: Annotated[int, Field(ge=0, le=MAX_RECORD_BYTES + 4)] | None


class ResolverCounts(_Record):
    scope_miss: U64
    rpc_selector_miss: U64
    schema_mismatch: U64
    decode_unavailable: U64
    transaction_context_missing: U64
    transaction_context_unusable: U64
    target_not_found: U64
    target_ambiguous: U64
    predicate_false: U64
    predicate_reference_ambiguous: U64
    transform_unsupported: U64
    transform_failed: U64
    resolved: U64
    conflict: U64
    structure_constraint_failed: U64
    apply_precondition_failed: U64


class RuleSummary(_Record):
    rule_id: Name
    counts: ResolverCounts


Summaries = Annotated[tuple[RuleSummary, ...], Field(min_length=1, max_length=MAX_RULES)]


def _summary_order(values: tuple[RuleSummary, ...]) -> None:
    ids = tuple(v.rule_id for v in values)
    if ids != tuple(sorted(set(ids))):
        raise ValueError("rule summaries must be sorted and unique")


class GenerationClosure(_Record):
    reason: Literal["drained", "reply_unresolved", "aborted"]
    drain_bound: U64  # milliseconds; explicit even for aborted closure
    reply_unresolved_count: U64

    @model_validator(mode="after")
    def _reason(self) -> Self:
        if self.reason == "drained" and self.reply_unresolved_count:
            raise ValueError("drained closure cannot have unresolved replies")
        if self.reason == "reply_unresolved" and not self.reply_unresolved_count:
            raise ValueError("reply_unresolved closure needs a positive unresolved count")
        return self


class GenerationCompletePayload(_Record):
    records_seen: U64
    exposure_batch_count: U64
    outside_activation_window: U64
    evidence_path_failures: U64
    resolver_summary: Summaries
    closure: GenerationClosure

    @model_validator(mode="after")
    def _summary(self) -> Self:
        _summary_order(self.resolver_summary)
        if self.exposure_batch_count > self.records_seen:
            raise ValueError("exposure batch count exceeds records seen")
        return self


class RunCompletePayload(_Record):
    rule_summaries: Summaries
    batch_count: U64
    forward_complete_count: U64
    forward_failed_count: U64

    @model_validator(mode="after")
    def _summary(self) -> Self:
        _summary_order(self.rule_summaries)
        if self.batch_count != self.forward_complete_count + self.forward_failed_count:
            raise ValueError("RUN_COMPLETE batch/forward counts disagree")
        return self


class _Event(_Record):
    schema_version: Literal["nfs-proxy-journal-event.v1"] = "nfs-proxy-journal-event.v1"
    session_binding: HostSessionBinding
    event_seq: U64


class _GenerationEvent(_Event):
    program_generation_correlation: GenerationCorrelation

    @model_validator(mode="after")
    def _binding(self) -> Self:
        c, s = self.program_generation_correlation, self.session_binding
        if c.vm_instance_id != s.vm_instance_id or c.rule_set_id != s.rule_set_id:
            raise ValueError("generation and session identity disagree")
        return self


class RulesetEvent(_Event):
    event_type: Literal["RULESET"]
    payload: RulesetPayload

    @model_validator(mode="after")
    def _binding(self) -> Self:
        if self.payload.rule_set_id != self.session_binding.rule_set_id:
            raise ValueError("RULESET and session identity disagree")
        return self


class GenerationOpenEvent(_GenerationEvent):
    event_type: Literal["GENERATION_OPEN"]
    payload: GenerationOpenPayload


class GenerationDrainingEvent(_GenerationEvent):
    event_type: Literal["GENERATION_DRAINING"]
    payload: GenerationDrainingPayload


class ExposureEvent(_GenerationEvent):
    event_type: Literal["EXPOSURE_INTENT"]
    payload: ExposurePayload


class RefusalEvent(_GenerationEvent):
    event_type: Literal["APPLY_REFUSAL"]
    payload: RefusalPayload


class ForwardCompleteEvent(_GenerationEvent):
    event_type: Literal["FORWARD_COMPLETE"]
    payload: ForwardCompletePayload


class ForwardFailedEvent(_GenerationEvent):
    event_type: Literal["FORWARD_FAILED"]
    payload: ForwardFailedPayload


class GenerationCompleteEvent(_GenerationEvent):
    event_type: Literal["GENERATION_COMPLETE"]
    payload: GenerationCompletePayload


class RunCompleteEvent(_Event):
    event_type: Literal["RUN_COMPLETE"]
    payload: RunCompletePayload


JournalEvent = Annotated[
    RulesetEvent | GenerationOpenEvent | GenerationDrainingEvent | ExposureEvent |
    RefusalEvent | ForwardCompleteEvent | ForwardFailedEvent | GenerationCompleteEvent |
    RunCompleteEvent, Field(discriminator="event_type"),
]
_EVENT = TypeAdapter(JournalEvent)


def decode_event(payload: bytes) -> JournalEvent:
    """Validate one exact canonical event payload; no authority is established."""
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise JournalEventError("event payload byte bound")
    try:
        parse_json(payload)  # Duplicate keys, UTF-8 and nonfinite numbers.
        event = _EVENT.validate_json(payload)
        if canonical_json(event) != payload:
            raise ValueError("noncanonical event")
        return event
    except (ValueError, TypeError, RecursionError) as error:
        raise JournalEventError(f"invalid journal event: {error}") from error


def encode_event(event: JournalEvent) -> bytes:
    """Revalidate even model_copy/model_construct instances before encoding."""
    try:
        event = _EVENT.validate_python(event)
        payload = canonical_json(event)
        decode_event(payload)
        return payload
    except (ValueError, TypeError, RecursionError) as error:
        raise JournalEventError(f"invalid journal event: {error}") from error
