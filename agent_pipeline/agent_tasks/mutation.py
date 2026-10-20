"""Structured output of Mutation Strategy (08 §5-§11, §15).

The vocabulary is the Proxy semantic runtime's (``03-nfs-proxy/04`` §3-§17).
This module only fixes the shape: names, paths and types are checked
against a ProtocolSchema by the Mutation Rule Compiler (08 §12), not here.
Nothing in a rule set is a byte offset, recorded original bytes, a raw
packet, a host command or a budget (08 §5); the closed models have no field
for any of them.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import ConfigDict, Field, RootModel, model_validator

from ..contracts import GapClass, Record
from .analysis import LongText, ShortText

#: NFSPRUL1 id and semantic_path (03-nfs-proxy/04 §35): visible ASCII.
SemanticId = Annotated[str, Field(min_length=1, max_length=128,
                                  pattern=r"^[\x21-\x7e]+$")]
SemanticPath = Annotated[str, Field(min_length=1, max_length=512,
                                    pattern=r"^[\x21-\x7e]+$")]
U32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
MAX_LITERAL_BYTES = 4096

# ---------------------------------------------------------------- values


class IntLiteral(Record):
    kind: Literal["int"] = "int"
    value: int = Field(ge=-(1 << 31), le=(1 << 31) - 1)


class UintLiteral(Record):
    kind: Literal["uint"] = "uint"
    value: U32


class HyperLiteral(Record):
    kind: Literal["hyper"] = "hyper"
    value: int = Field(ge=-(1 << 63), le=(1 << 63) - 1)


class UhyperLiteral(Record):
    kind: Literal["uhyper"] = "uhyper"
    value: int = Field(ge=0, le=(1 << 64) - 1)


class BoolLiteral(Record):
    kind: Literal["bool"] = "bool"
    value: bool


class EnumLiteral(Record):
    """A ProtocolSchema enum name such as ``NFS4ERR_BAD_STATEID``; the
    Compiler binds it to its wire word."""

    kind: Literal["enum"] = "enum"
    name: SemanticId


class OpaqueLiteral(Record):
    kind: Literal["opaque"] = "opaque"
    hex: str = Field(max_length=2 * MAX_LITERAL_BYTES,
                     pattern=r"^(?:[0-9a-f]{2})*$")


class StringLiteral(Record):
    kind: Literal["string"] = "string"
    value: str = Field(max_length=MAX_LITERAL_BYTES)

    @model_validator(mode="after")
    def _bound(self) -> StringLiteral:
        if len(self.value.encode("utf-8")) > MAX_LITERAL_BYTES:
            raise ValueError("string literal exceeds byte limit")
        return self


TypedLiteral = Annotated[
    Union[IntLiteral, UintLiteral, HyperLiteral, UhyperLiteral, BoolLiteral,
          EnumLiteral, OpaqueLiteral, StringLiteral],
    Field(discriminator="kind")]


class ValueRef(Record):
    """03-nfs-proxy/04 §8.  ``target`` is the target occurrence itself and
    has no path; every other source names one.  There is no source for a
    value from an earlier transaction (state lineage, 08 §15)."""

    kind: Literal["value_ref"] = "value_ref"
    source: Literal["target", "current_message", "request_forwarded",
                    "request_original"]
    path: SemanticPath | None = None

    @model_validator(mode="after")
    def _shape(self) -> ValueRef:
        if (self.source == "target") != (self.path is None):
            raise ValueError("a target ValueRef has no path; others need one")
        return self


Operand = Annotated[
    Union[IntLiteral, UintLiteral, HyperLiteral, UhyperLiteral, BoolLiteral,
          EnumLiteral, OpaqueLiteral, StringLiteral, ValueRef],
    Field(discriminator="kind")]


# ---------------------------------------------------------------- selector


class TrafficScope(Record):
    """08 §6-§7: a route the Stage 1 harness already uses."""

    direction: Literal["C2S", "S2C"]
    backend: SemanticId
    client: SemanticId


class RpcSelector(Record):
    """``message_type`` is stated, never inferred from direction (08 §6)."""

    message_type: Literal["call", "reply"]
    program: U32
    version: U32
    procedure: U32 | None = None


class ProtocolSelector(Record):
    family: SemanticId
    nfs_version: U32 | None = None
    minor_version: U32 | None = None


class SemanticTarget(Record):
    kind: Literal["field", "operation_array"]
    path: SemanticPath
    part: Literal["value", "encoded", "metadata:length", "metadata:count",
                  "metadata:discriminant", "metadata:padding"] = "value"


class Predicate(Record):
    lhs: ValueRef
    op: Literal["eq", "ne", "lt", "le", "gt", "ge"]
    rhs: Operand


class Selector(Record):
    """08 §8.  No ordinal identity: predicates select by content."""

    rpc: RpcSelector
    protocol: ProtocolSelector
    operation: SemanticId | None = None
    target: SemanticTarget
    predicates: tuple[Predicate, ...] = Field(default=(), max_length=16)


# ---------------------------------------------------------------- mutation


class LiteralTransform(Record):
    kind: Literal["literal"] = "literal"
    value: TypedLiteral


class CopyTransform(Record):
    kind: Literal["copy"] = "copy"
    source: ValueRef


class BuiltinTransform(Record):
    kind: Literal["builtin"] = "builtin"
    transform_id: SemanticId
    args: tuple[TypedLiteral, ...] = Field(default=(), max_length=8)


class OperationArgument(Record):
    path: SemanticPath
    value: TypedLiteral


class OperationValue(Record):
    """The typed operation object of op_append / op_prepend (03-nfs-proxy/04
    §16), never raw XDR.  NFSPRUL1 has no encoding for it yet, so the
    Compiler decides whether any operation is supported."""

    kind: Literal["operation"] = "operation"
    operation: SemanticId
    arguments: tuple[OperationArgument, ...] = Field(default=(),
                                                     max_length=32)


Transform = Annotated[
    Union[LiteralTransform, CopyTransform, BuiltinTransform, OperationValue],
    Field(discriminator="kind")]


class Mutation(Record):
    """08 §9.  ``structure_policy`` has no default in any kind."""

    kind: Literal["replace", "insert", "delete", "op_append", "op_prepend"]
    transform: Transform | None = None
    structure_policy: Literal["preserve", "raw"]

    @model_validator(mode="after")
    def _shape(self) -> Mutation:
        operation = isinstance(self.transform, OperationValue)
        if self.kind == "delete":
            if self.transform is not None:
                raise ValueError("delete takes no transform")
        elif self.kind in ("op_append", "op_prepend"):
            if not operation:
                raise ValueError(f"{self.kind} needs an operation value")
        elif self.transform is None or operation:
            raise ValueError(f"{self.kind} needs a literal, copy or builtin "
                             "transform")
        return self


class ExpectedEffect(Record):
    """08 §10: why, never executed."""

    target_state: LongText
    rationale: LongText


class MutationIntent(Record):
    intent_id: SemanticId
    traffic_scope: TrafficScope
    selector: Selector
    mutation: Mutation
    # 08 §16: required, no default.
    targets_baseline_traffic: bool
    expected_effect: ExpectedEffect


class Hypothesis(Record):
    """Intents that form one trigger hypothesis only together (08 §5)."""

    hypothesis_id: SemanticId
    intents: tuple[SemanticId, ...] = Field(min_length=1, max_length=64)
    requirement: Literal["all"]


class MutationUncertainty(Record):
    description: LongText
    impact: LongText


class MutationRuleSet(Record):
    schema_version: Literal["mutation-rule-set.v1"] = "mutation-rule-set.v1"
    candidate_id: ShortText
    intents: tuple[MutationIntent, ...] = Field(min_length=1, max_length=64)
    hypotheses: tuple[Hypothesis, ...] = Field(min_length=1, max_length=32)
    uncertainties: tuple[MutationUncertainty, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def _shape(self) -> MutationRuleSet:
        ids = [i.intent_id for i in self.intents]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate intent_id")
        hyps = [h.hypothesis_id for h in self.hypotheses]
        if len(set(hyps)) != len(hyps):
            raise ValueError("duplicate hypothesis_id")
        known = set(ids)
        for h in self.hypotheses:
            if len(set(h.intents)) != len(h.intents):
                raise ValueError("hypothesis lists an intent twice")
            if not set(h.intents) <= known:
                raise ValueError("hypothesis names an unknown intent")
        return self


# ---------------------------------------------------------------- variants


class RuleSetDecision(Record):
    variant: Literal["rule_set"] = "rule_set"
    rule_set: MutationRuleSet


class MutationUnsupported(Record):
    """08 §15.  ``missing_capability_id`` comes from the HCAP vocabulary; when
    none fits it stays empty and ``reason`` names the capability (09 Agent
    guidance)."""

    variant: Literal["unsupported"] = "unsupported"
    gap_class: Literal[GapClass.MUTATION_ENGINE]
    missing_capability_id: str = Field(max_length=256)
    reason: LongText


MutationDecision = Annotated[
    Union[RuleSetDecision, MutationUnsupported],
    Field(discriminator="variant"),
]


class MutationStrategyOutput(RootModel[MutationDecision]):
    """A top-level discriminated union accepted as structured output."""

    model_config = ConfigDict(frozen=True)
