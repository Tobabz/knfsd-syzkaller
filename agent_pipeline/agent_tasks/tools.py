"""The complete read-only tool surface exposed to Stage 1 agents.

Every toolbox is bound by trusted host code to one kernel commit and one
HCAP revision.  Neither value is a model argument.  Source paths are
relative POSIX paths confined to ``SOURCE_PREFIXES``; traversal, absolute
paths, other kernel subsystems and backend results outside that boundary are
rejected.  Result counts, snippets and source excerpts are bounded before
they cross the runtime boundary.

There is deliberately no generic filesystem, shell, process, write,
artifact-by-path or network tool here.  The one check tool,
``validate_program``, runs the host's deterministic, side-effect-free plan
checks (pinned parser, call admission, HCAP) on a draft; it writes nothing
and is never a verdict.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Callable, Literal, Protocol, Sequence

from pydantic import Field, ValidationError

from ..contracts import Record
from ..hcap import ArtifactHcapChecker, HcapCatalog
from ..protocol_schema import (SN_DISCRIMINANT, SN_LIST_ELEMENT,
                               SN_OPERATION, SN_OPS_ARRAY, SN_REPEATED,
                               SN_ROOT, Node, ProtocolSchema, Resolution,
                               load_schemas)
from ..semantic_promotion import (PromotedSemanticCapabilityRegistry,
                                  promoted_registry)
from ..intake import ANALYSIS_ROOTS, in_analysis_roots, line_count
from .planning import ReachabilityPlanDraft

SOURCE_PREFIXES = ANALYSIS_ROOTS
MAX_SOURCE_LINES = 400
MAX_SOURCE_BYTES = 32 * 1024
MAX_MATCHES = 32
MAX_SNIPPET_BYTES = 512
MAX_HCAP_RESULTS = 8
MAX_HCAP_LIST_ITEMS = 32
MAX_HCAP_TEXT_BYTES = 1024
MAX_SEMANTIC_PATH_RESULTS = 32
MAX_SEMANTIC_PATH_SCAN = 4096
MAX_SEMANTIC_PATH_DEPTH = 64
MAX_VALIDATION_TEXT_BYTES = 2048


class ToolBoundaryError(ValueError):
    """A tool call attempted to cross its pinned read-only boundary."""


class BackendBoundaryError(ToolBoundaryError):
    """The source index answered outside the boundary: a backend fault the
    model cannot correct."""


class SourceNotFound(ToolBoundaryError):
    """The requested file does not exist at the pinned commit: a mistake
    in the call, not a backend failure."""


@dataclass(frozen=True)
class IndexedMatch:
    """One trusted source-index response before output bounding."""

    path: str
    line: int
    text: str
    symbol: str | None = None


class IndexedSource(str):
    """String-compatible source text with the adapter's truncation signal.

    A byte limit can drop part of a UTF-8 character, leaving fewer than the
    requested bytes. Only the adapter knows whether it discarded content.
    """

    truncated: bool

    def __new__(cls, text: str, *, truncated: bool = False):
        result = super().__new__(cls, text)
        result.truncated = truncated
        return result


class KernelSourceIndex(Protocol):
    """A commit-aware, read-only source index supplied by the host.

    Implementations must honor the passed roots and limits.  The toolbox
    validates and bounds responses again before exposing them to a model.
    ``search`` is a literal text search, not an arbitrary regular expression.
    ``read`` may return a plain string for complete text; adapters that cap
    it must return ``IndexedSource`` with an explicit truncation flag.
    """

    def read(self, commit: str, path: str, start_line: int, end_line: int,
             max_bytes: int) -> str | None: ...

    def search(self, commit: str, query: str, roots: tuple[str, ...],
               max_results: int) -> Sequence[IndexedMatch]: ...

    def callers(self, commit: str, symbol: str, roots: tuple[str, ...],
                max_results: int) -> Sequence[IndexedMatch]: ...

    def callees(self, commit: str, path: str, symbol: str,
                max_results: int) -> Sequence[IndexedMatch]: ...


class HcapSource(Protocol):
    def load_catalog(self, revision: str) -> HcapCatalog: ...

    def load_semantic_scope(self, revision: str
                            ) -> PromotedSemanticCapabilityRegistry | None:
        """The promoted semantic registry the revision pins, or None."""


class ArtifactHcapSource:
    """HCAP lookup over the already pinned artifact-backed checker."""

    def __init__(self, checker: ArtifactHcapChecker) -> None:
        self.checker = checker

    def load_catalog(self, revision: str) -> HcapCatalog:
        return self.checker.load_catalog(revision)

    def load_semantic_scope(self, revision: str
                            ) -> PromotedSemanticCapabilityRegistry | None:
        return promoted_registry(self.checker.store,
                                 self.checker.load_catalog(revision))


class ToolArgs(Record):
    pass


class ReadSourceArgs(ToolArgs):
    path: str = Field(min_length=1, max_length=512)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)


class SearchSourceArgs(ToolArgs):
    query: str = Field(min_length=2, max_length=160, pattern=r"\S")
    path_prefix: str | None = Field(default=None, max_length=512)
    max_results: int = Field(default=20, ge=1, le=MAX_MATCHES)


class SymbolLookupArgs(ToolArgs):
    symbol: str = Field(min_length=1, max_length=256,
                        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    path_prefix: str | None = Field(default=None, max_length=512)
    max_results: int = Field(default=20, ge=1, le=MAX_MATCHES)


class CalleeLookupArgs(ToolArgs):
    path: str = Field(min_length=1, max_length=512)
    symbol: str = Field(min_length=1, max_length=256,
                        pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    max_results: int = Field(default=20, ge=1, le=MAX_MATCHES)


class HcapLookupArgs(ToolArgs):
    capability_id: str | None = Field(default=None, max_length=256)
    max_results: int = Field(default=MAX_HCAP_RESULTS, ge=1,
                             le=MAX_HCAP_RESULTS)


class SemanticScopeArgs(ToolArgs):
    pass


class SemanticPathLookupArgs(ToolArgs):
    schema_id: str = Field(min_length=1, max_length=160)
    message_type: Literal["call", "reply"]
    operation: str = Field(min_length=1, max_length=128,
                           pattern=r"^[\x21-\x7e]+$")
    query: str | None = Field(default=None, min_length=1, max_length=128,
                              pattern=r"\S")
    max_results: int = Field(default=MAX_SEMANTIC_PATH_RESULTS, ge=1,
                             le=MAX_SEMANTIC_PATH_RESULTS)


class ValidateProgramArgs(ToolArgs):
    plan: ReachabilityPlanDraft


class ProgramValidation(Record):
    """What the host's plan checks say about a draft.  ``accepted`` means
    only that materialization would accept it now; Q1 decides reachability.
    ``stage`` names the check that refused: schema (the draft itself),
    request (it disagrees with the trusted task), materializer (HCAP, parse
    or call admission) or host (the check could not run)."""

    accepted: bool
    stage: Literal["schema", "request", "materializer", "host"] | None = None
    reason: str | None = None
    detail: str = ""
    message: str = ""


#: Runs the host checks on a draft; bound by the toolbox factory to one
#: task's binding and trusted request.
ProgramValidator = Callable[[ReachabilityPlanDraft], ProgramValidation]


class SourceExcerpt(Record):
    """Returned line range; the last line may be partial when truncated.

    Empty text has end_line == start_line - 1.
    """

    path: str
    start_line: int
    end_line: int
    text: str
    truncated: bool


class SourceMatch(Record):
    path: str
    line: int = Field(ge=1)
    text: str
    symbol: str | None = None


class SourceMatches(Record):
    matches: tuple[SourceMatch, ...]
    truncated: bool


class HcapCapability(Record):
    capability_id: str
    name: str
    purpose: str
    usable_stage: tuple[str, ...]
    usable_by: tuple[str, ...]
    status: str
    scope: tuple[str, ...]
    validated_scope: tuple[str, ...]
    syz_calls: tuple[str, ...]
    host_tooling: tuple[str, ...]
    runtime_features: tuple[str, ...]
    constraints: tuple[str, ...]
    source_refs: tuple[str, ...]
    authority_refs: tuple[str, ...]


class HcapLookup(Record):
    hcap_revision: str
    capabilities: tuple[HcapCapability, ...]
    missing_capability_ids: tuple[str, ...]
    authority_refs: tuple[str, ...]
    truncated: bool


class SemanticScopeSubset(Record):
    subset_id: str
    description: str
    schema_ids: tuple[str, ...]
    directions: tuple[str, ...]
    message_types: tuple[str, ...]
    target_kinds: tuple[str, ...]
    parts: tuple[str, ...]
    mutation_kinds: tuple[str, ...]
    transforms: tuple[str, ...]
    structure_policies: tuple[str, ...]
    value_sources: tuple[str, ...]
    predicate_ops: tuple[str, ...]
    validation_items: tuple[str, ...]


class SemanticScopeLookup(Record):
    """Empty ``subsets`` means no semantic mutation is usable: a rule set
    would only be refused, so the Agent returns a mutation_engine gap."""

    hcap_revision: str
    proxy_sha256: str | None
    registry_digest: str | None
    registry_constraints: tuple[str, ...]
    subsets: tuple[SemanticScopeSubset, ...]
    truncated: bool


class SemanticPath(Record):
    """One canonical path; enum metadata has its own boundedness flag."""

    path: str
    value_kind: str
    type_name: str
    flags: tuple[str, ...]
    enum_literals: tuple[str, ...]
    enum_literals_truncated: bool


class SemanticPathLookup(Record):
    """Paths from one promoted ProtocolSchema operation or procedure.

    The selector fields are the exact values accepted by the deterministic
    Compiler.  In particular, an ``nfs4.1/...`` schema id still has family
    ``nfs4`` and minor version 1. ``truncated`` applies only to path
    traversal/results; each path reports enum literal truncation separately.
    """

    schema_id: str
    family: str
    rpc_program: int
    rpc_version: int
    minor_version: int | None
    message_type: Literal["call", "reply"]
    operation: str
    paths: tuple[SemanticPath, ...]
    truncated: bool


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    arguments: type[ToolArgs]


TOOL_DEFINITIONS = (
    ToolDefinition(
        "read_kernel_source",
        f"Read at most {MAX_SOURCE_LINES} lines (1-based, inclusive) of one "
        "file in the pinned kernel tree. Allowed roots: "
        + ", ".join(SOURCE_PREFIXES) + ".",
        ReadSourceArgs),
    ToolDefinition(
        "search_kernel_source",
        "Literal bounded search in the allowed roots (NFS, lockd, SUNRPC, "
        "exportfs and VFS entry files); path_prefix narrows it to one.",
        SearchSourceArgs),
    ToolDefinition(
        "find_callers",
        "Find bounded indexed callers of one C symbol in allowed roots.",
        SymbolLookupArgs),
    ToolDefinition(
        "find_callees",
        "Find bounded indexed callees of one function in an allowed file.",
        CalleeLookupArgs),
    ToolDefinition(
        "lookup_hcap",
        "Read bounded capability data from the task's pinned HCAP revision.",
        HcapLookupArgs),
    ToolDefinition(
        "lookup_semantic_scope",
        "Read the semantic mutation subsets the pinned HCAP revision "
        "promoted (M7). A MutationRuleSet must fit one subset; none means "
        "no semantic mutation is supported.",
        SemanticScopeArgs),
    ToolDefinition(
        "lookup_semantic_paths",
        "List bounded canonical paths and exact protocol selector values "
        "for one operation or procedure in a ProtocolSchema promoted by "
        "the pinned HCAP revision. query optionally filters paths.",
        SemanticPathLookupArgs),
)

VALIDATE_PROGRAM_TOOL = ToolDefinition(
    "validate_program",
    "Check a complete ReachabilityPlanDraft with the host's pinned syz "
    "parser, call admission and HCAP plan check, exactly as the "
    "Materializer will after you answer. Costs no repair attempt and "
    "stores nothing. Returns accepted, or the refusing check with its "
    "reason, detail and parser message. Acceptance is not a Q1 verdict.",
    ValidateProgramArgs)


def _bounded(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def _bounded_items(values: Sequence[str], *, limit: int = MAX_HCAP_LIST_ITEMS
                   ) -> tuple[tuple[str, ...], bool]:
    result = []
    truncated = len(values) > limit
    for value in values[:limit]:
        item, cut = _bounded(str(value), MAX_HCAP_TEXT_BYTES)
        result.append(item)
        truncated |= cut
    return tuple(result), truncated


_PATH_FLAGS = (
    (SN_OPERATION, "operation"),
    (SN_ROOT, "root"),
    (SN_DISCRIMINANT, "discriminant"),
    (SN_REPEATED, "repeated"),
    (SN_OPS_ARRAY, "operation_array"),
    (SN_LIST_ELEMENT, "list_element"),
)


def _schema_paths(schema: ProtocolSchema, *, response: bool,
                  operation: str) -> tuple[tuple[tuple[str, Node], ...], bool]:
    """Enumerate one root using the same names ``resolve`` accepts.

    Normalized schemas already reject ambiguous positions.  The explicit
    scan/depth bounds keep a future wider schema from expanding a model tool
    response without limit; every emitted path is resolved again before it
    crosses the boundary.
    """

    mine = "response" if response else "request"
    leaf = schema.response_leaf if response else schema.request_leaf
    values: list[tuple[str, Node]] = []
    seen: set[str] = set()
    truncated = False

    def emit(path: str) -> Node | None:
        nonlocal truncated
        if path in seen:
            return None
        if len(values) >= MAX_SEMANTIC_PATH_SCAN:
            truncated = True
            return None
        resolution, node = schema.resolve(response, path)
        if resolution is not Resolution.FOUND or node is None:
            raise BackendBoundaryError(
                "ProtocolSchema generated a path it cannot resolve")
        seen.add(path)
        values.append((path, node))
        return node

    def walk(type_id: int, path: str, depth: int) -> None:
        nonlocal truncated
        node = emit(path)
        if node is None:
            return
        # Operations are independent roots in ProtocolSchema. The enclosing
        # COMPOUND array is queryable, but its union elements are not children.
        if node.flags & SN_OPS_ARRAY:
            return
        if depth >= MAX_SEMANTIC_PATH_DEPTH:
            truncated = True
            return
        ty = schema.types[type_id]
        if schema._is_ops_union(ty):
            return
        kind = ty["kind"]
        if kind == "struct":
            for name, child in ty["fields"]:
                walk(child, f"{path}.{name}", depth + 1)
        elif kind == "union":
            walk(ty["disc"][1], f"{path}.{ty['disc'][0]}", depth + 1)
            for arm in schema._arms(ty):
                if arm.get("type") is not None:
                    walk(arm["type"], f"{path}.{arm['component']}",
                         depth + 1)
        elif kind in ("array_fixed", "array_var", "optional"):
            walk(ty["sub"], f"{path}[]", depth + 1)

    for procedure in schema.procedures:
        if procedure["name"] != operation:
            continue
        type_id = procedure["res"] if response else procedure["arg"]
        if type_id is not None:
            walk(type_id,
                 f"{schema.family}.{mine}.{operation}.{leaf}", 0)

    for type_id, ty in enumerate(schema.types):
        if not schema._is_ops_union(ty) or ty["operations"] != mine:
            continue
        for arm in schema._arms(ty):
            if arm["branch"] != operation:
                continue
            base = f"{schema.family}.{mine}.{operation}"
            emit(base)
            emit(f"{base}.{ty['disc'][0]}")
            if arm.get("type") is not None:
                walk(arm["type"], f"{base}.{arm['component']}", 0)

    return tuple(values), truncated


def _source_path(path: str) -> str:
    if not isinstance(path, str) or "\x00" in path or "\\" in path:
        raise ToolBoundaryError("source path must be a relative POSIX path")
    pure = PurePosixPath(path)
    if pure.is_absolute() or not pure.parts or any(
            part in ("", ".", "..") for part in pure.parts):
        raise ToolBoundaryError("source path must be normalized and relative")
    normalized = pure.as_posix()
    if normalized != path.rstrip("/"):
        raise ToolBoundaryError("source path must be normalized")
    if not in_analysis_roots(normalized):
        raise ToolBoundaryError(
            "source path is outside the Stage 1 roots: "
            + ", ".join(SOURCE_PREFIXES))
    return normalized


def _roots(path_prefix: str | None) -> tuple[str, ...]:
    if path_prefix is None:
        return SOURCE_PREFIXES
    root = _source_path(path_prefix)
    if root + "/" in SOURCE_PREFIXES:
        return (root + "/",)            # the directory, not a name prefix
    return (root,)


class Stage1Toolbox:
    """Pinned dispatcher containing seven read-only tools, plus
    ``validate_program`` when the factory binds a program validator."""

    def __init__(self, source: KernelSourceIndex, hcap: HcapSource, *,
                 kernel_commit: str, hcap_revision: str,
                 program_validator: ProgramValidator | None = None) -> None:
        self._source = source
        self._hcap = hcap
        self._commit = kernel_commit
        self._hcap_revision = hcap_revision
        self._validator = program_validator
        self._all = TOOL_DEFINITIONS if program_validator is None else \
            TOOL_DEFINITIONS + (VALIDATE_PROGRAM_TOOL,)
        self._definitions = {item.name: item for item in self._all}

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return self._all

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self._all)

    def invoke(self, name: str, arguments: dict) -> Record:
        definition = self._definitions.get(name)
        if definition is None:
            raise ToolBoundaryError(f"tool is not registered: {name}")
        if definition is VALIDATE_PROGRAM_TOOL:
            return self._validate_program(arguments)
        parsed = definition.arguments.model_validate(arguments)
        if isinstance(parsed, ReadSourceArgs):
            return self._read(parsed)
        if isinstance(parsed, SearchSourceArgs):
            return self._search(parsed)
        if isinstance(parsed, SymbolLookupArgs):
            return self._callers(parsed)
        if isinstance(parsed, CalleeLookupArgs):
            return self._callees(parsed)
        if isinstance(parsed, HcapLookupArgs):
            return self._lookup_hcap(parsed)
        if isinstance(parsed, SemanticScopeArgs):
            return self._lookup_semantic_scope()
        if isinstance(parsed, SemanticPathLookupArgs):
            return self._lookup_semantic_paths(parsed)
        raise AssertionError("unhandled Stage 1 tool arguments")

    def _validate_program(self, arguments: dict) -> ProgramValidation:
        # A draft that fails its own schema is an answer here, not a tool
        # call mistake: the model is asking exactly that question.
        # Records are strict in Python mode; tool arguments arrive as JSON.
        try:
            args = ValidateProgramArgs.model_validate_json(
                json.dumps(arguments))
        except (ValidationError, TypeError, ValueError) as exc:
            text, _ = _bounded(str(exc), MAX_VALIDATION_TEXT_BYTES)
            return ProgramValidation(accepted=False, stage="schema",
                                     reason="draft_schema_invalid",
                                     message=text)
        result = self._validator(args.plan)
        if not isinstance(result, ProgramValidation):
            raise BackendBoundaryError("program validator answered outside "
                                       "its contract")
        detail, _ = _bounded(result.detail, MAX_VALIDATION_TEXT_BYTES)
        message, _ = _bounded(result.message, MAX_VALIDATION_TEXT_BYTES)
        return result.model_copy(update={"detail": detail,
                                         "message": message})

    def _read(self, args: ReadSourceArgs) -> SourceExcerpt:
        path = _source_path(args.path)
        if args.end_line < args.start_line:
            raise ToolBoundaryError("end_line is before start_line")
        if args.end_line - args.start_line + 1 > MAX_SOURCE_LINES:
            raise ToolBoundaryError(
                f"source reads are limited to {MAX_SOURCE_LINES} lines")
        try:
            text = self._source.read(
                self._commit, path, args.start_line, args.end_line,
                MAX_SOURCE_BYTES)
        except FileNotFoundError:
            text = None
        if text is None:
            raise SourceNotFound(f"{path} does not exist at the pinned commit")
        truncated = isinstance(text, IndexedSource) and text.truncated
        text, cut = _bounded(text, MAX_SOURCE_BYTES)
        return SourceExcerpt(path=path, start_line=args.start_line,
                             end_line=args.start_line + line_count(text) - 1,
                             text=text, truncated=truncated or cut)

    def _matches(self, values: Sequence[IndexedMatch], requested: int
                 ) -> SourceMatches:
        limited = values[:requested]
        result = []
        truncated = len(values) > requested
        for value in limited:
            try:
                path = _source_path(value.path)
            except ToolBoundaryError as exc:
                raise BackendBoundaryError(
                    f"source index returned a path {exc}") from None
            if type(value.line) is not int or value.line < 1:
                raise BackendBoundaryError(
                    "source index returned an invalid line")
            snippet, cut = _bounded(value.text, MAX_SNIPPET_BYTES)
            symbol = value.symbol
            if symbol is not None and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
                raise BackendBoundaryError(
                    "source index returned an invalid symbol")
            result.append(SourceMatch(path=path, line=value.line,
                                      text=snippet, symbol=symbol))
            truncated |= cut
        return SourceMatches(matches=tuple(result), truncated=truncated)

    def _search(self, args: SearchSourceArgs) -> SourceMatches:
        values = self._source.search(self._commit, args.query,
                                     _roots(args.path_prefix),
                                     args.max_results + 1)
        return self._matches(values, args.max_results)

    def _callers(self, args: SymbolLookupArgs) -> SourceMatches:
        values = self._source.callers(self._commit, args.symbol,
                                      _roots(args.path_prefix),
                                      args.max_results + 1)
        return self._matches(values, args.max_results)

    def _callees(self, args: CalleeLookupArgs) -> SourceMatches:
        path = _source_path(args.path)
        try:
            values = self._source.callees(self._commit, path, args.symbol,
                                          args.max_results + 1)
        except FileNotFoundError:
            raise SourceNotFound(
                f"{path} does not exist at the pinned commit") from None
        return self._matches(values, args.max_results)

    def _lookup_hcap(self, args: HcapLookupArgs) -> HcapLookup:
        catalog = self._hcap.load_catalog(self._hcap_revision)
        capabilities = [
            cap for cap in catalog.capabilities
            if args.capability_id is None or cap.id == args.capability_id]
        selected = capabilities[:args.max_results]
        truncated = len(capabilities) > args.max_results
        views = []
        for cap in selected:
            name, cut_name = _bounded(cap.name, MAX_HCAP_TEXT_BYTES)
            purpose, cut_purpose = _bounded(cap.purpose,
                                            MAX_HCAP_TEXT_BYTES)
            fields = {}
            cut_fields = False
            for name_, values in (
                    ("scope", cap.scope),
                    ("validated_scope", cap.validated_scope),
                    ("syz_calls", cap.interface.syz_calls),
                    ("host_tooling", cap.interface.host_tooling),
                    ("runtime_features", cap.interface.runtime_features),
                    ("constraints", cap.constraints),
                    ("source_refs", cap.source_refs)):
                fields[name_], cut = _bounded_items(values)
                cut_fields |= cut
            authority_refs, cut_auth = _bounded_items(tuple(
                f"{ref.kind}:{ref.artifact_ref}" for ref in cap.authority_refs))
            views.append(HcapCapability(
                capability_id=cap.id, name=name, purpose=purpose,
                usable_stage=tuple(cap.usable_stage),
                usable_by=tuple(cap.usable_by), status=cap.status,
                authority_refs=authority_refs, **fields))
            truncated |= cut_name or cut_purpose or cut_fields or cut_auth
        missing, cut_missing = _bounded_items(catalog.missing_capability_ids)
        authority_refs, cut_catalog_auth = _bounded_items(tuple(
            f"{ref.kind}:{ref.artifact_ref}" for ref in catalog.authority_refs))
        return HcapLookup(
            hcap_revision=self._hcap_revision, capabilities=tuple(views),
            missing_capability_ids=missing,
            authority_refs=authority_refs,
            truncated=truncated or cut_missing or cut_catalog_auth)

    def _lookup_semantic_scope(self) -> SemanticScopeLookup:
        promoted = self._hcap.load_semantic_scope(self._hcap_revision)
        if promoted is None:
            return SemanticScopeLookup(
                hcap_revision=self._hcap_revision, proxy_sha256=None,
                registry_digest=None, registry_constraints=(), subsets=(),
                truncated=False)
        selected = promoted.subsets[:MAX_HCAP_RESULTS]
        truncated = len(promoted.subsets) > len(selected)
        views = []
        for entry in selected:
            subset = entry.subset
            fields = {}
            for name in ("schema_ids", "directions", "message_types",
                         "target_kinds", "parts", "mutation_kinds",
                         "transforms", "structure_policies", "value_sources",
                         "predicate_ops"):
                fields[name], cut = _bounded_items(getattr(subset, name))
                truncated |= cut
            description, cut = _bounded(subset.description,
                                        MAX_HCAP_TEXT_BYTES)
            truncated |= cut
            views.append(SemanticScopeSubset(
                subset_id=subset.subset_id, description=description,
                validation_items=tuple(i.value
                                       for i in entry.validation_items),
                **fields))
        constraints, cut = _bounded_items(promoted.registry.constraints)
        return SemanticScopeLookup(
            hcap_revision=self._hcap_revision,
            proxy_sha256=promoted.proxy_sha256,
            registry_digest=promoted.registry_digest,
            registry_constraints=constraints, subsets=tuple(views),
            truncated=truncated or cut)

    def _lookup_semantic_paths(self, args: SemanticPathLookupArgs
                               ) -> SemanticPathLookup:
        promoted = self._hcap.load_semantic_scope(self._hcap_revision)
        if promoted is None:
            raise ToolBoundaryError(
                "the pinned HCAP promotes no semantic ProtocolSchema")
        allowed = {schema_id for entry in promoted.subsets
                   for schema_id in entry.subset.schema_ids}
        if args.schema_id not in allowed:
            raise ToolBoundaryError(
                "schema_id is outside the pinned HCAP's promoted subsets")
        try:
            schema = load_schemas()[args.schema_id]
        except KeyError:
            raise BackendBoundaryError(
                "a promoted ProtocolSchema is absent from the pinned source") \
                from None
        response = args.message_type == "reply"
        values: tuple[tuple[str, Node], ...]
        traversal_cut = False
        exact = None
        if args.query is not None:
            resolution, node = schema.resolve(response, args.query)
            if (resolution is Resolution.FOUND and node is not None
                    and node.root == args.operation):
                exact = (args.query, node)
        if exact is not None:
            # An exact canonical path is complete independently of a bounded
            # traversal of recursive siblings elsewhere in the operation.
            values = (exact,)
        else:
            values, traversal_cut = _schema_paths(
                schema, response=response, operation=args.operation)
        if not values:
            raise ToolBoundaryError(
                "operation or procedure is absent from the schema")
        if args.query is not None and exact is None:
            query = args.query.casefold()
            values = tuple((path, node) for path, node in values
                           if query in path.casefold())
        selected = values[:args.max_results]
        truncated = traversal_cut or len(values) > len(selected)
        paths = []
        for path, node in selected:
            enum_literals = ()
            enum_literals_truncated = False
            if schema.kind(node.type) == "enum":
                enum_literals, enum_literals_truncated = _bounded_items(tuple(
                    label for label, unused in schema.types[node.type]["values"]
                ))
            paths.append(SemanticPath(
                path=path, value_kind=schema.kind(node.type),
                type_name=schema.type_name(node.type),
                flags=tuple(name for flag, name in _PATH_FLAGS
                            if node.flags & flag),
                enum_literals=enum_literals,
                enum_literals_truncated=enum_literals_truncated))
        return SemanticPathLookup(
            schema_id=schema.schema_id, family=schema.family,
            rpc_program=schema.program, rpc_version=schema.version,
            minor_version=schema.minor, message_type=args.message_type,
            operation=args.operation, paths=tuple(paths),
            truncated=truncated)
