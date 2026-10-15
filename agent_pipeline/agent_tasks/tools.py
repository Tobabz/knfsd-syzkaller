"""The complete read-only tool surface exposed to Stage 1 agents.

Every toolbox is bound by trusted host code to one kernel commit and one
HCAP revision.  Neither value is a model argument.  Source paths are
relative POSIX paths confined to ``SOURCE_PREFIXES``; traversal, absolute
paths, other kernel subsystems and backend results outside that boundary are
rejected.  Result counts, snippets and source excerpts are bounded before
they cross the runtime boundary.

There is deliberately no generic filesystem, shell, process, write,
artifact-by-path or network tool here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol, Sequence

from pydantic import Field

from ..contracts import Record
from ..hcap import ArtifactHcapChecker, HcapCatalog

SOURCE_PREFIXES = (
    "fs/nfsd/",
    "fs/nfs/",
    "fs/nfs_common/",
    "fs/lockd/",
    "net/sunrpc/",
    "include/linux/nfs",
    "include/linux/sunrpc/",
    "include/linux/lockd/",
    "include/uapi/linux/nfs",
    "include/trace/events/sunrpc.h",
)
MAX_SOURCE_LINES = 400
MAX_SOURCE_BYTES = 32 * 1024
MAX_MATCHES = 32
MAX_SNIPPET_BYTES = 512
MAX_HCAP_RESULTS = 8
MAX_HCAP_LIST_ITEMS = 32
MAX_HCAP_TEXT_BYTES = 1024


class ToolBoundaryError(ValueError):
    """A tool call attempted to cross its pinned read-only boundary."""


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


class ArtifactHcapSource:
    """HCAP lookup over the already pinned artifact-backed checker."""

    def __init__(self, checker: ArtifactHcapChecker) -> None:
        self.checker = checker

    def load_catalog(self, revision: str) -> HcapCatalog:
        return self.checker.load_catalog(revision)


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


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    arguments: type[ToolArgs]


TOOL_DEFINITIONS = (
    ToolDefinition(
        "read_kernel_source",
        "Read bounded lines from the pinned kernel source tree.",
        ReadSourceArgs),
    ToolDefinition(
        "search_kernel_source",
        "Literal bounded search in the allowed NFS, lockd and SUNRPC roots.",
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
)


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
    if not any(normalized.startswith(prefix) for prefix in SOURCE_PREFIXES):
        raise ToolBoundaryError("source path is outside the Stage 1 roots")
    return normalized


def _roots(path_prefix: str | None) -> tuple[str, ...]:
    if path_prefix is None:
        return SOURCE_PREFIXES
    return (_source_path(path_prefix),)


class Stage1Toolbox:
    """Pinned dispatcher containing exactly five read-only tools."""

    def __init__(self, source: KernelSourceIndex, hcap: HcapSource, *,
                 kernel_commit: str, hcap_revision: str) -> None:
        self._source = source
        self._hcap = hcap
        self._commit = kernel_commit
        self._hcap_revision = hcap_revision
        self._definitions = {item.name: item for item in TOOL_DEFINITIONS}

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return TOOL_DEFINITIONS

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(item.name for item in TOOL_DEFINITIONS)

    def invoke(self, name: str, arguments: dict) -> Record:
        definition = self._definitions.get(name)
        if definition is None:
            raise ToolBoundaryError(f"tool is not registered: {name}")
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
        raise AssertionError("unhandled Stage 1 tool arguments")

    def _read(self, args: ReadSourceArgs) -> SourceExcerpt:
        path = _source_path(args.path)
        if args.end_line < args.start_line:
            raise ToolBoundaryError("end_line is before start_line")
        if args.end_line - args.start_line + 1 > MAX_SOURCE_LINES:
            raise ToolBoundaryError(
                f"source reads are limited to {MAX_SOURCE_LINES} lines")
        text = self._source.read(
            self._commit, path, args.start_line, args.end_line,
            MAX_SOURCE_BYTES)
        if text is None:
            raise FileNotFoundError(path)
        truncated = isinstance(text, IndexedSource) and text.truncated
        text, cut = _bounded(text, MAX_SOURCE_BYTES)
        return SourceExcerpt(path=path, start_line=args.start_line,
                             end_line=args.start_line + len(text.splitlines()) - 1,
                             text=text, truncated=truncated or cut)

    def _matches(self, values: Sequence[IndexedMatch], requested: int
                 ) -> SourceMatches:
        limited = values[:requested]
        result = []
        truncated = len(values) > requested
        for value in limited:
            path = _source_path(value.path)
            if type(value.line) is not int or value.line < 1:
                raise ToolBoundaryError("source index returned an invalid line")
            snippet, cut = _bounded(value.text, MAX_SNIPPET_BYTES)
            symbol = value.symbol
            if symbol is not None and re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None:
                raise ToolBoundaryError(
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
        values = self._source.callees(self._commit, path, args.symbol,
                                      args.max_results + 1)
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
