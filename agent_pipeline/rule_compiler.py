"""Mutation Rule Compiler: MutationRuleSet -> CompiledMutationRule[] (08 §12).

The Compiler is the deterministic component between the Mutation Strategy
Agent and the Proxy.  It reads a stored ``MutationRuleSet``, binds it to the
Stage 1 harness and to the semantic capability the pinned HCAP revision
promoted, and lowers it to one NFSPRUL1 rule set (03-nfs-proxy/04 §35).  It
infers nothing from prose and computes no live offset, original bytes,
runtime XID or ordinal (08 §12).

Order of work for one rule set:

1. The promoted registry of ``binding.hcap_revision`` (M7, 04 §4).  With
   none, nothing semantic is supported: ``unsupported_capability`` with the
   ``semantic_mutation.unpromoted`` gap id.
2. The runtime: the Proxy binary the Compiler was given must be the
   promoted build, exactly (04 §7.1).  Anything else is not this
   capability; that and every other host-side fault raises
   ``CompilerUnavailable`` instead of answering for the Agent.
3. Binding, per intent: the traffic route must be one the Stage 1 harness
   opens (``syz_open_nfs_lane_profile$<client>_<backend>_v<N>``), and the
   ProtocolSchema is the one of the harness's NFS version.  Enum names
   become the wire word of the enum their value is compared with or
   written to, and context dependencies are derived as §35 says.
4. Validation, per intent: the lowered rule alone through the runtime's own
   loader (``nfs-proxy --check-rules``), which repeats every §19 check.
   Its refusal becomes the 08 §12 reason.  The first Agent-fixable
   refusal, in intent order, is the answer; otherwise the first refusal a
   runtime cannot apply.
5. Scope: the whole set must fit one promoted subset (``rule_set_scope``).
   A runtime advertising a feature is not enough (issue #14).
6. The whole set through the loader once more, then stored.

One intent lowers to one rule today: the vocabulary has no OR to split into
alternatives.  Its ``rule_id`` is ``r<NNN>`` by intent order, so rule ids
ascend as NFSPRUL1 requires and the parent ``intent_id`` is the link to the
Agent's intent (04 §2).  ``requires_state_lineage`` cannot arise: no
``ValueRef`` source reads an earlier transaction (08 §15).
"""

from __future__ import annotations

import hashlib
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer

from .agent_tasks.mutation import (BuiltinTransform, CopyTransform,
                                   EnumLiteral, LiteralTransform,
                                   MutationIntent, MutationRuleSet,
                                   OperationValue, ValueRef)
from .artifacts import ArtifactStore
from .contracts import (CompileRejected, CompiledRuleSet, HarnessBinding,
                        Record, Sha256)
from .data import load_record, put_record
from .hcap import ArtifactHcapChecker
from .materializer import ReachabilityHarness
from .protocol_schema import (SCHEMA_ROOT, SN_OPERATION, Node,
                              ProtocolSchema, Resolution, load_schemas)
from .semantic_promotion import (DEFAULT_CAPABILITY_ID, UNPROMOTED_GAP_ID,
                                 BuildRegistry,
                                 PromotedSemanticCapabilityRegistry,
                                 StagedProxies, check_runtime,
                                 promoted_registry, read_build_registry,
                                 rule_set_scope)

Visible = Annotated[str, Field(min_length=1, max_length=512,
                               pattern=r"^[\x21-\x7e]+$")]

#: Canonical traffic scope names (03-nfs-proxy/01 §9) and their NFSPRUL1
#: words: the Proxy's backend listeners and client source addresses, in the
#: order ``nfs-proxy`` takes them on its command line.
BACKENDS = {"knfsd": 0, "ganesha": 1}
CLIENTS = {"client0": 0, "client1": 1}
#: A lane-profile pseudo-syscall the Stage 1 harness enables names a route.
_LANE_PROFILE = re.compile(
    r"^syz_open_nfs_lane_profile\$(client[0-9]+)_([a-z]+)_v([0-9]+)$")
#: The harness's NFS version as (family, minor).
_NFS_VERSION = {"3": ("nfs3", None), "4.0": ("nfs4", 0), "4.1": ("nfs4", 1),
                "4.2": ("nfs4", 2)}

MAX_REQUEST_FIELDS = 16                 # per view (rule.h)
SEMANTIC_RUNTIME_VERSION = 1            # the NFSPRUL1 format written here

#: ``nfs-proxy --check-rules`` refusals and the 08 §12 reason each is.  An
#: ambiguous path names no single node; a missing part, and a kind /
#: transform / policy that do not fit the target, are the target's type
#: refusing the edit.
_RUNTIME_REASON = {
    "selector_mismatch": "selector_mismatch",
    "message_type_inconsistent": "message_type_inconsistent",
    "unknown_path": "unknown_path",
    "ambiguous_path": "unknown_path",
    "part_unavailable": "type_mismatch",
    "type_mismatch": "type_mismatch",
    "mutation_invalid": "type_mismatch",
    "unsupported_capability": "unsupported_capability",
}
_GAP = "unsupported_capability"


class CompilerUnavailable(RuntimeError):
    """The Compiler cannot answer under this binding: the Proxy is not the
    promoted build, a schema is missing, or the runtime refused what the
    Compiler wrote.  No rule-set change can fix it."""


# ---------------------------------------------------------------- the artifact


class CompiledRule(Record):
    rule_id: Visible
    intent_id: Visible


class CompiledMutationRuleSet(Record):
    """The CompiledMutationRule[] artifact ``CompiledRuleSet.compiled_ref``
    names.  ``nfsprul1_ref`` is the stored NFSPRUL1 bytes; its digest is the
    ``rule_set_id`` the Proxy reports and RULESET records (04 §35)."""

    schema_version: Literal["compiled-mutation-rule-set.v1"] = \
        "compiled-mutation-rule-set.v1"
    rule_set_ref: Sha256
    harness_ref: Sha256
    hcap_revision: str
    promoted_registry_ref: Sha256
    #: The promoted subset the set fits; None when it fits none and the
    #: host allowed that (``allow_unpromoted``), with the reasons in
    #: ``unpromoted_problems``. Both are left out of the encoding when the
    #: set fits a subset, so earlier records keep their bytes.
    subset_id: Visible | None = None
    unpromoted_problems: tuple[Annotated[str, Field(min_length=1,
                                                    max_length=512)],
                               ...] = Field(default=(), max_length=16)
    proxy_sha256: Sha256
    registry_digest: Sha256
    schema_id: Visible
    semantic_runtime_version: int
    candidate_id: Visible
    rules: tuple[CompiledRule, ...] = Field(min_length=1, max_length=256)
    nfsprul1_ref: Sha256

    @model_serializer(mode="wrap")
    def _omit_unpromoted(self, handler):
        data = handler(self)
        if data.get("subset_id") is None:
            data.pop("subset_id", None)
        if not data.get("unpromoted_problems"):
            data.pop("unpromoted_problems", None)
        return data


# ---------------------------------------------------------------- NFSPRUL1


def _u32(v: int) -> bytes:
    return struct.pack(">I", v)


def _opaque(b: bytes) -> bytes:
    return _u32(len(b)) + b + b"\0" * (-len(b) % 4)


def _text(s: str) -> bytes:
    return _opaque(s.encode("utf-8"))


def _optional_u32(v: int | None) -> bytes:
    return _u32(0) if v is None else _u32(1) + _u32(v)


_DIRECTION = {"C2S": 0, "S2C": 1}
_MESSAGE_TYPE = {"call": 0, "reply": 1}
_TARGET_KIND = {"field": 0, "operation_array": 1}
_PART = {"value": 0, "encoded": 1, "metadata:length": 2, "metadata:count": 3,
         "metadata:discriminant": 4, "metadata:padding": 5}
_SOURCE = {"target": 0, "current_message": 1, "request_forwarded": 2,
           "request_original": 3}
_COMPARE = {"eq": 0, "ne": 1, "lt": 2, "le": 3, "gt": 4, "ge": 5}
_KIND = {"replace": 0, "insert": 1, "delete": 2, "op_append": 3,
         "op_prepend": 4}
_POLICY = {"preserve": 0, "raw": 1}


def _literal(lit, enum_word: int | None) -> bytes:
    """typed_literal; an enum is written as the word it was bound to."""
    k = lit.kind
    if k == "int":
        return _u32(0) + struct.pack(">i", lit.value)
    if k == "uint":
        return _u32(1) + _u32(lit.value)
    if k == "hyper":
        return _u32(2) + struct.pack(">q", lit.value)
    if k == "uhyper":
        return _u32(3) + struct.pack(">Q", lit.value)
    if k == "bool":
        return _u32(4) + _u32(int(lit.value))
    if k == "enum":
        assert enum_word is not None
        return _u32(5) + _u32(enum_word)
    if k == "opaque":
        return _u32(6) + _opaque(bytes.fromhex(lit.hex))
    if k == "string":
        return _u32(7) + _opaque(lit.value.encode("utf-8"))
    raise AssertionError(k)


def _value_ref(ref: ValueRef) -> bytes:
    return _u32(_SOURCE[ref.source]) + _text(ref.path or "")


@dataclass
class _Deps:
    rpc_procedure: bool = False
    opseq: bool = False
    fields: set[str] | None = None

    def encode(self) -> bytes:
        fields = sorted(self.fields or (), key=lambda f: f.encode())
        return (_u32(int(self.rpc_procedure)) + _u32(int(self.opseq))
                + _u32(len(fields)) + b"".join(_text(f) for f in fields))


@dataclass
class _Lowered:
    """One intent bound for one schema and route, ready to encode."""

    rule_id: str
    intent: MutationIntent
    backend: int
    client: int
    predicates: list[int | None]           # enum word of each rhs literal
    transform_word: int | None             # enum word of a literal transform
    forwarded: _Deps
    original: _Deps

    def encode(self) -> bytes:
        i = self.intent
        sel, mut = i.selector, i.mutation
        out = [_text(self.rule_id), _text(i.intent_id),
               _u32(_DIRECTION[i.traffic_scope.direction]),
               _u32(self.backend), _u32(self.client),
               _u32(_MESSAGE_TYPE[sel.rpc.message_type]),
               _u32(sel.rpc.program), _u32(sel.rpc.version),
               _optional_u32(sel.rpc.procedure),
               _text(sel.protocol.family),
               _optional_u32(sel.protocol.nfs_version),
               _optional_u32(sel.protocol.minor_version)]
        out.append(_u32(0) if sel.operation is None
                   else _u32(1) + _text(sel.operation))
        out += [_u32(_TARGET_KIND[sel.target.kind]), _text(sel.target.path),
                _u32(_PART[sel.target.part]), _u32(len(sel.predicates))]
        for p, word in zip(sel.predicates, self.predicates):
            out += [_value_ref(p.lhs), _u32(_COMPARE[p.op])]
            if isinstance(p.rhs, ValueRef):
                out += [_u32(1), _value_ref(p.rhs)]
            else:
                out += [_u32(0), _literal(p.rhs, word)]
        out.append(_u32(_KIND[mut.kind]))
        t = mut.transform
        if t is None or isinstance(t, OperationValue):
            # NFSPRUL1 v1 has no typed operation value (04 §35).
            out.append(_u32(0))
        elif isinstance(t, LiteralTransform):
            out += [_u32(1), _u32(0), _literal(t.value, self.transform_word)]
        elif isinstance(t, CopyTransform):
            out += [_u32(1), _u32(1), _value_ref(t.source)]
        else:
            out += [_u32(1), _u32(2), _text(t.transform_id),
                    _u32(len(t.args)),
                    *(_literal(a, None) for a in t.args)]
        out += [_u32(_POLICY[mut.structure_policy]), self.forwarded.encode(),
                self.original.encode(), _u32(0)]           # all_matches
        return b"".join(out)


def encode_rule_set(schema_id: str, candidate_id: str,
                    rules: list[_Lowered]) -> bytes:
    return (b"NFSPRUL1" + _u32(SEMANTIC_RUNTIME_VERSION) + _text(schema_id)
            + _text(candidate_id) + _u32(len(rules))
            + b"".join(r.encode() for r in rules))


# ---------------------------------------------------------------- the runtime check


_OK = re.compile(r"rules ok rule_set_id=([0-9a-f]{64}) "
                 r"semantic_runtime_version=(\d+) schema_id=(\S+) rules=(\d+)")
_REFUSED = re.compile(r"rules refused rule_set_id=([0-9a-f]{64}) "
                      r"status=([a-z_]+)(?: rule=(\d+))?(?: predicate=(\d+))?")


@dataclass(frozen=True)
class _Check:
    status: str                 # "ok" or the runtime's refusal
    predicate: int | None = None


def _check(proxy: Path, workdir: Path, blob: bytes,
           launcher: tuple[str, ...] = ()) -> _Check:
    """``nfs-proxy --check-rules``: the loader ``--target`` runs.
    ``launcher`` prefixes a staged Proxy, which reads the file as another
    user."""
    digest = hashlib.sha256(blob).hexdigest()
    with tempfile.TemporaryDirectory(dir=workdir) as tmp:
        path = Path(tmp) / "rules.bin"
        path.write_bytes(blob)
        if launcher:
            Path(tmp).chmod(0o755)
            path.chmod(0o644)
        run = subprocess.run([*launcher, str(proxy), "--check-rules",
                              str(path)],
                             capture_output=True, text=True, timeout=60)
    line = run.stdout.strip()
    ok = _OK.fullmatch(line)
    if run.returncode == 0 and ok and ok.group(1) == digest:
        return _Check("ok")
    refused = _REFUSED.fullmatch(line)
    if run.returncode == 3 and refused and refused.group(1) == digest:
        pred = refused.group(4)
        return _Check(refused.group(2), None if pred is None else int(pred))
    raise CompilerUnavailable(
        f"--check-rules answered {run.returncode}: "
        f"{(line or run.stderr.strip())[:200]}")


# ---------------------------------------------------------------- binding


class _Refusal(Exception):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def harness_routes(harness: ReachabilityHarness) -> set[tuple[str, str]]:
    """The (client, backend) routes the Stage 1 harness opens."""
    routes = set()
    for name in harness.runtime_selection.enabled_interfaces:
        m = _LANE_PROFILE.match(name)
        if m:
            routes.add((m.group(1), m.group(2)))
    return routes


def _schema_for(harness: ReachabilityHarness, schemas: dict[str, ProtocolSchema],
                promoted: PromotedSemanticCapabilityRegistry) -> ProtocolSchema:
    """The ProtocolSchema of the harness's NFS version on the promoted
    build.  Not finding it is a host fault: the build or the schema source
    is not the one the HCAP names."""
    family, minor = _NFS_VERSION[harness.runtime_selection.nfs_version]
    ids = [s.schema_id for s in promoted.registry.schemas
           if s.family == family and s.minor_version == minor]
    if len(ids) != 1:
        raise CompilerUnavailable(
            f"the promoted build has no single {family} minor {minor} schema")
    if ids[0] not in schemas:
        raise CompilerUnavailable(
            f"schema {ids[0]} is not in the ProtocolSchema source")
    return schemas[ids[0]]


def _resolve(s: ProtocolSchema, reply: bool, ref_path: str, *,
             request_view: bool = False) -> Node:
    """``resolve`` / ``resolve_ref`` of ``src/rule.c``, with its refusals."""
    if request_view:
        if not reply:
            raise _Refusal("message_type_inconsistent",
                           "a request view in a call rule")
        if s.in_message(ref_path, True):
            raise _Refusal("message_type_inconsistent",
                           f"{ref_path}: a response path in a request view")
        response = False
    else:
        response = reply
        if s.in_message(ref_path, not response):
            raise _Refusal("message_type_inconsistent",
                           f"{ref_path}: a "
                           f"{'request' if response else 'response'} path in "
                           f"a {'reply' if reply else 'call'} rule")
    found, node = s.resolve(response, ref_path)
    if found is Resolution.AMBIGUOUS:
        raise _Refusal("unknown_path",
                       f"{ref_path} names more than one schema node")
    if found is Resolution.NOT_FOUND:
        raise _Refusal("unknown_path", f"{ref_path} names no schema node")
    return node


def _enum_word(s: ProtocolSchema, node: Node, lit: EnumLiteral,
               where: str) -> int:
    word = s.enum_value(node.type, lit.name)
    if word is None:
        raise _Refusal("type_mismatch",
                       f"{where}: {lit.name} is not a value of "
                       f"{s.type_name(node.type)}")
    return word


def _bind(s: ProtocolSchema, harness_routes_: set[tuple[str, str]],
          intent: MutationIntent, rule_id: str) -> _Lowered:
    scope, sel, mut = intent.traffic_scope, intent.selector, intent.mutation
    if scope.backend not in BACKENDS or scope.client not in CLIENTS:
        raise _Refusal("selector_mismatch",
                       f"traffic scope {scope.client}/{scope.backend}: the "
                       f"backends are {sorted(BACKENDS)} and the clients "
                       f"{sorted(CLIENTS)}")
    if (scope.client, scope.backend) not in harness_routes_:
        raise _Refusal("selector_mismatch",
                       f"traffic scope {scope.client}/{scope.backend} is not a "
                       "route the Stage 1 harness opens: "
                       f"{sorted(f'{c}/{b}' for c, b in harness_routes_)}")
    minor = sel.protocol.minor_version
    if sel.protocol.family != s.family or (minor is not None
                                           and minor != s.minor):
        raise _Refusal("selector_mismatch",
                       f"the Stage 1 harness runs {s.schema_id.split('/')[0]}")

    reply = sel.rpc.message_type == "reply"
    target = _resolve(s, reply, sel.target.path)
    forwarded, original = _Deps(fields=set()), _Deps(fields=set())

    def read(ref: ValueRef) -> Node:
        if ref.source == "target":
            return target
        node = _resolve(s, reply, ref.path, request_view=ref.source in (
            "request_forwarded", "request_original"))
        # §35: the request fields of each view, and the operation sequence
        # when a request field of an operation binds to a target in one.
        bind = bool(node.flags & SN_OPERATION and target.flags & SN_OPERATION)
        if ref.source == "request_forwarded":
            forwarded.fields.add(ref.path)
            forwarded.opseq |= bind
        elif ref.source == "request_original":
            original.fields.add(ref.path)
            original.opseq |= bind
            forwarded.opseq |= bind
        return node

    words: list[int | None] = []
    for n, p in enumerate(sel.predicates):
        lhs = read(p.lhs)
        if isinstance(p.rhs, ValueRef):
            read(p.rhs)
            words.append(None)
        elif isinstance(p.rhs, EnumLiteral):
            words.append(_enum_word(s, lhs, p.rhs, f"predicate {n}"))
        else:
            words.append(None)
    transform_word = None
    t = mut.transform
    if isinstance(t, CopyTransform):
        read(t.source)
    elif isinstance(t, LiteralTransform) and isinstance(t.value, EnumLiteral):
        if sel.target.part != "value":
            raise _Refusal("type_mismatch",
                           "a metadata word is written as unsigned int")
        transform_word = _enum_word(s, target, t.value, "literal transform")
    elif isinstance(t, BuiltinTransform) and any(
            isinstance(a, EnumLiteral) for a in t.args):
        # No builtin is registered, so no argument type binds an enum name.
        raise _Refusal(_GAP, "no builtin transform is registered")
    forwarded.rpc_procedure = reply and sel.rpc.procedure is not None
    if max(len(forwarded.fields), len(original.fields)) > MAX_REQUEST_FIELDS:
        raise _Refusal(_GAP, f"more than {MAX_REQUEST_FIELDS} request fields "
                       "in one view")
    return _Lowered(rule_id=rule_id, intent=intent,
                    backend=BACKENDS[scope.backend],
                    client=CLIENTS[scope.client], predicates=words,
                    transform_word=transform_word, forwarded=forwarded,
                    original=original)


# ---------------------------------------------------------------- the Compiler


class ArtifactMutationRuleCompiler:
    """``components.MutationRuleCompiler`` over the artifact store, the
    promoted Proxy build and the pinned ProtocolSchema source.

    A staged revision (a subset pinned with crash survival pending,
    03-nfs-proxy/06 §30) may pin another build than the configured Proxy:
    its staged host Proxy (``staged``) compiles for it, under the
    launcher.  A shared revision uses the configured Proxy only."""

    def __init__(self, store: ArtifactStore, proxy: Path, workdir: Path, *,
                 schema_root: Path = SCHEMA_ROOT,
                 staged: StagedProxies | None = None,
                 allow_unpromoted: bool = False) -> None:
        self.allow_unpromoted = allow_unpromoted
        self.store = store
        self.proxy = Path(proxy)
        self.workdir = Path(workdir)
        self.schema_root = Path(schema_root)
        self.staged = staged

    def _runtime(self, promoted) -> tuple[Path, tuple[str, ...],
                                          BuildRegistry]:
        build = read_build_registry(self.proxy)
        if check_runtime(promoted, build) or not promoted.pending or \
                self.staged is None:
            return self.proxy, (), build
        found = self.staged.find(promoted.proxy_sha256)
        if found is None:
            return self.proxy, (), build
        launcher = self.staged.launcher
        return found, launcher, read_build_registry(found, launcher=launcher)

    def compile(self, rule_set_ref: str, harness_ref: str,
                binding: HarnessBinding) -> CompiledRuleSet | CompileRejected:
        rule_set = load_record(self.store, rule_set_ref, MutationRuleSet)
        harness = load_record(self.store, harness_ref, ReachabilityHarness)
        if harness.candidate_id != rule_set.candidate_id:
            raise CompilerUnavailable("the rule set is for another candidate "
                                      "than the harness")
        catalog = ArtifactHcapChecker(self.store).load_catalog(
            binding.hcap_revision)
        promoted = promoted_registry(self.store, catalog)
        if promoted is None:
            return CompileRejected(
                reason=_GAP, missing_capability_id=UNPROMOTED_GAP_ID,
                detail="no semantic subset is promoted in this HCAP revision")
        proxy, launcher, build = self._runtime(promoted)
        if not check_runtime(promoted, build):
            raise CompilerUnavailable(
                f"the Proxy {build.proxy_sha256[:12]} is not the promoted "
                f"build {promoted.proxy_sha256[:12]}")
        if build.registry.semantic_runtime_version != SEMANTIC_RUNTIME_VERSION:
            raise CompilerUnavailable("the runtime reads another NFSPRUL1 "
                                      "version")
        schema = _schema_for(harness, load_schemas(self.schema_root), promoted)
        routes = harness_routes(harness)
        self.workdir.mkdir(parents=True, exist_ok=True)

        lowered: list[_Lowered] = []
        fixable: CompileRejected | None = None
        gap: CompileRejected | None = None
        for n, intent in enumerate(rule_set.intents):
            try:
                rule = _bind(schema, routes, intent, f"r{n:03d}")
                checked = _check(proxy, self.workdir, encode_rule_set(
                    schema.schema_id, rule_set.candidate_id, [rule]),
                    launcher)
                if checked.status != "ok":
                    reason = _RUNTIME_REASON.get(checked.status)
                    if reason is None:
                        raise CompilerUnavailable(
                            f"the runtime refused intent {intent.intent_id} "
                            f"as {checked.status}")
                    where = ("" if checked.predicate is None
                             else f" at predicate {checked.predicate}")
                    raise _Refusal(reason, f"the runtime refused it as "
                                   f"{checked.status}{where}")
            except _Refusal as r:
                refusal = CompileRejected(
                    reason=r.reason, intent_id=intent.intent_id,
                    detail=r.detail[:1024],
                    missing_capability_id=(UNPROMOTED_GAP_ID
                                           if r.reason == _GAP else None))
                if r.reason == _GAP:
                    gap = gap or refusal
                else:
                    fixable = refusal
                    break
                continue
            lowered.append(rule)
        if fixable is not None:
            return fixable
        if gap is not None:
            return gap

        scope = rule_set_scope(rule_set, promoted)
        subset = next((p.subset for p in promoted.subsets
                       if p.subset.subset_id == scope.subset_id), None)
        if subset is None or schema.schema_id not in subset.schema_ids:
            problems = scope.problems or (
                f"{schema.schema_id} is outside the subset",)
            if not self.allow_unpromoted:
                return CompileRejected(
                    reason=_GAP, missing_capability_id=UNPROMOTED_GAP_ID,
                    detail="; ".join(problems)[:1024])
            # Outside every promoted subset: the Proxy loader accepted each
            # rule, and the record says nothing validated the set as a whole.
            subset = None
            outside = tuple(x[:512] for x in problems[:16])
        else:
            outside = ()

        blob = encode_rule_set(schema.schema_id, rule_set.candidate_id,
                               lowered)
        if _check(proxy, self.workdir, blob, launcher).status != "ok":
            raise CompilerUnavailable("the runtime refused the whole set its "
                                      "rules each passed")
        record = CompiledMutationRuleSet(
            rule_set_ref=rule_set_ref, harness_ref=harness_ref,
            hcap_revision=binding.hcap_revision,
            promoted_registry_ref=_promoted_ref(catalog),
            subset_id=None if subset is None else subset.subset_id,
            unpromoted_problems=outside, proxy_sha256=build.proxy_sha256,
            registry_digest=build.registry_digest, schema_id=schema.schema_id,
            semantic_runtime_version=SEMANTIC_RUNTIME_VERSION,
            candidate_id=rule_set.candidate_id,
            rules=tuple(CompiledRule(rule_id=r.rule_id,
                                     intent_id=r.intent.intent_id)
                        for r in lowered),
            nfsprul1_ref=self.store.put(blob))
        return CompiledRuleSet(rule_set_ref=rule_set_ref,
                               compiled_ref=put_record(self.store, record),
                               hcap_revision=binding.hcap_revision)


def _promoted_ref(catalog) -> str:
    """The registry ``promoted_registry`` read: the semantic entry's one
    PromotedSemanticCapabilityRegistry reference."""
    entry = next(c for c in catalog.capabilities
                 if c.id == DEFAULT_CAPABILITY_ID)
    return next(r.artifact_ref for r in entry.authority_refs
                if r.kind == "PromotedSemanticCapabilityRegistry")


def load_compiled(store: ArtifactStore, compiled: CompiledRuleSet
                  ) -> tuple[CompiledMutationRuleSet, bytes]:
    """The compiled artifact and its NFSPRUL1 bytes, for the Runner."""
    record = load_record(store, compiled.compiled_ref, CompiledMutationRuleSet)
    return record, store.get(record.nfsprul1_ref)


__all__ = ["ArtifactMutationRuleCompiler", "BACKENDS", "CLIENTS",
           "CompiledMutationRuleSet", "CompiledRule", "CompilerUnavailable",
           "encode_rule_set", "harness_routes", "load_compiled"]
