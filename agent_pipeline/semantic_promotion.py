"""M7: semantic capability registry and subset promotion (06 §21, §30; 04 §4).

The Proxy build says what it implements (``nfs-proxy --capability-registry``)
and how it reads a rule set (``nfs-proxy --describe-rules``).  Neither is
Agent capability.  A semantic subset becomes usable by ``agent_stage2`` only
through this gate:

- the subset lies inside the build's registry;
- guest validation runs cover every element of it.  A run counts when its
  ``ReplayResult`` re-evaluates from the sealed judge input to
  ``REPLAY_EQUIVALENT`` with no invalid evidence, its production side ended
  in a guest crash with the crash-cut position's MutationDelta present
  (semantic Delta crash survival), and every rule of its rule set is inside
  the subset.  A rule is exercised when a batch naming it completed
  forwarding in both production and replay at one window position;
- dynamic-original replay is covered only when an exercised rule replaced,
  at one position, original values in replay that production never had;
- the §30 validation items the subset's contents call for are covered.

The gate writes a ``PromotedSemanticCapabilityRegistry`` and the HCAP entry
that references it by digest.  A different build is promoted afresh.

The gate has two stages (§30).  ``pin`` is stage 1, the staged pin: the
same checks without crash survival, so a run need not end in a guest crash.
Its subset is marked ``crash_survival: pending`` and may only sit in a
staged ``hcap_revision``; the jobs bound to that revision use it.  Guests
are never crashed on purpose.  ``promote`` is stage 2.  It takes either

- the Proxy build's ``DeltaDurabilityCheck`` (``durability``, produced on
  the host without a guest crash by ``delta_durability.probe``): the
  mutation record is stored before the peer sees the bytes and every
  journal prefix after it still holds the exposure.  The subset is promoted
  with ``natural_crash_reproduction: not_observed``; or
- no such check, and runs that end in a crash a campaign with the subset
  met by itself, as before, which is ``natural_crash_reproduction:
  observed`` (so does a counted run that is such a crash alongside the
  check).

``not_observed`` is a stated limit, never a crash validation: what a real
kernel death does to data the guest Proxy still held is only shown by a
natural crash.  A run whose production ended in a crash without the
crash-cut MutationDelta cannot be reproduced by replay: either stage
refuses the subset over it and the CLI records an ``UnreproducibleCrash``.

Content addressing establishes byte integrity, not provenance.  That a run
came from a KVM guest with the real executor and knfsd is the operator's
statement when recording it, as for every other host-supplied record; host
tests and test doubles are never recorded as runs (06 §27, §30).
"""

from __future__ import annotations

import enum
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (ConfigDict, Field, field_validator, model_serializer,
                      model_validator)

from .artifacts import ArtifactStore
from .contracts import Record, Sha256
from .data import canonical_json, load_record, put_record
from .delta_durability import DeltaDurabilityCheck, ProbeError, probe
from .hcap import AuthorityRef, Capability, CapabilityInterface, HcapCatalog
from .semantic_replay import (JournalIntegrity, ReplayJudgeInput, ReplayResult,
                              ReplayVerdict, Termination, evaluate)

Text = Annotated[str, Field(min_length=1, max_length=1024, pattern=r"\S")]
Visible = Annotated[str, Field(min_length=1, max_length=512,
                               pattern=r"^[\x21-\x7e]+$")]
SubsetId = Annotated[str, Field(max_length=128,
                                pattern=r"^semantic\.[a-z0-9][a-z0-9_.-]*$")]
U32 = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]

Direction = Literal["C2S", "S2C"]
MessageType = Literal["call", "reply"]
TargetKind = Literal["field", "operation_array"]
Part = Literal["value", "encoded", "metadata:length", "metadata:count",
               "metadata:discriminant", "metadata:padding"]
MutationKind = Literal["replace", "insert", "delete", "op_append",
                       "op_prepend"]
TransformKind = Literal["literal", "copy", "builtin"]
Policy = Literal["preserve", "raw"]
Source = Literal["target", "current_message", "request_forwarded",
                 "request_original"]
CompareOp = Literal["eq", "ne", "lt", "le", "gt", "ge"]

#: Gap id for an intent no promoted subset covers (07 §3).
UNPROMOTED_GAP_ID = "semantic_mutation.unpromoted"
DEFAULT_CAPABILITY_ID = "HCAP-10"
MAX_SUBSETS = 64
MAX_RUNS = 64


class _Strict(Record):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _sorted_unique(values: tuple, name: str) -> tuple:
    if len(set(values)) != len(values):
        raise ValueError(f"duplicate {name}")
    return tuple(sorted(values))


# ---------------------------------------------------------------- build registry


class RegistrySchema(_Strict):
    schema_id: Visible
    family: Visible
    program: U32
    version: U32
    minor_version: U32 | None


class RegistryLimits(_Strict):
    literal_bytes: U32
    path_bytes: U32
    predicates_per_rule: U32
    rule_set_bytes: U32
    rules: U32


class CapabilityRegistry(_Strict):
    """What one Proxy build implements, as ``--capability-registry`` prints it."""

    schema_version: Literal["semantic-capability-registry.v1"]
    semantic_runtime_version: U32
    schemas: tuple[RegistrySchema, ...] = Field(min_length=1, max_length=64)
    directions: tuple[Direction, ...]
    message_types: tuple[MessageType, ...]
    target_kinds: tuple[TargetKind, ...]
    parts: tuple[Part, ...]
    mutation_kinds: tuple[MutationKind, ...]
    transforms: tuple[TransformKind, ...]
    structure_policies: tuple[Policy, ...]
    value_sources: tuple[Source, ...]
    predicate_ops: tuple[CompareOp, ...]
    constraints: tuple[Visible, ...]
    limits: RegistryLimits

    @model_validator(mode="after")
    def _canonical(self) -> CapabilityRegistry:
        ids = tuple(s.schema_id for s in self.schemas)
        if ids != _sorted_unique(ids, "schema_id"):
            raise ValueError("schemas must be in schema_id order")
        for name in (*DIMENSIONS[1:], "constraints"):
            values = getattr(self, name)
            if values != _sorted_unique(values, name):
                raise ValueError(f"{name} must be sorted")
        return self

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(s.schema_id for s in self.schemas)

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self)).hexdigest()


class BuildRegistry(_Strict):
    """A registry bound to the Proxy binary that printed it (04 §7.2)."""

    schema_version: Literal["semantic-build-registry.v1"] = \
        "semantic-build-registry.v1"
    proxy_sha256: Sha256
    registry_digest: Sha256
    registry: CapabilityRegistry

    @model_validator(mode="after")
    def _digest(self) -> BuildRegistry:
        if self.registry.digest != self.registry_digest:
            raise ValueError("registry_digest is not the registry's digest")
        return self


class RegistryError(ValueError):
    """The Proxy refused, or printed something that is not its contract."""


def read_build_registry(proxy: Path, *, launcher: tuple[str, ...] = ()
                        ) -> BuildRegistry:
    """``launcher`` prefixes the command: a Proxy a Harness Generation
    patch set built runs as the generation user (07 §5.1)."""
    run = subprocess.run([*launcher, str(proxy), "--capability-registry"],
                         capture_output=True, timeout=60)
    if run.returncode != 0:
        raise RegistryError(f"--capability-registry exited {run.returncode}: "
                            f"{run.stderr.decode(errors='replace')[:200]}")
    registry = CapabilityRegistry.model_validate_json(run.stdout)
    if canonical_json(registry) + b"\n" != run.stdout:
        raise RegistryError("--capability-registry output is not canonical")
    return BuildRegistry(proxy_sha256=hashlib.sha256(
        Path(proxy).read_bytes()).hexdigest(),
        registry_digest=registry.digest, registry=registry)


@dataclass(frozen=True)
class StagedProxies:
    """The host Proxies Harness Generation validation staged, each under
    ``<root>/<sha256>/nfs-proxy`` (``stage1/host/semantic.py``
    ``stage_proxy``).  A patch set built them: they run under
    ``launcher`` (07 §5.1).  A staged revision's pinned build is found
    here when the configured Proxy is not it (03-nfs-proxy/06 §30)."""

    root: Path
    launcher: tuple[str, ...] = ()

    def path(self, proxy_sha256: str) -> Path:
        return Path(self.root) / proxy_sha256 / "nfs-proxy"

    def find(self, proxy_sha256: str) -> Path | None:
        """The staged Proxy of this digest, when its bytes are it."""
        path = self.path(proxy_sha256)
        if not path.is_file() or path.is_symlink():
            return None
        if hashlib.sha256(path.read_bytes()).hexdigest() != proxy_sha256:
            return None
        return path


# ---------------------------------------------------------------- rule description


class RuleDescription(_Strict):
    """One rule of an accepted NFSPRUL1 set, in the registry's vocabulary."""

    rule_id: Visible
    intent_id: Visible
    direction: Direction
    message_type: MessageType
    program: U32
    version: U32
    procedure: U32 | None
    family: Visible
    nfs_version: U32 | None
    minor_version: U32 | None
    operation: Visible | None
    target_kind: TargetKind
    target_path: Visible
    target_discriminant: bool
    part: Part
    kind: MutationKind
    transform: TransformKind | None
    structure_policy: Policy
    value_sources: tuple[Source, ...]
    predicate_ops: tuple[CompareOp, ...]


class RuleSetDescription(_Strict):
    schema_version: Literal["semantic-rule-description.v1"]
    rule_set_id: Sha256
    schema_id: Visible
    semantic_runtime_version: U32
    candidate_id: Visible
    rules: tuple[RuleDescription, ...] = Field(min_length=1, max_length=256)


def describe_rule_set(proxy: Path, rule_set: bytes, workdir: Path, *,
                      launcher: tuple[str, ...] = ()) -> RuleSetDescription:
    path = Path(workdir) / "described-rules.bin"
    path.write_bytes(rule_set)
    run = subprocess.run([*launcher, str(proxy), "--describe-rules",
                          str(path)],
                         capture_output=True, timeout=60)
    if run.returncode != 0:
        raise RegistryError("the runtime refused the rule set: "
                            + run.stdout.decode(errors="replace").strip()[:200])
    described = RuleSetDescription.model_validate_json(run.stdout)
    if described.rule_set_id != hashlib.sha256(rule_set).hexdigest():
        raise RegistryError("the runtime described other bytes")
    return described


# ---------------------------------------------------------------- subsets


#: Subset dimensions; each but schema_ids is a registry field of that name.
DIMENSIONS = ("schema_ids", "directions", "message_types", "target_kinds",
              "parts", "mutation_kinds", "transforms", "structure_policies",
              "value_sources", "predicate_ops")


class SemanticSubset(_Strict):
    """A scope label and, per dimension, exactly what it lets a rule use.

    ``value_sources`` and ``predicate_ops`` are sets a rule's references and
    comparisons must stay within; the others hold one value per rule.  Empty
    ``value_sources`` and ``predicate_ops`` admit only rules that read no
    value and compare nothing.  Every
    element must be exercised by guest evidence before promotion.
    """

    subset_id: SubsetId
    description: Text
    schema_ids: tuple[Visible, ...] = Field(min_length=1, max_length=8)
    directions: tuple[Direction, ...] = Field(min_length=1)
    message_types: tuple[MessageType, ...] = Field(min_length=1)
    target_kinds: tuple[TargetKind, ...] = Field(min_length=1)
    parts: tuple[Part, ...] = Field(min_length=1)
    mutation_kinds: tuple[MutationKind, ...] = Field(min_length=1)
    transforms: tuple[TransformKind, ...] = Field(min_length=1)
    structure_policies: tuple[Policy, ...] = Field(min_length=1)
    value_sources: tuple[Source, ...] = ()
    predicate_ops: tuple[CompareOp, ...] = ()

    @field_validator(*DIMENSIONS)
    @classmethod
    def _set(cls, values: tuple, info) -> tuple:
        return _sorted_unique(values, info.field_name)


class ValidationItem(str, enum.Enum):
    """06 §30's guest/runtime validation contents."""

    REQUEST_MUTATION = "request_mutation"
    RESPONSE_MUTATION = "response_mutation"
    DYNAMIC_STATE_VALUE = "dynamic_state_value"
    BACKCHANNEL_CORRELATION = "backchannel_correlation"
    PRESERVE_BEHAVIOR = "preserve_behavior"
    RAW_BEHAVIOR = "raw_behavior"
    DELTA_CRASH_SURVIVAL = "semantic_delta_crash_survival"
    #: The build's host-side check (``delta_durability``), the stage 2
    #: stand-in for a natural crash that was not observed.
    DELTA_DURABILITY = "semantic_delta_durability"
    DYNAMIC_ORIGINAL_REPLAY = "dynamic_original_semantic_replay"


def _items_of_rule(rule: RuleDescription) -> set[ValidationItem]:
    items = set()
    if rule.message_type == "call":
        items.add(ValidationItem.REQUEST_MUTATION)
        if rule.direction == "S2C":   # a server's CALL is the backchannel
            items.add(ValidationItem.BACKCHANNEL_CORRELATION)
    else:
        items.add(ValidationItem.RESPONSE_MUTATION)
    if rule.transform == "copy" or set(rule.value_sources) - {"target"}:
        items.add(ValidationItem.DYNAMIC_STATE_VALUE)
    items.add(ValidationItem.PRESERVE_BEHAVIOR
              if rule.structure_policy == "preserve"
              else ValidationItem.RAW_BEHAVIOR)
    return items


def required_items(subset: SemanticSubset, *, crash: bool = True,
                   durability: bool = False) -> tuple[ValidationItem, ...]:
    """Crash survival and replay always; the rest when the subset has them.
    ``crash=False`` is the staged pin's list, without crash survival.
    ``durability`` asks for the build's host-side check instead of a
    natural crash (``crash=False`` with it)."""
    items = {ValidationItem.DYNAMIC_ORIGINAL_REPLAY}
    if durability:
        items.add(ValidationItem.DELTA_DURABILITY)
    if crash:
        items.add(ValidationItem.DELTA_CRASH_SURVIVAL)
    if "call" in subset.message_types:
        items.add(ValidationItem.REQUEST_MUTATION)
        if "S2C" in subset.directions:
            items.add(ValidationItem.BACKCHANNEL_CORRELATION)
    if "reply" in subset.message_types:
        items.add(ValidationItem.RESPONSE_MUTATION)
    if "copy" in subset.transforms or set(subset.value_sources) - {"target"}:
        items.add(ValidationItem.DYNAMIC_STATE_VALUE)
    if "preserve" in subset.structure_policies:
        items.add(ValidationItem.PRESERVE_BEHAVIOR)
    if "raw" in subset.structure_policies:
        items.add(ValidationItem.RAW_BEHAVIOR)
    return tuple(sorted(items, key=lambda i: i.value))


def subset_problems(subset: SemanticSubset, registry: CapabilityRegistry
                    ) -> list[str]:
    """What the subset claims that this build does not implement."""
    problems = []
    for name in DIMENSIONS:
        have = set(registry.schema_ids if name == "schema_ids"
                   else getattr(registry, name))
        extra = sorted(set(getattr(subset, name)) - have)
        if extra:
            problems.append(f"{name} not in the build registry: {extra}")
    return problems


def rule_problems(rule: RuleDescription, schema_id: str,
                  subset: SemanticSubset) -> list[str]:
    """Where a described rule leaves the subset."""
    single = {"schema_ids": schema_id, "directions": rule.direction,
              "message_types": rule.message_type,
              "target_kinds": rule.target_kind, "parts": rule.part,
              "mutation_kinds": rule.kind,
              "structure_policies": rule.structure_policy}
    if rule.transform is not None:
        single["transforms"] = rule.transform
    problems = [f"rule {rule.rule_id}: {name} {value!r} is outside the subset"
                for name, value in single.items()
                if value not in getattr(subset, name)]
    for name in ("value_sources", "predicate_ops"):
        extra = sorted(set(getattr(rule, name)) - set(getattr(subset, name)))
        if extra:
            problems.append(f"rule {rule.rule_id}: {name} {extra} are "
                            "outside the subset")
    return problems


# ---------------------------------------------------------------- guest runs


class OriginalDigest(_Strict):
    rule_id: Visible
    semantic_path: Visible
    original_sha256: Sha256


class PositionOriginals(_Strict):
    window_index: Annotated[int, Field(ge=0, lt=64)]
    production: tuple[OriginalDigest, ...] = Field(max_length=4096)
    replay: tuple[OriginalDigest, ...] = Field(max_length=4096)


class DynamicOriginals(_Strict):
    """The original values each side's forwarded batches replaced, projected
    from the same sealed journals as the judge input (05 oracle §1: replay
    must run on other dynamic bytes than production)."""

    production_evidence_manifest_sha256: Sha256
    replay_evidence_manifest_sha256: Sha256
    positions: tuple[PositionOriginals, ...] = Field(max_length=64)


def dynamic_originals(production, replay, data: ReplayJudgeInput
                      ) -> DynamicOriginals:
    """Project ``DynamicOriginals`` from two ``SealedJournal`` views, for the
    generations ``data`` correlated at each window position."""
    def digests(journal, side) -> tuple[OriginalDigest, ...]:
        if side is None:
            return ()
        c = side.correlation
        found = journal.find(vm_instance_id=c.vm_instance_id, lane_id=c.lane_id,
                             kcov_generation=c.kcov_generation,
                             program_digest=c.program_digest)
        if found is None:
            return ()
        return tuple(sorted(
            (OriginalDigest(rule_id=r, semantic_path=p, original_sha256=d)
             for e in found[1].exposures if e.terminal == "complete"
             for r, p, d in e.originals),
            key=lambda o: (o.rule_id, o.semantic_path, o.original_sha256)))
    return DynamicOriginals(
        production_evidence_manifest_sha256=production.manifest_sha256(),
        replay_evidence_manifest_sha256=replay.manifest_sha256(),
        positions=tuple(PositionOriginals(
            window_index=p.window_index, production=digests(production, p.production),
            replay=digests(replay, p.replay)) for p in data.positions))


def _dynamic_rules(run: GuestValidationRun) -> set[str]:
    """Rules that replaced, at one position, only other original values in
    replay than in production."""
    found: set[str] = set()
    for position in run.original_values.positions:
        keys = {(o.rule_id, o.semantic_path) for o in position.production}
        for key in keys:
            prod = {o.original_sha256 for o in position.production
                    if (o.rule_id, o.semantic_path) == key}
            repl = {o.original_sha256 for o in position.replay
                    if (o.rule_id, o.semantic_path) == key}
            if repl and not prod & repl:
                found.add(key[0])
    return found


class GuestValidationRun(_Strict):
    """One KVM validation of a subset: a crashed production window and its
    replay on the same Proxy build, judged by ``semantic_replay.evaluate``."""

    schema_version: Literal["semantic-guest-validation.v1"] = \
        "semantic-guest-validation.v1"
    subset_id: SubsetId
    environment: Literal["kvm_guest"]
    proxy_sha256: Sha256
    registry_digest: Sha256
    kernel_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    production_vm_instance_id: Visible
    replay_vm_instance_id: Visible
    rule_set: RuleSetDescription
    judge_input: ReplayJudgeInput
    replay_result: ReplayResult
    original_values: DynamicOriginals
    note: Annotated[str, Field(max_length=1024)] = ""


def _exercised(run: GuestValidationRun) -> set[str]:
    """Rules whose batch completed forwarding on both sides of one position."""
    found: set[str] = set()
    for position in run.replay_result.positions:
        if position.production is None or position.replay is None:
            continue
        sides = []
        for side in (position.production, position.replay):
            sides.append({item.rule_id
                          for entry in side.forward_complete_multiset
                          for item in entry.signature.items})
        found |= sides[0] & sides[1]
    return found


def _crash_cut(run: GuestValidationRun) -> tuple[bool, bool]:
    """Whether the production window ended in a guest crash, and whether
    the crash-cut position's MutationDelta was read back."""
    production = [p.production for p in run.judge_input.positions]
    last = production[-1] if production else None
    crashed = any(p is not None for p in production) and all(
        p.termination is Termination.GUEST_CRASH
        for p in production if p is not None)
    delta = (last is not None and bool(last.batches)
             and last.journal_integrity is not JournalIntegrity.CORRUPT)
    return crashed, delta


def unreproducible(run: GuestValidationRun) -> bool:
    """A guest crash left no MutationDelta at the crash cut: replay cannot
    reproduce it, and the subset is refused (§30)."""
    crashed, delta = _crash_cut(run)
    return crashed and not delta


def run_problems(run: GuestValidationRun, build: BuildRegistry,
                 subset: SemanticSubset, *, crash: bool = True) -> list[str]:
    """Why ``run`` does not count for ``subset``.  ``crash=False`` is the
    staged pin's check: the run need not end in a guest crash, but one that
    did must have left its MutationDelta."""
    problems = []
    if run.subset_id != subset.subset_id:
        problems.append("the run validates another subset")
    if (run.proxy_sha256, run.registry_digest) != (build.proxy_sha256,
                                                   build.registry_digest):
        problems.append("the run used another Proxy build")
    data, result = run.judge_input, run.replay_result
    if evaluate(data) != result:
        problems.append("the ReplayResult is not the judgment of its input")
    if not data.evidence_verified:
        problems.append("the replay evidence was not verified")
    if (result.semantic_verdict is not ReplayVerdict.EQUIVALENT
            or result.invalid_evidence or result.invalid_reasons):
        problems.append("the replay is not REPLAY_EQUIVALENT")
    described = run.rule_set
    if ((described.rule_set_id, described.schema_id,
         described.semantic_runtime_version) !=
            (data.rule_set_id, data.schema_id, data.semantic_runtime_version)):
        problems.append("the described rule set is not the replayed one")
    if (described.semantic_runtime_version
            != build.registry.semantic_runtime_version):
        problems.append("the rule set targets another runtime version")
    for rule in described.rules:
        problems += rule_problems(rule, described.schema_id, subset)
    originals = run.original_values
    if ((originals.production_evidence_manifest_sha256,
         originals.replay_evidence_manifest_sha256) !=
            (data.production_evidence_manifest_sha256,
             data.replay_evidence_manifest_sha256)
            or tuple(p.window_index for p in originals.positions)
            != tuple(p.window_index for p in data.positions)):
        problems.append("the original values are not from the judged journals")
    # Semantic Delta crash survival: the production window ended in a guest
    # crash and the crash-cut position's MutationDelta was read back.
    crashed, delta = _crash_cut(run)
    if crash and not crashed:
        problems.append("the production side did not end in a guest crash")
    if (crash or crashed) and not delta:
        problems.append("the crash-cut position has no MutationDelta")
    return problems


# ---------------------------------------------------------------- promotion


class PromotedSubset(_Strict):
    subset: SemanticSubset
    validation_items: tuple[ValidationItem, ...]
    evidence_refs: tuple[Sha256, ...] = Field(min_length=1,
                                              max_length=MAX_RUNS)
    #: ``pending``: the staged pin (§30 stage 1), usable only through a
    #: staged ``hcap_revision``.  Omitted when passed, so subsets promoted
    #: before the field keep their canonical bytes.
    crash_survival: Literal["passed", "pending"] = "passed"
    #: ``not_observed``: promoted on the build's ``DeltaDurabilityCheck``,
    #: no natural crash recorded.  Omitted when observed, so subsets
    #: promoted before the field keep their canonical bytes: each was
    #: promoted on a natural crash.
    natural_crash_reproduction: Literal["observed", "not_observed"] = \
        "observed"
    #: The ``DeltaDurabilityCheck`` the subset was promoted on, if any.
    durability_ref: Sha256 | None = None

    @model_validator(mode="after")
    def _durability(self) -> PromotedSubset:
        if self.natural_crash_reproduction == "not_observed" and (
                self.durability_ref is None
                or self.crash_survival != "passed"):
            raise ValueError("not_observed needs a durability check and a "
                             "promoted subset")
        return self

    @model_serializer(mode="wrap")
    def _serialize(self, handler):
        data = handler(self)
        if self.crash_survival == "passed":
            data.pop("crash_survival", None)
        if self.natural_crash_reproduction == "observed":
            data.pop("natural_crash_reproduction", None)
        if self.durability_ref is None:
            data.pop("durability_ref", None)
        return data


class PromotedSemanticCapabilityRegistry(_Strict):
    """The authority HCAP references for semantic mutation (04 §4)."""

    schema_version: Literal["promoted-semantic-registry.v1"] = \
        "promoted-semantic-registry.v1"
    proxy_sha256: Sha256
    registry_digest: Sha256
    registry: CapabilityRegistry
    subsets: tuple[PromotedSubset, ...] = Field(min_length=1,
                                                max_length=MAX_SUBSETS)

    @model_validator(mode="after")
    def _shape(self) -> PromotedSemanticCapabilityRegistry:
        if self.registry.digest != self.registry_digest:
            raise ValueError("registry_digest is not the registry's digest")
        ids = tuple(p.subset.subset_id for p in self.subsets)
        if ids != _sorted_unique(ids, "subset_id"):
            raise ValueError("subsets must be in subset_id order")
        return self

    @property
    def not_observed(self) -> tuple[str, ...]:
        """The promoted subsets no natural crash has been recorded for:
        their crash survival rests on the build's host-side check."""
        return tuple(p.subset.subset_id for p in self.subsets
                     if p.natural_crash_reproduction == "not_observed")

    @property
    def pending(self) -> tuple[str, ...]:
        """The subsets pinned with crash survival pending: this registry
        belongs to a staged revision, never a shared one (§30)."""
        return tuple(p.subset.subset_id for p in self.subsets
                     if p.crash_survival == "pending")


class UnreproducibleCrash(_Strict):
    """Natural guest crashes of a subset's runs that left no MutationDelta
    at the crash cut.  Replay cannot reproduce them; the subset was refused
    (§30)."""

    schema_version: Literal["semantic-unreproducible-crash.v1"] = \
        "semantic-unreproducible-crash.v1"
    subset_id: SubsetId
    proxy_sha256: Sha256
    registry_digest: Sha256
    run_refs: tuple[Sha256, ...] = Field(min_length=1, max_length=MAX_RUNS)


class PromotionRefused(ValueError):
    def __init__(self, problems: list[str],
                 unreproducible: tuple[str, ...] = ()) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems
        #: Runs whose natural crash left no MutationDelta.
        self.unreproducible = unreproducible


def pin(store: ArtifactStore, build: BuildRegistry, subset: SemanticSubset,
        run_refs: tuple[str, ...],
        previous: PromotedSemanticCapabilityRegistry | None = None,
        ) -> PromotedSemanticCapabilityRegistry:
    """M7 stage 1, the staged pin: the gate without crash survival.  The
    subset is kept with ``crash_survival: pending``; ``promote`` with a
    natural crash's runs passes it later."""
    return _gate(store, build, subset, run_refs, previous, crash=False)


def promote(store: ArtifactStore, build: BuildRegistry, subset: SemanticSubset,
            run_refs: tuple[str, ...],
            previous: PromotedSemanticCapabilityRegistry | None = None,
            durability_ref: str | None = None,
            ) -> PromotedSemanticCapabilityRegistry:
    """Run the M7 gate for one subset; raise PromotionRefused with every
    reason it fails.  ``previous`` keeps the subsets already promoted on the
    same build; a subset it pins pending is passed, its evidence kept.
    ``durability_ref`` is the build's ``DeltaDurabilityCheck``: runs then
    need not end in a guest crash, and the subset is promoted with its
    natural crash reproduction ``not_observed`` unless a counted run is
    one.  Without it, the runs must be a natural crash."""
    return _gate(store, build, subset, run_refs, previous, crash=True,
                 durability_ref=durability_ref)


def _gate(store: ArtifactStore, build: BuildRegistry, subset: SemanticSubset,
          run_refs: tuple[str, ...],
          previous: PromotedSemanticCapabilityRegistry | None, *,
          crash: bool, durability_ref: str | None = None
          ) -> PromotedSemanticCapabilityRegistry:
    problems = subset_problems(subset, build.registry)
    if durability_ref is not None:
        check = load_record(store, durability_ref, DeltaDurabilityCheck)
        if (check.proxy_sha256, check.registry_digest) != (
                build.proxy_sha256, build.registry_digest):
            problems.append("the durability check is for another Proxy "
                            "build")
        problems += [f"durability check: {p}" for p in check.problems()]
    # With a durability check the runs need not be a natural crash.
    runs_crash = crash and durability_ref is None
    if previous is not None and (previous.proxy_sha256, previous.registry_digest
                                 ) != (build.proxy_sha256,
                                       build.registry_digest):
        problems.append("the promoted registry belongs to another build; "
                        "a new build is promoted afresh")
    if not run_refs:
        problems.append("no guest validation run")
    if len(set(run_refs)) != len(run_refs) or len(run_refs) > MAX_RUNS:
        problems.append("run references must be unique and at most "
                        f"{MAX_RUNS}")
    exercised: list[tuple[str, RuleDescription]] = []
    passed: set[ValidationItem] = set()
    lost: list[str] = []
    for ref in run_refs:
        run = load_record(store, ref, GuestValidationRun)
        found = run_problems(run, build, subset, crash=runs_crash)
        if unreproducible(run):
            lost.append(ref)
            found.append("a natural guest crash left no MutationDelta at "
                         "the crash cut, so replay cannot reproduce it; "
                         "the subset is refused")
        problems += [f"run {ref[:12]}: {p}" for p in found]
        if found:
            continue
        crashed, delta = _crash_cut(run)
        if runs_crash or (crash and crashed and delta):
            passed.add(ValidationItem.DELTA_CRASH_SURVIVAL)
        used = _exercised(run)
        # Equivalent on the same originals proves nothing dynamic.
        if used & _dynamic_rules(run):
            passed.add(ValidationItem.DYNAMIC_ORIGINAL_REPLAY)
        for rule in run.rule_set.rules:
            if rule.rule_id in used:
                exercised.append((run.rule_set.schema_id, rule))
                passed |= _items_of_rule(rule)
    covered = {name: set() for name in DIMENSIONS}
    for schema_id, rule in exercised:
        covered["schema_ids"].add(schema_id)
        covered["directions"].add(rule.direction)
        covered["message_types"].add(rule.message_type)
        covered["target_kinds"].add(rule.target_kind)
        covered["parts"].add(rule.part)
        covered["mutation_kinds"].add(rule.kind)
        covered["structure_policies"].add(rule.structure_policy)
        if rule.transform is not None:
            covered["transforms"].add(rule.transform)
        covered["value_sources"] |= set(rule.value_sources)
        covered["predicate_ops"] |= set(rule.predicate_ops)
    for name in DIMENSIONS:
        missing = sorted(set(getattr(subset, name)) - covered[name])
        if missing:
            problems.append(f"no guest evidence exercises {name} {missing}")
    # A durability check that fails already raised its problems above.
    if durability_ref is not None:
        passed.add(ValidationItem.DELTA_DURABILITY)
    required = required_items(subset, crash=runs_crash,
                              durability=durability_ref is not None)
    observed = ValidationItem.DELTA_CRASH_SURVIVAL in passed
    if observed:
        required = tuple(sorted({*required,
                                 ValidationItem.DELTA_CRASH_SURVIVAL},
                                key=lambda i: i.value))
    missing_items = [i.value for i in required if i not in passed]
    if missing_items:
        problems.append(f"validation items not covered: {missing_items}")
    kept = {p.subset.subset_id: p for p in (previous.subsets if previous
                                           else ())}
    old = kept.get(subset.subset_id)
    if old is not None and old.subset != subset:
        problems.append(f"{subset.subset_id} is already promoted with "
                        "another definition")
    if old is not None and not crash and old.crash_survival == "passed":
        problems.append(f"{subset.subset_id} is already promoted; a staged "
                        "pin would not change it")
    if problems:
        raise PromotionRefused(problems, tuple(lost))
    refs = set(run_refs) | set(old.evidence_refs if old else ())
    extra: dict = {}
    if not crash:
        extra["crash_survival"] = "pending"
    else:
        # A natural crash seen now, or the one this subset was promoted on
        # before, keeps the reproduction observed; the build's durability
        # check alone leaves it not_observed.
        natural = observed or (old is not None
                               and old.crash_survival == "passed"
                               and old.natural_crash_reproduction
                               == "observed")
        standing = durability_ref or (old.durability_ref if old else None)
        if natural:
            required = tuple(sorted(
                {*required, ValidationItem.DELTA_CRASH_SURVIVAL},
                key=lambda i: i.value))
        else:
            extra["natural_crash_reproduction"] = "not_observed"
        if standing is not None:
            extra["durability_ref"] = standing
    kept[subset.subset_id] = PromotedSubset(
        subset=subset, validation_items=required,
        evidence_refs=tuple(sorted(refs)), **extra)
    return PromotedSemanticCapabilityRegistry(
        proxy_sha256=build.proxy_sha256, registry_digest=build.registry_digest,
        registry=build.registry,
        subsets=tuple(kept[k] for k in sorted(kept)))


def check_runtime(promoted: PromotedSemanticCapabilityRegistry,
                  runtime: BuildRegistry) -> bool:
    """04 §7.1: the running build must be the promoted one, exactly."""
    return ((runtime.proxy_sha256, runtime.registry_digest)
            == (promoted.proxy_sha256, promoted.registry_digest))


# ---------------------------------------------------------------- HCAP


def with_semantic_capability(catalog: HcapCatalog, promoted_ref: str,
                             promoted: PromotedSemanticCapabilityRegistry, *,
                             capability_id: str = DEFAULT_CAPABILITY_ID
                             ) -> HcapCatalog:
    """A new HCAP revision whose semantic mutation entry is ``promoted``.

    The entry lists the promoted subset ids as its scope and references the
    promoted registry by digest; the subsets' contents stay in that
    authority (04 §1.1), which the Agent reads with ``lookup_semantic_scope``.
    Its promotion is the M7 gate (``promote``), Stage 2's criterion in
    place of the probe campaign (07 §5.3 item 7), so the entry carries no
    contract.  The rest of the catalog, its gap contracts included, is kept.
    A subset pinned with crash survival pending (``pin``) makes the revision
    a staged one: the entry says so, and no shared catalog takes it.  A
    subset promoted on the build's durability check says that no natural
    crash was observed for it, and references the check as evidence.
    """
    ids = tuple(p.subset.subset_id for p in promoted.subsets)
    evidence = tuple(sorted(
        {r for p in promoted.subsets for r in p.evidence_refs}
        | {p.durability_ref for p in promoted.subsets
           if p.durability_ref is not None}))
    pending = (
        (f"Crash survival pending for {', '.join(promoted.pending)}: a "
         "staged pin (M7 stage 1); this revision is staged, not shared.",)
        if promoted.pending else ())
    pending += (
        (f"Natural crash reproduction not observed for "
         f"{', '.join(promoted.not_observed)}: Delta survival was checked "
         "on the host for this Proxy build (delta durability), not on a "
         "crashed guest.",)
        if promoted.not_observed else ())
    entry = Capability(
        id=capability_id, name="Promoted semantic mutation",
        purpose=("Semantic NFS/RPC mutation of Stage 1 traffic through the "
                 "Proxy target mode, limited to the M7-promoted subsets."),
        usable_stage=("stage2",), usable_by=("agent_stage2",),
        interface=CapabilityInterface(
            runtime_features=("nfs_proxy_target_mode",)),
        constraints=(
            "A MutationRuleSet must fit one promoted subset; read the subsets "
            "with lookup_semantic_scope.",
            "A value from an earlier transaction is state_lineage: not "
            "supported.",
            f"Proxy build sha256 {promoted.proxy_sha256}, registry "
            f"{promoted.registry_digest}; any other runtime is not this "
            "capability.", *pending),
        status="validated_subset", scope=ids, validated_scope=ids,
        evidence_refs=evidence,
        authority_refs=(AuthorityRef(
            kind="PromotedSemanticCapabilityRegistry",
            artifact_ref=promoted_ref),),
        source_refs=("tools/nfs-proxy/README.md",
                     "docs/design/03-nfs-proxy/06-implementation-gap-analysis.md"))
    capabilities = tuple(c for c in catalog.capabilities
                         if c.id != capability_id) + (entry,)
    missing = tuple(sorted(set(catalog.missing_capability_ids)
                           | {UNPROMOTED_GAP_ID}))
    kept = {name: getattr(catalog, name)
            for name in ("authority_refs", "gap_contracts")
            if name in catalog.model_fields_set}
    return HcapCatalog(capabilities=capabilities,
                       missing_capability_ids=missing, **kept)


def promoted_registry(store: ArtifactStore, catalog: HcapCatalog, *,
                      capability_id: str = DEFAULT_CAPABILITY_ID
                      ) -> PromotedSemanticCapabilityRegistry | None:
    """The promoted registry this HCAP revision's semantic mutation entry
    pins, narrowed to that entry's validated scope, or None.

    Only the entry ``with_semantic_capability`` writes counts: the
    capability ``capability_id``, usable by ``agent_stage2``, validated,
    and referencing the registry itself.  A registry digest anywhere else in
    the catalog (top level, another capability) is not Agent scope.  A
    subset pinned pending is kept, marked: a job bound to the staged
    revision uses it (§30 stage 1); ``pending`` names them.
    """
    entry = next((c for c in catalog.capabilities if c.id == capability_id),
                 None)
    if (entry is None or "agent_stage2" not in entry.usable_by
            or entry.status not in ("validated", "validated_subset")):
        return None
    refs = [r.artifact_ref for r in entry.authority_refs
            if r.kind == "PromotedSemanticCapabilityRegistry"]
    if len(refs) != 1:
        return None
    promoted = load_record(store, refs[0], PromotedSemanticCapabilityRegistry)
    scope = set(entry.validated_scope if entry.status == "validated_subset"
                else entry.scope)
    kept = tuple(p for p in promoted.subsets if p.subset.subset_id in scope)
    if not kept:
        return None
    return promoted.model_copy(update={"subsets": kept})


# ---------------------------------------------------------------- rule-set scope


class ScopeCheck(_Strict):
    subset_id: SubsetId | None
    missing_capability_id: str | None
    problems: tuple[str, ...] = ()


def _intent_problems(intent, subset: SemanticSubset,
                     registry: CapabilityRegistry) -> list[str]:
    sel = intent.selector
    who = f"intent {intent.intent_id}"
    schemas = [s.schema_id for s in registry.schemas
               if s.family == sel.protocol.family
               and s.program == sel.rpc.program and s.version == sel.rpc.version
               and (sel.protocol.minor_version is None
                    or s.minor_version == sel.protocol.minor_version)]
    problems = []
    if not schemas or not set(schemas) <= set(subset.schema_ids):
        problems.append(f"{who}: its ProtocolSchema is outside the subset")
    mutation = intent.mutation
    transform = mutation.transform
    sources = {p.lhs.source for p in sel.predicates}
    sources |= {p.rhs.source for p in sel.predicates
                if getattr(p.rhs, "kind", None) == "value_ref"}
    kind = getattr(transform, "kind", None)
    if kind == "copy":
        sources.add(transform.source.source)
    single = {"directions": intent.traffic_scope.direction,
              "message_types": sel.rpc.message_type,
              "target_kinds": sel.target.kind, "parts": sel.target.part,
              "mutation_kinds": mutation.kind,
              "structure_policies": mutation.structure_policy}
    if transform is not None:
        single["transforms"] = kind
    for name, value in single.items():
        if value not in getattr(subset, name):
            problems.append(f"{who}: {name} {value!r} is outside the subset")
    for name, values in (("value_sources", sources),
                         ("predicate_ops", {p.op for p in sel.predicates})):
        extra = sorted(values - set(getattr(subset, name)))
        if extra:
            problems.append(f"{who}: {name} {extra} are outside the subset")
    return problems


def rule_set_scope(rule_set, promoted: PromotedSemanticCapabilityRegistry | None
                   ) -> ScopeCheck:
    """Which promoted subset a ``MutationRuleSet`` fits as a whole, for the
    Mutation Rule Compiler (08 §12).  One compiled set has one schema and
    one subset's evidence, so every intent must fit the same subset.  This
    checks scope only; paths and types are the Compiler's against the
    ProtocolSchema."""
    if promoted is None:
        return ScopeCheck(subset_id=None,
                          missing_capability_id=UNPROMOTED_GAP_ID,
                          problems=("no semantic subset is promoted",))
    problems = []
    for p in promoted.subsets:
        found = [x for i in rule_set.intents
                 for x in _intent_problems(i, p.subset, promoted.registry)]
        if not found:
            return ScopeCheck(subset_id=p.subset.subset_id,
                              missing_capability_id=None)
        problems += [f"{p.subset.subset_id}: {x}" for x in found]
    return ScopeCheck(subset_id=None, missing_capability_id=UNPROMOTED_GAP_ID,
                      problems=tuple(problems))


# ---------------------------------------------------------------- operator entry


def main(argv: list[str] | None = None) -> int:
    """Operator entry for M7 (``tools/nfs-proxy/README.md`` "Promotion").

    registry: print the BuildRegistry of a Proxy binary (store it with --store).
    durability: check one Proxy build on the host, without a guest crash
              (write-ahead order, journal prefixes) and store the
              DeltaDurabilityCheck; ``promote --durability`` takes it.
    record:   turn one KVM validation (replay plan, both journals, the
              execprog output) into a GuestValidationRun record.
    pin:      M7 stage 1: the gate without crash survival; write the
              registry with the subset pending and the staged HCAP revision.
    promote:  run the gate for a subset over recorded runs; write the
              promoted registry and the new HCAP revision.

    A refusal over a natural crash without its MutationDelta stores an
    ``UnreproducibleCrash`` and prints ``unreproducible=<ref>``.
    """
    import argparse
    import sys

    from .replay_runner import (ReplayPlan, check_rule_set, judge_input,
                                parse_execprog_barriers)
    from .semantic_delta import SealedJournal
    from .semantic_replay import ReplayJudgeProfile

    parser = argparse.ArgumentParser(
        prog="python -m agent_pipeline.semantic_promotion")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("registry")
    r.add_argument("--proxy", type=Path, required=True)
    r.add_argument("--store", type=Path)
    d = sub.add_parser("durability")
    d.add_argument("--proxy", type=Path, required=True)
    d.add_argument("--store", type=Path, required=True)
    c = sub.add_parser("record")
    c.add_argument("--store", type=Path, required=True)
    c.add_argument("--subset", type=Path, required=True)
    c.add_argument("--proxy", type=Path, required=True,
                   help="the guest Proxy binary both sides ran")
    c.add_argument("--kernel-commit", required=True)
    c.add_argument("--environment", choices=["kvm_guest"], required=True)
    c.add_argument("--plan", type=Path, required=True)
    c.add_argument("--journal-dir", type=Path, required=True)
    c.add_argument("--production-vm", required=True)
    c.add_argument("--replay-dir", type=Path, required=True)
    c.add_argument("--replay-name", required=True)
    c.add_argument("--replay-vm", required=True)
    c.add_argument("--replay-lane", type=int, required=True)
    c.add_argument("--execprog-output", type=Path, required=True)
    ends = [t.value for t in Termination]
    c.add_argument("--production-end", choices=ends, required=True)
    c.add_argument("--replay-end", choices=ends, required=True)
    c.add_argument("--note", default="")
    for name in ("pin", "promote"):
        p = sub.add_parser(name)
        p.add_argument("--store", type=Path, required=True)
        p.add_argument("--build", required=True, help="BuildRegistry ref")
        p.add_argument("--subset", type=Path, required=True)
        p.add_argument("--run", action="append", required=True, dest="runs")
        p.add_argument("--hcap", required=True,
                       help="the HCAP revision to extend")
        p.add_argument("--previous", help="promoted registry ref on this build")
        p.add_argument("--capability-id", default=DEFAULT_CAPABILITY_ID)
        if name == "promote":
            p.add_argument("--durability",
                           help="the build's DeltaDurabilityCheck ref: runs "
                                "need not be a natural crash")
    args = parser.parse_args(argv)

    if args.command == "registry":
        build = read_build_registry(args.proxy)
        if args.store is not None:
            print(f"build={put_record(ArtifactStore(args.store), build)}")
        print(canonical_json(build).decode())
        return 0

    if args.command == "durability":
        import tempfile
        build = read_build_registry(args.proxy)
        schema = next((i for i in build.registry.schema_ids
                       if i.startswith("nfs4.1/")), None)
        if schema is None:
            print("durability: the build has no nfs4.1 schema",
                  file=sys.stderr)
            return 3
        with tempfile.TemporaryDirectory(prefix="durability-") as work:
            try:
                check = probe(args.proxy, proxy_sha256=build.proxy_sha256,
                              registry_digest=build.registry_digest,
                              schema_id=schema, workdir=Path(work))
            except ProbeError as error:
                print(f"durability: no evidence: {error}", file=sys.stderr)
                return 3
        ref = put_record(ArtifactStore(args.store), check)
        print(f"durability={ref} passed={str(check.passed).lower()} "
              f"cuts={check.cuts_checked}")
        for problem in check.problems():
            print(f"  does not count: {problem}", file=sys.stderr)
        return 0 if check.passed else 3

    store = ArtifactStore(args.store)
    subset = SemanticSubset.model_validate_json(args.subset.read_bytes())
    if args.command == "record":
        build = read_build_registry(args.proxy)
        plan = ReplayPlan.model_validate_json(args.plan.read_text())
        workdir = args.plan.parent
        compat = check_rule_set(args.proxy, plan.rule_set, workdir)
        production = SealedJournal(args.journal_dir, plan.production_journal)
        replay = SealedJournal(args.replay_dir, args.replay_name)
        data = judge_input(
            plan, production, replay,
            replay_vm_instance_id=args.replay_vm,
            replay_lane_id=args.replay_lane,
            replay_barriers=parse_execprog_barriers(
                args.execprog_output.read_text()),
            production_termination=Termination(args.production_end),
            replay_termination=Termination(args.replay_end),
            compatibility=compat, evidence_verified=True,
            profile=ReplayJudgeProfile(name="replay-default", revision="1"))
        run = GuestValidationRun(
            subset_id=subset.subset_id, environment=args.environment,
            proxy_sha256=build.proxy_sha256,
            registry_digest=build.registry_digest,
            kernel_commit=args.kernel_commit,
            production_vm_instance_id=plan.window.vm_instance_id,
            replay_vm_instance_id=args.replay_vm,
            rule_set=describe_rule_set(args.proxy, plan.rule_set, workdir),
            judge_input=data, replay_result=evaluate(data),
            original_values=dynamic_originals(production, replay, data),
            note=args.note)
        problems = run_problems(run, build, subset)
        print(f"run={put_record(store, run)} "
              f"verdict={run.replay_result.semantic_verdict}")
        for problem in problems:
            print(f"  does not count: {problem}", file=sys.stderr)
        return 0 if not problems else 3

    build = load_record(store, args.build, BuildRegistry)
    previous = (load_record(store, args.previous,
                            PromotedSemanticCapabilityRegistry)
                if args.previous else None)
    try:
        if args.command == "pin":
            promoted = pin(store, build, subset, tuple(args.runs), previous)
        else:
            promoted = promote(store, build, subset, tuple(args.runs),
                               previous, args.durability)
    except PromotionRefused as refused:
        for problem in refused.problems:
            print(f"{args.command} refused: {problem}", file=sys.stderr)
        if refused.unreproducible:
            lost = put_record(store, UnreproducibleCrash(
                subset_id=subset.subset_id, proxy_sha256=build.proxy_sha256,
                registry_digest=build.registry_digest,
                run_refs=tuple(sorted(refused.unreproducible))))
            print(f"unreproducible={lost}")
        return 3
    promoted_ref = put_record(store, promoted)
    catalog = load_record(store, args.hcap, HcapCatalog)
    hcap = with_semantic_capability(catalog, promoted_ref, promoted,
                                    capability_id=args.capability_id)
    label = "pinned" if args.command == "pin" else "promoted"
    print(f"{label}={promoted_ref} hcap_revision={put_record(store, hcap)}")
    return 0


__all__ = [
    "BuildRegistry", "CapabilityRegistry", "DEFAULT_CAPABILITY_ID",
    "DIMENSIONS", "DeltaDurabilityCheck", "DynamicOriginals", "GuestValidationRun", "PromotedSemanticCapabilityRegistry",
    "PromotedSubset", "PromotionRefused", "RegistryError", "RuleDescription",
    "RuleSetDescription", "ScopeCheck", "SemanticSubset", "StagedProxies",
    "UNPROMOTED_GAP_ID",
    "UnreproducibleCrash",
    "ValidationItem", "check_runtime", "describe_rule_set", "dynamic_originals",
    "pin", "promote",
    "promoted_registry", "read_build_registry", "required_items",
    "rule_problems", "rule_set_scope", "run_problems", "subset_problems",
    "unreproducible",
    "with_semantic_capability",
]

if __name__ == "__main__":
    raise SystemExit(main())
