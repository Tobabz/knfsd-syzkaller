"""Materializer authority contracts and deterministic admission decisions.

The records in this module are content-addressed repository authority data.
They do not parse syz programs and do not materialize a harness.  A caller
must start from a host-trusted HCAP revision; content addressing proves byte
integrity, not who approved the bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Annotated, Literal, Union

from pydantic import ConfigDict, Field, model_validator

from .artifacts import ArtifactStore
from .contracts import Commit, Record, Sha256
from .data import canonical_json, load_record
from .hcap import ArtifactHcapChecker, HcapCatalog, RuntimeSelection


Text = Annotated[str, Field(min_length=1, pattern=r"\S")]
Identifier = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]
CallName = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.$]*$")]
Target = Annotated[
    str, Field(pattern=r"^[a-z0-9_]+/[a-z0-9_]+$")]


class AuthorityError(ValueError):
    """An authority artifact is missing, inconsistent, or not trusted."""


class AuthorityIdentityMismatch(AuthorityError):
    """Authority data belongs to a different build or target."""


class UntrustedAuthority(AuthorityError):
    """The selected HCAP does not identify exactly one required authority."""


class AuthorityRecord(Record):
    """Strict immutable records used in canonical authority artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _require_sorted_unique(values: tuple, name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {name}")
    if values != tuple(sorted(values)):
        raise ValueError(f"{name} must be sorted")


class BuildFile(AuthorityRecord):
    """One build output, named relative to an explicitly supplied build root."""

    path: Text
    artifact_ref: Sha256

    @model_validator(mode="after")
    def _safe_relative_path(self) -> BuildFile:
        path = PurePosixPath(self.path)
        if (path.is_absolute() or self.path in ("", ".") or "\\" in self.path
                or self.path != path.as_posix()
                or any(part in ("", ".", "..") for part in path.parts)):
            raise ValueError("build file path must be a normalized relative POSIX path")
        return self


class SyzkallerBuildManifest(AuthorityRecord):
    """Canonical digest inventory for one pinned syzkaller target build."""

    schema_version: Literal["syzkaller-build-manifest.v1"] = \
        "syzkaller-build-manifest.v1"
    syzkaller_commit: Commit
    patch_series_sha256: Sha256
    target: Target
    files: tuple[BuildFile, ...] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def _shape(self) -> SyzkallerBuildManifest:
        paths = tuple(item.path for item in self.files)
        _require_sorted_unique(paths, "build file path")
        return self


class SyzkallerCallTable(AuthorityRecord):
    """Exact call names resolved by one generated syzkaller target table."""

    schema_version: Literal["syzkaller-call-table.v1"] = \
        "syzkaller-call-table.v1"
    syzkaller_commit: Commit
    target: Target
    calls: tuple[CallName, ...] = Field(min_length=1, max_length=131072)

    @model_validator(mode="after")
    def _shape(self) -> SyzkallerCallTable:
        _require_sorted_unique(self.calls, "call name")
        return self


class SyzkallerTargetIdentity(AuthorityRecord):
    """The exact syzkaller source, patch, build, call table, and target."""

    syzkaller_commit: Commit
    patch_series_sha256: Sha256
    build_manifest_sha256: Sha256
    call_table_sha256: Sha256
    target: Target


class ResourceOriginConstraint(AuthorityRecord):
    kind: Literal["resource_origin"] = "resource_origin"
    argument_index: int = Field(ge=0, le=4095)
    resource_type: Literal["fd", "path", "socket", "buffer"]
    allowed_origins: tuple[Identifier, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def _shape(self) -> ResourceOriginConstraint:
        _require_sorted_unique(self.allowed_origins, "allowed resource origin")
        return self


class IntegerRangeConstraint(AuthorityRecord):
    kind: Literal["integer_range"] = "integer_range"
    argument_index: int = Field(ge=0, le=4095)
    minimum: int | None = None
    maximum: int | None = None

    @model_validator(mode="after")
    def _shape(self) -> IntegerRangeConstraint:
        if self.minimum is None and self.maximum is None:
            raise ValueError("integer range needs at least one bound")
        if (self.minimum is not None and self.maximum is not None
                and self.minimum > self.maximum):
            raise ValueError("integer range minimum exceeds maximum")
        return self


class ByteLengthConstraint(AuthorityRecord):
    kind: Literal["byte_length"] = "byte_length"
    argument_index: int = Field(ge=0, le=4095)
    minimum_bytes: int = Field(default=0, ge=0)
    maximum_bytes: int = Field(ge=0)

    @model_validator(mode="after")
    def _shape(self) -> ByteLengthConstraint:
        if self.minimum_bytes > self.maximum_bytes:
            raise ValueError("byte length minimum exceeds maximum")
        return self


ResourceConstraint = Annotated[
    Union[ResourceOriginConstraint, IntegerRangeConstraint,
          ByteLengthConstraint],
    Field(discriminator="kind"),
]


def _constraint_key(value: ResourceConstraint) -> tuple[int, str, bytes]:
    return (value.argument_index, value.kind, canonical_json(value))


class CallAdmissionEntry(AuthorityRecord):
    """One exact syz call and every HCAP capability that may admit it."""

    call: CallName
    capability_ids: tuple[Identifier, ...] = Field(min_length=1, max_length=64)
    resource_constraints: tuple[ResourceConstraint, ...] = Field(
        default=(), max_length=64)

    @model_validator(mode="after")
    def _shape(self) -> CallAdmissionEntry:
        _require_sorted_unique(self.capability_ids, "capability ID")
        keys = tuple(_constraint_key(item) for item in self.resource_constraints)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate resource constraint")
        if keys != tuple(sorted(keys)):
            raise ValueError("resource constraints must be sorted")
        # Multiple constraints of one kind on one argument are ambiguous even
        # if their JSON differs.
        slots = tuple((item.argument_index, item.kind)
                      for item in self.resource_constraints)
        if len(slots) != len(set(slots)):
            raise ValueError("conflicting resource constraints")
        return self


class AdmissionLimits(AuthorityRecord):
    """Materializer-owned hard bounds, never Agent-selected policy."""

    max_program_bytes: int = Field(ge=1, le=64 * 1024 * 1024)
    max_calls_per_program: int = Field(ge=1, le=1_000_000)
    max_resources_per_program: int = Field(ge=0, le=1_000_000)


class CallAdmissionProfile(AuthorityRecord):
    """04 §3.1 authority. Absence from ``entries`` always means refusal."""

    schema_version: Literal["call-admission-profile.v1"] = \
        "call-admission-profile.v1"
    identity: SyzkallerTargetIdentity
    limits: AdmissionLimits
    entries: tuple[CallAdmissionEntry, ...] = Field(max_length=131072)

    @model_validator(mode="after")
    def _shape(self) -> CallAdmissionProfile:
        calls = tuple(entry.call for entry in self.entries)
        _require_sorted_unique(calls, "admission call")
        return self


class ResourceOriginFact(AuthorityRecord):
    argument_index: int = Field(ge=0, le=4095)
    resource_type: Literal["fd", "path", "socket", "buffer"]
    origin: Identifier


class IntegerFact(AuthorityRecord):
    argument_index: int = Field(ge=0, le=4095)
    value: int


class ByteLengthFact(AuthorityRecord):
    argument_index: int = Field(ge=0, le=4095)
    length_bytes: int = Field(ge=0)


class CallResourceFacts(AuthorityRecord):
    """Facts extracted by a future pinned syz parser for one concrete call."""

    origins: tuple[ResourceOriginFact, ...] = ()
    integers: tuple[IntegerFact, ...] = ()
    byte_lengths: tuple[ByteLengthFact, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> CallResourceFacts:
        for name in ("origins", "integers", "byte_lengths"):
            values = getattr(self, name)
            indexes = tuple(item.argument_index for item in values)
            if len(indexes) != len(set(indexes)):
                raise ValueError(f"duplicate {name} argument fact")
            if indexes != tuple(sorted(indexes)):
                raise ValueError(f"{name} facts must be sorted")
        return self


class ProgramResourceUsage(AuthorityRecord):
    program_bytes: int = Field(ge=0)
    call_count: int = Field(ge=0)
    resource_count: int = Field(ge=0)


AdmissionReason = Literal[
    "admitted", "identity_mismatch", "unknown_call",
    "capability_not_required", "resource_constraint_unverified",
    "resource_constraint_mismatch",
]


class AdmissionDecision(AuthorityRecord):
    admitted: bool
    reason: AdmissionReason
    capability_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> AdmissionDecision:
        _require_sorted_unique(self.capability_ids, "admitted capability ID")
        if self.admitted != (self.reason == "admitted"):
            raise ValueError("admission decision and reason disagree")
        if self.admitted and not self.capability_ids:
            raise ValueError("an admitted call needs a capability")
        if not self.admitted and self.capability_ids:
            raise ValueError("a refused call cannot grant capabilities")
        return self


class LimitDecision(AuthorityRecord):
    accepted: bool
    reason: Literal["within_limits", "program_bytes_exceeded",
                    "call_count_exceeded", "resource_count_exceeded"]

    @model_validator(mode="after")
    def _shape(self) -> LimitDecision:
        if self.accepted != (self.reason == "within_limits"):
            raise ValueError("limit decision and reason disagree")
        return self


def _resource_result(constraints: tuple[ResourceConstraint, ...],
                     facts: CallResourceFacts | None) -> str | None:
    if not constraints:
        return None
    if facts is None:
        return "resource_constraint_unverified"
    origins = {item.argument_index: item for item in facts.origins}
    integers = {item.argument_index: item.value for item in facts.integers}
    lengths = {item.argument_index: item.length_bytes
               for item in facts.byte_lengths}
    for constraint in constraints:
        if isinstance(constraint, ResourceOriginConstraint):
            fact = origins.get(constraint.argument_index)
            if fact is None:
                return "resource_constraint_unverified"
            if (fact.resource_type != constraint.resource_type
                    or fact.origin not in constraint.allowed_origins):
                return "resource_constraint_mismatch"
        elif isinstance(constraint, IntegerRangeConstraint):
            value = integers.get(constraint.argument_index)
            if value is None:
                return "resource_constraint_unverified"
            if ((constraint.minimum is not None and value < constraint.minimum)
                    or (constraint.maximum is not None
                        and value > constraint.maximum)):
                return "resource_constraint_mismatch"
        else:
            value = lengths.get(constraint.argument_index)
            if value is None:
                return "resource_constraint_unverified"
            if not constraint.minimum_bytes <= value <= constraint.maximum_bytes:
                return "resource_constraint_mismatch"
    return None


@dataclass(frozen=True)
class CallAdmissionAuthority:
    """A profile selected through one trusted HCAP revision."""

    hcap_revision: str
    profile_ref: str
    profile: CallAdmissionProfile

    def admit(self, call: str, required_capability_ids: tuple[str, ...], *,
              identity: SyzkallerTargetIdentity,
              resource_facts: CallResourceFacts | None = None
              ) -> AdmissionDecision:
        """Return a grant only after every closed-world check succeeds."""

        if identity != self.profile.identity:
            return AdmissionDecision(admitted=False, reason="identity_mismatch")
        if (not required_capability_ids
                or len(required_capability_ids) != len(set(required_capability_ids))
                or any(not isinstance(item, str) or re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9_.:/-]*", item) is None
                       for item in required_capability_ids)):
            raise ValueError("required capability IDs must be nonempty and unique")
        entry = next((item for item in self.profile.entries
                      if item.call == call), None)
        if entry is None:
            return AdmissionDecision(admitted=False, reason="unknown_call")
        matched = tuple(sorted(set(entry.capability_ids)
                               & set(required_capability_ids)))
        if not matched:
            return AdmissionDecision(
                admitted=False, reason="capability_not_required")
        resource_reason = _resource_result(entry.resource_constraints,
                                           resource_facts)
        if resource_reason is not None:
            return AdmissionDecision(admitted=False, reason=resource_reason)
        return AdmissionDecision(admitted=True, reason="admitted",
                                 capability_ids=matched)

    def check_limits(self, usage: ProgramResourceUsage) -> LimitDecision:
        limits = self.profile.limits
        if usage.program_bytes > limits.max_program_bytes:
            return LimitDecision(accepted=False,
                                 reason="program_bytes_exceeded")
        if usage.call_count > limits.max_calls_per_program:
            return LimitDecision(accepted=False, reason="call_count_exceeded")
        if usage.resource_count > limits.max_resources_per_program:
            return LimitDecision(accepted=False,
                                 reason="resource_count_exceeded")
        return LimitDecision(accepted=True, reason="within_limits")


class NeutralControlEntry(AuthorityRecord):
    """One exact runtime key and its immutable repository program."""

    runtime_selection: RuntimeSelection
    program_ref: Sha256
    required_capability_ids: tuple[Identifier, ...] = Field(
        min_length=1, max_length=64)

    @model_validator(mode="after")
    def _shape(self) -> NeutralControlEntry:
        _require_sorted_unique(self.required_capability_ids,
                               "neutral capability ID")
        interfaces = self.runtime_selection.enabled_interfaces
        if interfaces != tuple(sorted(interfaces)):
            raise ValueError("neutral enabled interfaces must be sorted")
        return self


def _runtime_selection_key(selection: RuntimeSelection) -> bytes:
    """Canonicalize the set-like interface subset for exact key lookup."""

    value = selection.model_dump(mode="json")
    value["enabled_interfaces"] = sorted(value["enabled_interfaces"])
    return canonical_json(value)


def _neutral_key(entry: NeutralControlEntry) -> bytes:
    return _runtime_selection_key(entry.runtime_selection)


class NeutralControlCatalog(AuthorityRecord):
    """05 §11 neutral programs, keyed by the full runtime selection."""

    schema_version: Literal["neutral-control-catalog.v1"] = \
        "neutral-control-catalog.v1"
    identity: SyzkallerTargetIdentity
    call_admission_profile_ref: Sha256
    entries: tuple[NeutralControlEntry, ...] = Field(max_length=4096)

    @model_validator(mode="after")
    def _shape(self) -> NeutralControlCatalog:
        keys = tuple(_neutral_key(entry) for entry in self.entries)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate neutral runtime selection")
        if keys != tuple(sorted(keys)):
            raise ValueError("neutral runtime selections must be sorted")
        return self


class NeutralSelectionDecision(AuthorityRecord):
    selected: bool
    reason: Literal["selected", "identity_mismatch",
                    "neutral_control_unavailable"]
    program_ref: Sha256 | None = None
    required_capability_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> NeutralSelectionDecision:
        _require_sorted_unique(self.required_capability_ids,
                               "selected neutral capability ID")
        if self.selected:
            if (self.reason != "selected" or self.program_ref is None
                    or not self.required_capability_ids):
                raise ValueError("selected neutral decision is incomplete")
        elif (self.reason == "selected" or self.program_ref is not None
              or self.required_capability_ids):
            raise ValueError("unselected neutral decision grants an artifact")
        return self


@dataclass(frozen=True)
class NeutralControlAuthority:
    """A neutral catalog selected through the same trusted HCAP."""

    hcap_revision: str
    catalog_ref: str
    catalog: NeutralControlCatalog

    def select(self, runtime_selection: RuntimeSelection, *,
               identity: SyzkallerTargetIdentity) -> NeutralSelectionDecision:
        if identity != self.catalog.identity:
            return NeutralSelectionDecision(
                selected=False, reason="identity_mismatch")
        requested_key = _runtime_selection_key(runtime_selection)
        entry = next((item for item in self.catalog.entries
                      if _neutral_key(item) == requested_key), None)
        if entry is None:
            return NeutralSelectionDecision(
                selected=False, reason="neutral_control_unavailable")
        return NeutralSelectionDecision(
            selected=True, reason="selected", program_ref=entry.program_ref,
            required_capability_ids=entry.required_capability_ids)


def _validate_identity_dependencies(store: ArtifactStore,
                                    identity: SyzkallerTargetIdentity
                                    ) -> tuple[SyzkallerBuildManifest,
                                               SyzkallerCallTable]:
    # Raw patch bytes are still immutable CAS data even though they have no
    # schema. The manifest and call table must be canonical typed records.
    store.get(identity.patch_series_sha256)
    manifest = load_record(store, identity.build_manifest_sha256,
                           SyzkallerBuildManifest)
    call_table = load_record(store, identity.call_table_sha256,
                             SyzkallerCallTable)
    if (manifest.syzkaller_commit != identity.syzkaller_commit
            or manifest.patch_series_sha256 != identity.patch_series_sha256
            or manifest.target != identity.target
            or call_table.syzkaller_commit != identity.syzkaller_commit
            or call_table.target != identity.target):
        raise AuthorityIdentityMismatch(
            "syzkaller identity dependencies do not match")
    for item in manifest.files:
        store.get(item.artifact_ref)
    return manifest, call_table


def load_call_admission_profile(
        store: ArtifactStore, trusted_profile_ref: str, *,
        expected_identity: SyzkallerTargetIdentity) -> CallAdmissionProfile:
    """Load canonical bytes and validate the complete build identity graph."""

    profile = load_record(store, trusted_profile_ref, CallAdmissionProfile)
    if profile.identity != expected_identity:
        raise AuthorityIdentityMismatch(
            "call admission profile build/target identity mismatch")
    _, call_table = _validate_identity_dependencies(store, profile.identity)
    unresolved = sorted(set(entry.call for entry in profile.entries)
                        - set(call_table.calls))
    if unresolved:
        raise AuthorityError(
            "admission profile contains unresolved calls: "
            + ", ".join(unresolved))
    return profile


def load_neutral_control_catalog(
        store: ArtifactStore, trusted_catalog_ref: str, *,
        trusted_profile_ref: str,
        expected_identity: SyzkallerTargetIdentity) -> NeutralControlCatalog:
    """Load a catalog and all of its immutable program dependencies."""

    profile = load_call_admission_profile(
        store, trusted_profile_ref, expected_identity=expected_identity)
    catalog = load_record(store, trusted_catalog_ref, NeutralControlCatalog)
    if catalog.identity != expected_identity:
        raise AuthorityIdentityMismatch(
            "neutral catalog build/target identity mismatch")
    if catalog.call_admission_profile_ref != trusted_profile_ref:
        raise UntrustedAuthority(
            "neutral catalog references a different admission profile")
    admitted_capabilities = {
        capability for entry in profile.entries
        for capability in entry.capability_ids
    }
    for entry in catalog.entries:
        if not set(entry.required_capability_ids) <= admitted_capabilities:
            raise AuthorityError(
                "neutral entry references a capability absent from the profile")
        store.get(entry.program_ref,
                  max_bytes=profile.limits.max_program_bytes)
    return catalog


def _hcap_authority_ref(catalog: HcapCatalog, kind: str) -> str:
    refs = {
        ref.artifact_ref
        for ref in (*catalog.authority_refs,
                    *(ref for capability in catalog.capabilities
                      for ref in capability.authority_refs))
        if ref.kind == kind
    }
    if len(refs) != 1:
        raise UntrustedAuthority(
            f"HCAP must select exactly one {kind} authority")
    return refs.pop()


def _validate_hcap_capabilities(profile: CallAdmissionProfile,
                                catalog: HcapCatalog) -> None:
    by_id = {capability.id: capability for capability in catalog.capabilities}
    for capability_id in sorted({
            item for entry in profile.entries for item in entry.capability_ids}):
        capability = by_id.get(capability_id)
        if capability is None:
            raise UntrustedAuthority(
                f"profile references unknown HCAP capability: {capability_id}")
        if ("stage1" not in capability.usable_stage
                or "agent_stage1" not in capability.usable_by):
            raise UntrustedAuthority(
                f"profile capability is not usable by Stage 1: {capability_id}")


def load_call_admission_authority(
        store: ArtifactStore, trusted_hcap_revision: str, *,
        expected_identity: SyzkallerTargetIdentity) -> CallAdmissionAuthority:
    """Resolve the sole profile selected by a host-trusted HCAP revision."""

    catalog = ArtifactHcapChecker(store).load_catalog(trusted_hcap_revision)
    profile_ref = _hcap_authority_ref(catalog, "CallAdmissionProfile")
    profile = load_call_admission_profile(
        store, profile_ref, expected_identity=expected_identity)
    _validate_hcap_capabilities(profile, catalog)
    return CallAdmissionAuthority(
        hcap_revision=trusted_hcap_revision, profile_ref=profile_ref,
        profile=profile)


def load_neutral_control_authority(
        store: ArtifactStore, trusted_hcap_revision: str, *,
        expected_identity: SyzkallerTargetIdentity) -> NeutralControlAuthority:
    """Resolve the neutral catalog and its matching profile from one HCAP."""

    catalog = ArtifactHcapChecker(store).load_catalog(trusted_hcap_revision)
    profile_ref = _hcap_authority_ref(catalog, "CallAdmissionProfile")
    neutral_ref = _hcap_authority_ref(catalog, "NeutralControlCatalog")
    profile = load_call_admission_profile(
        store, profile_ref, expected_identity=expected_identity)
    _validate_hcap_capabilities(profile, catalog)
    neutral = load_neutral_control_catalog(
        store, neutral_ref, trusted_profile_ref=profile_ref,
        expected_identity=expected_identity)
    return NeutralControlAuthority(
        hcap_revision=trusted_hcap_revision, catalog_ref=neutral_ref,
        catalog=neutral)
