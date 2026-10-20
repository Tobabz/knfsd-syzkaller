"""Deterministic Stage 1 Harness Materializer core.

This module validates and binds existing bytes.  It does not contain a
syzkaller parser, build syzkaller, repair programs, or infer calls.  Production
integration must inject an immutable build authority and a parser tied to the
exact :class:`SyzkallerTargetIdentity` selected by that authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Annotated, Literal, Protocol

from pydantic import ConfigDict, Field, model_validator

from .admission import (
    CallAdmissionAuthority,
    CallResourceFacts,
    NeutralControlAuthority,
    ProgramResourceUsage,
    SyzkallerCallTable,
    SyzkallerTargetIdentity,
    load_call_admission_authority,
    load_neutral_control_authority,
)
from .artifacts import (
    ArtifactIntegrityError,
    ArtifactLimitError,
    ArtifactStore,
)
from .contracts import (
    HOST_AUTHORITY_UNAVAILABLE,
    Commit,
    HarnessBinding,
    MaterializationHcapAuthority,
    MaterializeRejected,
    Materialized,
    NEUTRAL_CONTROL_UNAVAILABLE,
    Record,
    Sanitizer,
    Sha256,
)
from .data import canonical_json, load_record, put_record
from .hcap import (
    ArtifactHcapChecker,
    HcapCatalog,
    Q1Observation,
    ReachabilityPlan,
    RuntimeSelection,
)


Identifier = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]
Text = Annotated[str, Field(min_length=1, pattern=r"\S")]
CallName = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9_][A-Za-z0-9_.$]*$")]

PARSE_FAILURE = "parse_failure"
CALL_UNRESOLVED = "call_unresolved"
CALL_NOT_ADMITTED = "call_not_admitted"
DISALLOWED_OR_UNAVAILABLE_CALL = "disallowed_or_unavailable_call"
PROFILE_FIXTURE_ROUTE_MISMATCH = "profile_fixture_route_mismatch"
INVALID_RUNTIME_SELECTION = "invalid_runtime_selection"

# Typed parser refusal -> (Materialization reason, detail suffix).
PARSER_REFUSALS = {
    "call_unresolved": (CALL_UNRESOLVED, None),
    "call_disabled": (DISALLOWED_OR_UNAVAILABLE_CALL, "disabled"),
    "nfs_acquisition_unverified": (PROFILE_FIXTURE_ROUTE_MISMATCH,
                                   "nfs_acquisition_unverified"),
}
PARSER_CALL_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.$]{0,127}$")

MAX_PARSED_CALLS = 1_000_000
MAX_FACTS_PER_CALL = 64
MAX_NFS_ACQUISITIONS = 4096


class MaterializerRecord(Record):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)


def _sorted_unique(values: tuple, name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {name}")
    if values != tuple(sorted(values)):
        raise ValueError(f"{name} must be sorted")


def _runtime_key(selection: RuntimeSelection) -> bytes:
    value = selection.model_dump(mode="json")
    value["enabled_interfaces"] = sorted(value["enabled_interfaces"])
    return canonical_json(value)


def _runtime_coarse_key(selection: RuntimeSelection) -> tuple[str, ...]:
    return (selection.profile, selection.nfs_version, selection.fixture_mode,
            selection.route, selection.topology)


class HarnessBuildArtifact(MaterializerRecord):
    name: Identifier
    artifact_ref: Sha256


class ExecutionHarnessDescriptor(MaterializerRecord):
    """Immutable build and runtime surface behind an execution identity.

    The canonical SHA-256 of this record is ``execution_harness_id``. HCAP is
    deliberately absent: HCAP is evaluation authority and can be promoted
    without changing build identity.
    """

    schema_version: Literal["execution-harness.v1"] = "execution-harness.v1"
    kernel_commit: Commit
    sanitizer: Sanitizer
    syzkaller_identity: SyzkallerTargetIdentity
    build_artifacts: tuple[HarnessBuildArtifact, ...] = Field(
        min_length=1, max_length=256)
    guest_kernel_command_line: Text
    allowed_runtime_selections: tuple[RuntimeSelection, ...] = Field(
        min_length=1, max_length=4096)

    @model_validator(mode="after")
    def _shape(self) -> ExecutionHarnessDescriptor:
        names = tuple(item.name for item in self.build_artifacts)
        _sorted_unique(names, "harness build artifact name")
        keys = tuple(_runtime_key(item)
                     for item in self.allowed_runtime_selections)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate allowed runtime selection")
        if keys != tuple(sorted(keys)):
            raise ValueError("allowed runtime selections must be sorted")
        for selection in self.allowed_runtime_selections:
            interfaces = selection.enabled_interfaces
            if interfaces != tuple(sorted(interfaces)):
                raise ValueError("allowed runtime interfaces must be sorted")
        return self


def descriptor_id(descriptor: ExecutionHarnessDescriptor) -> str:
    return hashlib.sha256(canonical_json(descriptor)).hexdigest()


class ExecutionHarnessApproval(MaterializerRecord):
    """Trusted link between an execution descriptor and usable HCAP data."""

    descriptor: ExecutionHarnessDescriptor
    approved_hcap_revisions: tuple[Sha256, ...] = Field(
        min_length=1, max_length=128)

    @model_validator(mode="after")
    def _shape(self) -> ExecutionHarnessApproval:
        _sorted_unique(self.approved_hcap_revisions,
                       "approved HCAP revision")
        return self


class ExecutionHarnessAuthority(Protocol):
    def resolve(self, binding: HarnessBinding
                ) -> ExecutionHarnessApproval | None:
        """Return a host-approved immutable descriptor, or no approval."""


@dataclass(frozen=True)
class StaticExecutionHarnessAuthority:
    """Small immutable authority adapter useful for host snapshots."""

    approvals: tuple[ExecutionHarnessApproval, ...]

    def __post_init__(self) -> None:
        ids = tuple(descriptor_id(item.descriptor) for item in self.approvals)
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate execution harness approval")

    def resolve(self, binding: HarnessBinding
                ) -> ExecutionHarnessApproval | None:
        for approval in self.approvals:
            if descriptor_id(approval.descriptor) == \
                    binding.execution_harness_id:
                return approval
        return None


class NfsAcquisition(MaterializerRecord):
    profile: Identifier
    resource_origin: Identifier


class ParsedCall(MaterializerRecord):
    index: int = Field(ge=0, le=MAX_PARSED_CALLS - 1)
    call: CallName
    availability: Literal["available", "disabled", "unsupported"]
    resource_facts: CallResourceFacts

    @model_validator(mode="after")
    def _bounded_facts(self) -> ParsedCall:
        facts = self.resource_facts
        if any(len(values) > MAX_FACTS_PER_CALL for values in (
                facts.origins, facts.integers, facts.byte_lengths)):
            raise ValueError("too many resource facts for one call")
        return self


class ParsedProgram(MaterializerRecord):
    """Canonical output required from the injected pinned syz parser."""

    schema_version: Literal["parsed-syz-program.v1"] = \
        "parsed-syz-program.v1"
    identity: SyzkallerTargetIdentity
    program_sha256: Sha256
    calls: tuple[ParsedCall, ...] = Field(
        min_length=1, max_length=MAX_PARSED_CALLS)
    usage: ProgramResourceUsage
    nfs_acquisitions: tuple[NfsAcquisition, ...] = Field(
        max_length=MAX_NFS_ACQUISITIONS)

    @model_validator(mode="after")
    def _shape(self) -> ParsedProgram:
        indexes = tuple(item.index for item in self.calls)
        if indexes != tuple(range(len(self.calls))):
            raise ValueError("parsed call indexes must be contiguous and ordered")
        acquisitions = tuple((item.profile, item.resource_origin)
                             for item in self.nfs_acquisitions)
        if len(acquisitions) != len(set(acquisitions)):
            raise ValueError("duplicate NFS acquisition fact")
        if acquisitions != tuple(sorted(acquisitions)):
            raise ValueError("NFS acquisition facts must be sorted")
        return self


HCAP11_ID = "HCAP-11"
HCAP11_EXPIRE = "syz_nfsd_client_ctl$expire_client0"
HCAP11_ACQUIRE = "syz_open_nfs_lane_profile$client0_knfsd_v41"
HCAP11_ORIGIN = "nfs-profile:knfsd-v41:client0"
HCAP11_RECOVERY_IO = frozenset({
    "flock", "fsync", "getdents64", "openat", "read", "renameat2",
    "statx", "unlinkat", "write",
})


def _hcap11_program_error(parsed: ParsedProgram) -> str | None:
    """Return why a program is outside HCAP-11's validated sequence.

    Per-call admission proves that each individual pseudo-syscall and fd use
    is allowed.  It cannot prove the cross-call contract validated by the KVM
    campaign: one client0 expiry, followed by a fresh client0 profile
    acquisition.  Keep that small temporal/client constraint at the
    Materializer trust boundary.
    """
    expiry = [call.index for call in parsed.calls
              if call.call == HCAP11_EXPIRE]
    if len(expiry) != 1:
        return "expiry_count"

    acquisitions = [call.index for call in parsed.calls
                    if call.call == HCAP11_ACQUIRE]
    if not acquisitions:
        return "client0_recovery_missing"
    if len(acquisitions) != 1:
        return "client0_acquisition_count"
    if any(index <= expiry[0] for index in acquisitions):
        return "client0_recovery_precedes_expiry"

    origins = {item.resource_origin for item in parsed.nfs_acquisitions}
    if origins != {HCAP11_ORIGIN}:
        return "non_client0_acquisition"

    # Reject another lane-profile selector even if a future admission profile
    # happens to grant it through a different capability.
    if any(call.call.startswith("syz_open_nfs_lane_profile$")
           and call.call != HCAP11_ACQUIRE for call in parsed.calls):
        return "non_client0_profile_call"

    # Acquiring the profile alone does not establish the validated recovery
    # path.  Require a later ordinary operation whose FD provenance still
    # names client0.  close and lseek are deliberately excluded because they
    # need not drive an NFS request.
    first_acquisition = acquisitions[0]
    recovery_io = [
        call.index for call in parsed.calls
        if (call.index > first_acquisition
            and call.call in HCAP11_RECOVERY_IO
            and any(fact.origin == HCAP11_ORIGIN
                    for fact in call.resource_facts.origins))
    ]
    if not recovery_io:
        return "client0_recovery_io_missing"
    return None


HCAP12_ID = "HCAP-12"
HCAP12_CLD_PREFIX = "syz_nfsd_cld_ctl$"
HCAP12_RECONNECT = "syz_nfsd_cld_ctl$reconnect"


def _hcap12_program_error(parsed: ParsedProgram) -> str | None:
    """Return why a program is outside HCAP-12's validated sequence.

    HCAP-12 extends the HCAP-11 recovery sequence with exactly one bounded
    nfsdcld reconnect between the client0 expiry and the fresh client0
    acquisition, so the recovery's tracking create meets a pipe whose reader
    is being replaced.  Any other nfsdcld control operation (the
    daemon-down validation operation included) is outside the validated
    subset and is refused here regardless of per-call grants.
    """
    error = _hcap11_program_error(parsed)
    if error is not None:
        return f"hcap11:{error}"
    controls = [call for call in parsed.calls
                if call.call.startswith(HCAP12_CLD_PREFIX)]
    if any(call.call != HCAP12_RECONNECT for call in controls):
        return "cld_operation_not_validated"
    if len(controls) != 1:
        return "cld_reconnect_count"
    expiry = next(call.index for call in parsed.calls
                  if call.call == HCAP11_EXPIRE)
    acquisition = next(call.index for call in parsed.calls
                       if call.call == HCAP11_ACQUIRE)
    if not expiry < controls[0].index < acquisition:
        return "cld_reconnect_order"
    return None


class SyzParseFailure(ValueError):
    """A deterministic strict-parse refusal from the injected parser.

    ``reason`` is set only for a typed refusal that names the offending call
    (one of ``PARSER_REFUSALS``); the Materializer routes it to that typed
    reason instead of a bare ``parse_failure``.
    """

    def __init__(self, message: str = "", *, reason: str | None = None,
                 call: str | None = None,
                 call_index: int | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.call = call
        self.call_index = call_index


class PinnedSyzParser(Protocol):
    def parse(self, program: bytes, *,
              identity: SyzkallerTargetIdentity) -> ParsedProgram:
        """Strictly parse immutable bytes under exactly ``identity``."""


class NormalFlowSeed(MaterializerRecord):
    seed_id: Identifier
    program_ref: Sha256
    runtime_selections: tuple[RuntimeSelection, ...] = Field(
        min_length=1, max_length=128)

    @model_validator(mode="after")
    def _shape(self) -> NormalFlowSeed:
        keys = tuple(_runtime_key(item) for item in self.runtime_selections)
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate seed runtime selection")
        if keys != tuple(sorted(keys)):
            raise ValueError("seed runtime selections must be sorted")
        for selection in self.runtime_selections:
            interfaces = selection.enabled_interfaces
            if interfaces != tuple(sorted(interfaces)):
                raise ValueError("seed runtime interfaces must be sorted")
        return self


class NormalFlowSeedManifest(MaterializerRecord):
    schema_version: Literal["normal-flow-seed-manifest.v1"] = \
        "normal-flow-seed-manifest.v1"
    identity: SyzkallerTargetIdentity
    seeds: tuple[NormalFlowSeed, ...] = Field(max_length=65536)

    @model_validator(mode="after")
    def _shape(self) -> NormalFlowSeedManifest:
        ids = tuple(item.seed_id for item in self.seeds)
        _sorted_unique(ids, "normal-flow seed ID")
        return self


class MaterializationReviewManifest(MaterializerRecord):
    schema_version: Literal["materialization-review.v1"] = \
        "materialization-review.v1"
    candidate_id: Text
    plan_ref: Sha256
    program_kind: Literal["program", "seed"]
    program_ref: Sha256
    seed_manifest_ref: Sha256 | None = None
    seed_id: Identifier | None = None
    neutral_program_ref: Sha256
    hcap_revision: Sha256
    call_admission_profile_ref: Sha256
    neutral_control_catalog_ref: Sha256
    runtime_selection: RuntimeSelection
    execution_harness_id: Sha256
    scenario_parser_result_ref: Sha256
    neutral_parser_result_ref: Sha256
    required_capability_ids: tuple[Identifier, ...]
    selected_capability_ids: tuple[Identifier, ...]

    @model_validator(mode="after")
    def _shape(self) -> MaterializationReviewManifest:
        _seed_shape(self.program_kind, self.seed_manifest_ref, self.seed_id)
        _sorted_unique(self.required_capability_ids,
                       "review required capability ID")
        _sorted_unique(self.selected_capability_ids,
                       "review selected capability ID")
        return self


class ReachabilityHarness(MaterializerRecord):
    schema_version: Literal["reachability-harness.v1"] = \
        "reachability-harness.v1"
    candidate_id: Text
    plan_ref: Sha256
    program_kind: Literal["program", "seed"]
    program_ref: Sha256
    seed_manifest_ref: Sha256 | None = None
    seed_id: Identifier | None = None
    neutral_program_ref: Sha256
    runtime_selection: RuntimeSelection
    required_capability_ids: tuple[Identifier, ...]
    selected_capability_ids: tuple[Identifier, ...]
    q1_observation: Q1Observation
    hcap_revision: Sha256
    call_admission_profile_ref: Sha256
    neutral_control_catalog_ref: Sha256
    execution_harness_id: Sha256
    scenario_parser_result_ref: Sha256
    neutral_parser_result_ref: Sha256
    review_manifest_sha256: Sha256

    @model_validator(mode="after")
    def _shape(self) -> ReachabilityHarness:
        _seed_shape(self.program_kind, self.seed_manifest_ref, self.seed_id)
        _sorted_unique(self.required_capability_ids,
                       "harness required capability ID")
        _sorted_unique(self.selected_capability_ids,
                       "harness selected capability ID")
        return self


def _seed_shape(kind: str, manifest_ref: str | None,
                seed_id: str | None) -> None:
    if kind == "seed":
        if manifest_ref is None or seed_id is None:
            raise ValueError("seed harness needs seed provenance")
    elif manifest_ref is not None or seed_id is not None:
        raise ValueError("program harness cannot carry seed provenance")


@dataclass(frozen=True)
class _Failure(Exception):
    reason: str
    detail: str
    profile: str | None = None

    def result(self) -> MaterializeRejected:
        return MaterializeRejected(reason=self.reason, detail=self.detail,
                                   profile=self.profile)


_INVALID_RECORD = (ValueError, TypeError, RecursionError)


class ArtifactHarnessMaterializer:
    """``components.Materializer`` over canonical CAS and injected authority."""

    def __init__(self, artifacts: ArtifactStore,
                 builds: ExecutionHarnessAuthority,
                 parser: PinnedSyzParser) -> None:
        self.artifacts = artifacts
        self.builds = builds
        self.parser = parser

    @staticmethod
    def _fail(reason: str, detail: str, *,
              profile: str | None = None) -> None:
        raise _Failure(reason, detail, profile)

    def _load_plan(self, plan_ref: str) -> ReachabilityPlan:
        try:
            return load_record(self.artifacts, plan_ref, ReachabilityPlan)
        except OSError:
            raise
        except _INVALID_RECORD:
            self._fail(PARSE_FAILURE, "invalid_plan_artifact")

    def _approval(self, binding: HarnessBinding) -> ExecutionHarnessApproval:
        approval = self.builds.resolve(binding)
        if type(approval) is not ExecutionHarnessApproval:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "execution_harness_unapproved")
        try:
            approval = ExecutionHarnessApproval.model_validate_json(
                canonical_json(approval))
        except _INVALID_RECORD:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "malformed_execution_harness_approval")
        descriptor = approval.descriptor
        if descriptor_id(descriptor) != binding.execution_harness_id:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "execution_harness_identity_mismatch")
        if (descriptor.kernel_commit != binding.kernel_commit
                or descriptor.sanitizer != binding.sanitizer):
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "execution_harness_binding_mismatch")
        if binding.hcap_revision not in approval.approved_hcap_revisions:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "hcap_not_approved_for_execution_harness")
        for artifact in descriptor.build_artifacts:
            try:
                self.artifacts.get(artifact.artifact_ref)
            except OSError:
                raise
            except _INVALID_RECORD:
                self._fail(HOST_AUTHORITY_UNAVAILABLE,
                           f"invalid_build_artifact:{artifact.name}")
        return approval

    def _runtime(self, descriptor: ExecutionHarnessDescriptor,
                 selection: RuntimeSelection) -> None:
        requested = _runtime_key(selection)
        if any(_runtime_key(item) == requested
               for item in descriptor.allowed_runtime_selections):
            return
        coarse = _runtime_coarse_key(selection)
        if any(_runtime_coarse_key(item) == coarse
               for item in descriptor.allowed_runtime_selections):
            self._fail(INVALID_RUNTIME_SELECTION,
                       "runtime_interfaces_or_trace_not_allowlisted")
        self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                   "profile_fixture_route_or_topology_not_allowlisted")

    def _hcap(self, binding: HarnessBinding, plan: ReachabilityPlan,
              authority: MaterializationHcapAuthority) -> HcapCatalog:
        if authority.effective_hcap_revision != binding.hcap_revision:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "materialization_hcap_authority_mismatch")
        if authority.validation == "exact_plan_revision" and \
                plan.hcap_revision != authority.effective_hcap_revision:
            self._fail(INVALID_RUNTIME_SELECTION, "hcap_revision_mismatch")
        try:
            catalog = ArtifactHcapChecker(self.artifacts).load_catalog(
                binding.hcap_revision)
        except OSError:
            raise
        except _INVALID_RECORD:
            self._fail(HOST_AUTHORITY_UNAVAILABLE, "invalid_hcap_artifact")

        # Materializer is an independent trust boundary.  Repeat the complete
        # declarative plan/catalog check here instead of assuming that a
        # Controller called ArtifactHcapChecker.check_plan() first.  This is
        # intentionally performed over the already loaded immutable records.
        by_id = {item.id: item for item in catalog.capabilities}
        interfaces: set[str] = set()
        violations: list[str] = []
        for use in plan.capability_uses:
            capability = by_id.get(use.capability_id)
            if capability is None:
                violations.append(f"unknown_capability:{use.capability_id}")
                continue
            if "agent_stage1" not in capability.usable_by:
                violations.append(
                    f"not_usable_by_agent_stage1:{capability.id}")
            if "stage1" not in capability.usable_stage:
                violations.append(f"not_usable_in_stage1:{capability.id}")
            if use.status != capability.status:
                violations.append(
                    f"capability_status_mismatch:{capability.id}")
            for scope in sorted(set(use.scope) - set(capability.scope)):
                violations.append(
                    f"undeclared_scope:{capability.id}:{scope}")
            if capability.status == "validated":
                unvalidated: set[str] = set()
            elif capability.status == "validated_subset":
                unvalidated = set(use.scope) - \
                    set(capability.validated_scope)
            else:
                unvalidated = set(use.scope)
            if set(use.unvalidated_scope) != unvalidated:
                violations.append(
                    f"unvalidated_scope_not_explicit:{capability.id}")
            interfaces.update(capability.interface.syz_calls)
            interfaces.update(capability.interface.runtime_features)
        for interface in plan.runtime_selection.enabled_interfaces:
            if interface not in interfaces:
                violations.append(f"interface_not_declared:{interface}")
        if violations:
            self._fail(CALL_NOT_ADMITTED,
                       f"hcap_plan_violation:{violations[0]}")
        return catalog

    @staticmethod
    def _authority_ref(catalog: HcapCatalog, kind: str) -> str | None:
        refs = {
            ref.artifact_ref
            for ref in (*catalog.authority_refs,
                        *(ref for capability in catalog.capabilities
                          for ref in capability.authority_refs))
            if ref.kind == kind
        }
        if len(refs) == 1:
            return refs.pop()
        return None

    def _seed(self, plan: ReachabilityPlan, catalog: HcapCatalog,
              identity: SyzkallerTargetIdentity) -> None:
        proposal = plan.program_proposal
        if proposal.kind != "seed":
            return
        trusted_ref = self._authority_ref(catalog, "NormalFlowSeedManifest")
        if trusted_ref is None or proposal.seed_manifest_ref != trusted_ref:
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       "seed_manifest_not_trusted")
        try:
            manifest = load_record(self.artifacts, trusted_ref,
                                   NormalFlowSeedManifest)
        except OSError:
            raise
        except _INVALID_RECORD:
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       "invalid_seed_manifest")
        if manifest.identity != identity:
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       "seed_build_identity_mismatch")
        seed = next((item for item in manifest.seeds
                     if item.seed_id == proposal.seed_id), None)
        if seed is None or seed.program_ref != proposal.artifact_ref:
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       "seed_provenance_mismatch")
        requested = _runtime_key(plan.runtime_selection)
        if all(_runtime_key(item) != requested
               for item in seed.runtime_selections):
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       "seed_runtime_selection_mismatch")

    def _program_bytes(self, ref: str, *, limit: int, role: str) -> bytes:
        try:
            return self.artifacts.get(ref, max_bytes=limit)
        except OSError:
            raise
        except ArtifactLimitError:
            self._fail(DISALLOWED_OR_UNAVAILABLE_CALL,
                       f"{role}_program_limit_exceeded")
        except (ArtifactIntegrityError, ValueError, TypeError, RecursionError):
            self._fail(PARSE_FAILURE, f"invalid_{role}_program_artifact")

    def _parse(self, program: bytes, program_ref: str, *, role: str,
               identity: SyzkallerTargetIdentity) -> ParsedProgram:
        try:
            parsed = self.parser.parse(program, identity=identity)
        except OSError:
            raise
        except SyzParseFailure as error:
            self._parser_refusal(error, role)
            self._fail(PARSE_FAILURE, f"{role}_strict_parse_failed")
        except (ValueError, TypeError, RecursionError):
            self._fail(PARSE_FAILURE, f"{role}_strict_parse_failed")
        if type(parsed) is not ParsedProgram:
            self._fail(PARSE_FAILURE, f"{role}_parser_contract_invalid")
        try:
            parsed = ParsedProgram.model_validate_json(canonical_json(parsed))
        except _INVALID_RECORD:
            self._fail(PARSE_FAILURE, f"{role}_parser_result_invalid")
        if parsed.identity != identity:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       f"{role}_parser_identity_mismatch")
        if parsed.program_sha256 != program_ref:
            self._fail(PARSE_FAILURE, f"{role}_parser_digest_mismatch")
        if (parsed.usage.program_bytes != len(program)
                or parsed.usage.call_count != len(parsed.calls)):
            self._fail(PARSE_FAILURE, f"{role}_parser_usage_mismatch")
        fact_resources = {
            fact.origin
            for call in parsed.calls for fact in call.resource_facts.origins
        }
        fact_resources.update(item.resource_origin
                              for item in parsed.nfs_acquisitions)
        if parsed.usage.resource_count < len(fact_resources):
            self._fail(PARSE_FAILURE,
                       f"{role}_parser_resource_count_underreported")
        return parsed

    def _parser_refusal(self, error: SyzParseFailure, role: str) -> None:
        """Keep a typed refusal's reason and call; ignore a malformed one."""
        route = PARSER_REFUSALS.get(getattr(error, "reason", None))
        call, index = getattr(error, "call", None), getattr(error, "call_index", None)
        if (route is None or type(call) is not str or not PARSER_CALL_NAME.fullmatch(call)
                or type(index) is not int or not 0 <= index < MAX_PARSED_CALLS):
            return
        reason, suffix = route
        detail = f"{role}:{index}:{call}"
        self._fail(reason, f"{detail}:{suffix}" if suffix else detail)

    def _admit(self, parsed: ParsedProgram, *, role: str,
               selection: RuntimeSelection,
               required_capabilities: tuple[str, ...],
               authority: CallAdmissionAuthority,
               call_table: SyzkallerCallTable) -> tuple[str, ...]:
        limit = authority.check_limits(parsed.usage)
        if not limit.accepted:
            self._fail(DISALLOWED_OR_UNAVAILABLE_CALL,
                       f"{role}_{limit.reason}")
        if not parsed.nfs_acquisitions:
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       f"{role}_nfs_profile_not_acquired")
        if any(item.profile != selection.profile
               for item in parsed.nfs_acquisitions):
            self._fail(PROFILE_FIXTURE_ROUTE_MISMATCH,
                       f"{role}_nfs_profile_mismatch")
        hcap12 = role == "scenario" and HCAP12_ID in required_capabilities
        if hcap12:
            error = _hcap12_program_error(parsed)
            if error is not None:
                self._fail(CALL_NOT_ADMITTED,
                           f"{role}_hcap12_program_contract:{error}")
        elif any(call.call.startswith(HCAP12_CLD_PREFIX)
                 for call in parsed.calls):
            # nfsdcld control perturbs a shared lane daemon; only the
            # HCAP-12 scenario contract may carry it, never a neutral control.
            self._fail(CALL_NOT_ADMITTED,
                       f"{role}_hcap12_program_contract:cld_without_hcap12")
        if role == "scenario" and HCAP11_ID in required_capabilities:
            error = _hcap11_program_error(parsed)
            if error is not None:
                self._fail(CALL_NOT_ADMITTED,
                           f"{role}_hcap11_program_contract:{error}")

        resolved_calls = set(call_table.calls)
        selected: set[str] = set()
        for call in parsed.calls:
            if call.call not in resolved_calls:
                self._fail(CALL_UNRESOLVED,
                           f"{role}:{call.index}:{call.call}")
            if call.availability != "available":
                self._fail(DISALLOWED_OR_UNAVAILABLE_CALL,
                           f"{role}:{call.index}:{call.call}:"
                           f"{call.availability}")
            decision = authority.admit(
                call.call, required_capabilities,
                identity=parsed.identity,
                resource_facts=call.resource_facts)
            if not decision.admitted:
                if decision.reason == "identity_mismatch":
                    self._fail(HOST_AUTHORITY_UNAVAILABLE,
                               f"{role}_admission_identity_mismatch")
                self._fail(CALL_NOT_ADMITTED,
                           f"{role}:{call.index}:{call.call}:"
                           f"{decision.reason}")
            selected.update(decision.capability_ids)
        return tuple(sorted(selected))

    def _persist(self, *, plan_ref: str, plan: ReachabilityPlan,
                 binding: HarnessBinding,
                 descriptor: ExecutionHarnessDescriptor,
                 admission: CallAdmissionAuthority,
                 neutral: NeutralControlAuthority,
                 neutral_program_ref: str,
                 scenario_parsed: ParsedProgram,
                 neutral_parsed: ParsedProgram,
                 selected_capabilities: tuple[str, ...]) -> Materialized:
        descriptor_ref = put_record(self.artifacts, descriptor)
        if descriptor_ref != binding.execution_harness_id:
            self._fail(HOST_AUTHORITY_UNAVAILABLE,
                       "execution_descriptor_digest_changed")
        scenario_ref = put_record(self.artifacts, scenario_parsed)
        neutral_parser_ref = put_record(self.artifacts, neutral_parsed)
        proposal = plan.program_proposal
        required = tuple(sorted(plan.required_capabilities))
        review = MaterializationReviewManifest(
            candidate_id=plan.candidate_id, plan_ref=plan_ref,
            program_kind=proposal.kind, program_ref=proposal.artifact_ref,
            seed_manifest_ref=proposal.seed_manifest_ref,
            seed_id=proposal.seed_id,
            neutral_program_ref=neutral_program_ref,
            hcap_revision=binding.hcap_revision,
            call_admission_profile_ref=admission.profile_ref,
            neutral_control_catalog_ref=neutral.catalog_ref,
            runtime_selection=plan.runtime_selection,
            execution_harness_id=binding.execution_harness_id,
            scenario_parser_result_ref=scenario_ref,
            neutral_parser_result_ref=neutral_parser_ref,
            required_capability_ids=required,
            selected_capability_ids=selected_capabilities)
        review_ref = put_record(self.artifacts, review)
        harness = ReachabilityHarness(
            candidate_id=plan.candidate_id, plan_ref=plan_ref,
            program_kind=proposal.kind, program_ref=proposal.artifact_ref,
            seed_manifest_ref=proposal.seed_manifest_ref,
            seed_id=proposal.seed_id,
            neutral_program_ref=neutral_program_ref,
            runtime_selection=plan.runtime_selection,
            required_capability_ids=required,
            selected_capability_ids=selected_capabilities,
            q1_observation=plan.q1_observation,
            hcap_revision=binding.hcap_revision,
            call_admission_profile_ref=admission.profile_ref,
            neutral_control_catalog_ref=neutral.catalog_ref,
            execution_harness_id=binding.execution_harness_id,
            scenario_parser_result_ref=scenario_ref,
            neutral_parser_result_ref=neutral_parser_ref,
            review_manifest_sha256=review_ref)
        harness_ref = put_record(self.artifacts, harness)

        # A Materialized value is returned only after every generated artifact
        # has survived canonical reload under its advertised digest.
        if (load_record(self.artifacts, descriptor_ref,
                        ExecutionHarnessDescriptor) != descriptor
                or load_record(self.artifacts, scenario_ref,
                               ParsedProgram) != scenario_parsed
                or load_record(self.artifacts, neutral_parser_ref,
                               ParsedProgram) != neutral_parsed
                or load_record(self.artifacts, review_ref,
                               MaterializationReviewManifest) != review
                or load_record(self.artifacts, harness_ref,
                               ReachabilityHarness) != harness):
            raise ArtifactIntegrityError("materialized artifact reload changed")
        return Materialized(
            harness_ref=harness_ref,
            review_manifest_sha256=review_ref,
            execution_harness_id=binding.execution_harness_id,
            hcap_revision=binding.hcap_revision)

    def harness_authority_current(self, harness_ref: str,
                                  binding: HarnessBinding) -> bool:
        """09 §5: an HCAP-only change keeps a harness whose HCAP-derived
        authority refs are unchanged under the new revision."""
        try:
            harness = load_record(self.artifacts, harness_ref,
                                  ReachabilityHarness)
            if harness.execution_harness_id != binding.execution_harness_id:
                return False
            identity = self._approval(binding).descriptor.syzkaller_identity
            admission = load_call_admission_authority(
                self.artifacts, binding.hcap_revision,
                expected_identity=identity)
            neutral = load_neutral_control_authority(
                self.artifacts, binding.hcap_revision,
                expected_identity=identity)
        except OSError:
            raise
        except (_Failure, *_INVALID_RECORD):
            return False
        return admission.profile_ref == harness.call_admission_profile_ref \
            and neutral.catalog_ref == harness.neutral_control_catalog_ref

    def materialize(self, plan_ref: str, binding: HarnessBinding, *,
                    hcap_authority: MaterializationHcapAuthority | None = None
                    ) -> Materialized | MaterializeRejected:
        try:
            if hcap_authority is None:
                hcap_authority = MaterializationHcapAuthority(
                    effective_hcap_revision=binding.hcap_revision,
                    validation="exact_plan_revision")
            plan = self._load_plan(plan_ref)
            approval = self._approval(binding)
            descriptor = approval.descriptor
            self._runtime(descriptor, plan.runtime_selection)
            catalog = self._hcap(binding, plan, hcap_authority)
            identity = descriptor.syzkaller_identity
            self._seed(plan, catalog, identity)

            try:
                admission = load_call_admission_authority(
                    self.artifacts, binding.hcap_revision,
                    expected_identity=identity)
                neutral = load_neutral_control_authority(
                    self.artifacts, binding.hcap_revision,
                    expected_identity=identity)
                call_table = load_record(
                    self.artifacts, identity.call_table_sha256,
                    SyzkallerCallTable)
            except OSError:
                raise
            except _INVALID_RECORD:
                self._fail(HOST_AUTHORITY_UNAVAILABLE,
                           "invalid_materializer_authority")

            neutral_choice = neutral.select(
                plan.runtime_selection, identity=identity)
            if not neutral_choice.selected:
                if neutral_choice.reason == "neutral_control_unavailable":
                    self._fail(
                        NEUTRAL_CONTROL_UNAVAILABLE,
                        "no exact neutral control runtime selection",
                        profile=plan.runtime_selection.profile)
                self._fail(HOST_AUTHORITY_UNAVAILABLE,
                           "neutral_control_identity_mismatch")
            neutral_required = neutral_choice.required_capability_ids
            if not set(neutral_required) <= set(plan.required_capabilities):
                self._fail(CALL_NOT_ADMITTED,
                           "neutral_capability_not_required_by_plan")

            scenario_bytes = self._program_bytes(
                plan.program_proposal.artifact_ref,
                limit=admission.profile.limits.max_program_bytes,
                role="scenario")
            neutral_bytes = self._program_bytes(
                neutral_choice.program_ref,
                limit=admission.profile.limits.max_program_bytes,
                role="neutral")
            scenario_parsed = self._parse(
                scenario_bytes, plan.program_proposal.artifact_ref,
                role="scenario", identity=identity)
            neutral_parsed = self._parse(
                neutral_bytes, neutral_choice.program_ref,
                role="neutral", identity=identity)
            scenario_caps = self._admit(
                scenario_parsed, role="scenario",
                selection=plan.runtime_selection,
                required_capabilities=plan.required_capabilities,
                authority=admission, call_table=call_table)
            neutral_caps = self._admit(
                neutral_parsed, role="neutral",
                selection=plan.runtime_selection,
                required_capabilities=neutral_required,
                authority=admission, call_table=call_table)
            if not set(neutral_required) <= set(neutral_caps):
                self._fail(CALL_NOT_ADMITTED,
                           "neutral_catalog_capability_not_exercised")
            selected = tuple(sorted(set(scenario_caps) | set(neutral_caps)))
            return self._persist(
                plan_ref=plan_ref, plan=plan, binding=binding,
                descriptor=descriptor, admission=admission,
                neutral=neutral,
                neutral_program_ref=neutral_choice.program_ref,
                scenario_parsed=scenario_parsed,
                neutral_parsed=neutral_parsed,
                selected_capabilities=selected)
        except _Failure as failure:
            return failure.result()
