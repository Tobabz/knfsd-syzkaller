"""Canonical HCAP and declarative Stage 1 plans (04, 05, 07).

Persist these models with ``data.put_record``; the HCAP artifact digest is
its revision, not a self-referential field in the catalog. ``load_record``
verifies the digest, schema and canonical bytes. A trusted harness binding
must choose the revision: content addressing alone does not confer trust.

Scope names are exact, repository-defined coarse labels. They neither
expand wildcards nor duplicate detailed lists owned by authority artifacts.
This component checks declarations and referenced bytes, not syz parsing,
call admission, authority-specific schemas, runtime drift or promotion.
No production catalog or runtime validation evidence is supplied here.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import ConfigDict, Field, JsonValue, model_validator

from .artifacts import ArtifactStore
from .contracts import CandidateLocation, HcapCheck, JudgeVersions, Record, Sha256
from .data import load_record

Text = Annotated[str, Field(min_length=1, pattern=r"\S")]
Identifier = Annotated[
    str, Field(min_length=1, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")]
# Keep the same context semantics as q1.Context so accepted plans can be
# consumed by Q1. A local alias avoids coupling HCAP to the judge module.
Context = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$")]
CapabilityStatus = Literal[
    "validated", "validated_subset", "partially_validated", "experimental"]
NfsVersion = Literal["3", "4.0", "4.1", "4.2"]
AuthorityKind = Literal[
    "CallAdmissionProfile", "RemoteKcovSupportBoundary",
    "Q1AdmissibilityProfile", "PromotedSemanticCapabilityRegistry",
    "NeutralControlCatalog", "NormalFlowSeedManifest"]


class HcapRecord(Record):
    """Strict scalar types; JSON arrays deserialize to immutable tuples."""

    model_config = ConfigDict(strict=True)


def _unique(values: tuple, name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"duplicate {name}")


class AuthorityRef(HcapRecord):
    kind: AuthorityKind
    artifact_ref: Sha256


def _unique_authorities(refs: tuple[AuthorityRef, ...]) -> None:
    _unique(tuple(ref.kind for ref in refs), "authority kind")


class CapabilityInterface(HcapRecord):
    """Descriptions of exposed interfaces, never call admission rules."""

    syz_calls: tuple[Text, ...] = ()
    host_tooling: tuple[Text, ...] = ()
    runtime_features: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> CapabilityInterface:
        for name in ("syz_calls", "host_tooling", "runtime_features"):
            _unique(getattr(self, name), name)
        return self


class Capability(HcapRecord):
    """04 §3 plus explicit coarse scope labels, not inferred support.

    ``scope`` enumerates the uses the repository actually exposes, including
    any experimental uses. ``validated_scope`` identifies a validated subset
    of those labels. For ``validated``, all declared scope is validated.
    Evidence references pin records; this checker does not establish that
    those records substantiate a maintainer's validation claim.
    """

    id: Identifier
    name: Text
    purpose: Text
    usable_stage: tuple[Literal["stage1", "stage2"], ...] = Field(min_length=1)
    # Required, without a legacy fallback or a default consumer.
    usable_by: tuple[Literal[
        "agent_stage1", "agent_stage2", "manual_legacy_campaigns"], ...]
    interface: CapabilityInterface
    inputs: tuple[Text, ...] = ()
    outputs: tuple[Text, ...] = ()
    constraints: tuple[Text, ...] = ()
    status: CapabilityStatus
    scope: tuple[Identifier, ...] = Field(min_length=1)
    validated_scope: tuple[Identifier, ...] = ()
    evidence_refs: tuple[Sha256, ...] = ()
    authority_refs: tuple[AuthorityRef, ...] = ()
    source_refs: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> Capability:
        for name in ("usable_stage", "usable_by", "scope", "validated_scope",
                     "evidence_refs", "source_refs"):
            _unique(getattr(self, name), name)
        _unique_authorities(self.authority_refs)
        if not set(self.validated_scope) <= set(self.scope):
            raise ValueError("validated_scope must be declared in scope")
        if self.status == "validated_subset" and not self.validated_scope:
            raise ValueError("validated_subset requires validated_scope")
        if (self.status == "validated" and self.validated_scope
                and set(self.validated_scope) != set(self.scope)):
            raise ValueError("validated must cover all declared scope")
        return self


class HcapCatalog(HcapRecord):
    """04 §1.1: one immutable catalog and an exact missing-ID vocabulary.

    The vocabulary does not implicitly include capability IDs, namespace
    prefixes or arbitrary kernel commits. Each permissible gap ID must be
    explicitly present in this revision. Multiple capabilities can refer to
    the same authority, but cannot pin different digests for its kind.
    """

    schema_version: Literal["hcap.v1"] = "hcap.v1"
    capabilities: tuple[Capability, ...]
    missing_capability_ids: tuple[Identifier, ...]
    authority_refs: tuple[AuthorityRef, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> HcapCatalog:
        _unique(tuple(cap.id for cap in self.capabilities), "capability ID")
        _unique(self.missing_capability_ids, "missing capability ID")
        _unique_authorities(self.authority_refs)
        by_kind: dict[str, str] = {}
        refs = (*self.authority_refs,
                *(ref for cap in self.capabilities for ref in cap.authority_refs))
        for ref in refs:
            previous = by_kind.setdefault(ref.kind, ref.artifact_ref)
            if previous != ref.artifact_ref:
                raise ValueError(f"conflicting authority kind: {ref.kind}")
        return self


class CapabilityUse(HcapRecord):
    """Explicit status/scope declaration for each required capability.

    ``unvalidated_scope`` must name precisely the requested out-of-subset
    labels. For experimental/partially_validated entries it must name every
    requested label, acknowledging the entry's validation status as well.
    It cannot grant a scope absent from the catalog.
    """

    capability_id: Identifier
    status: CapabilityStatus
    scope: tuple[Identifier, ...] = Field(min_length=1)
    unvalidated_scope: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> CapabilityUse:
        _unique(self.scope, "requested scope")
        _unique(self.unvalidated_scope, "unvalidated scope")
        if not set(self.unvalidated_scope) <= set(self.scope):
            raise ValueError("unvalidated_scope must be a requested scope")
        return self


class SelectedPath(HcapRecord):
    entry_surface: Text
    path_summary: Text
    required_state: tuple[Text, ...] = ()


class ScenarioStep(HcapRecord):
    """Review-only description; no component executes action/parameters."""

    capability_id: Identifier
    action: Text
    parameters: dict[str, JsonValue] = Field(default_factory=dict)
    expected_state_change: Text


class Q1Observation(HcapRecord):
    target: CandidateLocation
    expected_context: Context
    capability_id: Identifier
    oracle: Literal["remote_kcov"] = "remote_kcov"
    success_condition: Literal[
        "target_pc_in_generation_attributed_remote_coverage"
    ] = "target_pc_in_generation_attributed_remote_coverage"


class ProgramProposal(HcapRecord):
    """Bytes for later Materializer validation, including seeds (05 §11)."""

    kind: Literal["program", "seed"]
    artifact_ref: Sha256
    seed_manifest_ref: Sha256 | None = None
    seed_id: Identifier | None = None

    @model_validator(mode="after")
    def _shape(self) -> ProgramProposal:
        if self.kind == "seed":
            if self.seed_manifest_ref is None or self.seed_id is None:
                raise ValueError("seed requires manifest reference and seed ID")
        elif self.seed_manifest_ref is not None or self.seed_id is not None:
            raise ValueError("seed provenance is only permitted for a seed")
        return self


class RuntimeSelection(HcapRecord):
    """05 §10 allowlist; program selection lives in ProgramProposal.

    No sanitizer, timeouts, retries, resource policy or environment override
    is accepted. Route/profile strings are selections, not support claims;
    consistency with the actual fixture remains Materializer's task.
    """

    profile: Identifier
    nfs_version: NfsVersion
    fixture_mode: Literal["single", "broad-knfsd"]
    route: Identifier
    topology: Identifier
    enabled_interfaces: tuple[Text, ...]
    trace_mode: Literal["off", "on"] = "off"

    @model_validator(mode="after")
    def _shape(self) -> RuntimeSelection:
        _unique(self.enabled_interfaces, "enabled interface")
        return self


class ExecutionConstraint(HcapRecord):
    description: Text


class ReachabilityPlan(HcapRecord):
    """05: declarations only, not an executable or admitted harness.

    Q1 adapters read candidate_id, q1_observation.target (CandidateLocation)
    and q1_observation.expected_context after canonical load_record().
    """

    schema_version: Literal["reachability-plan.v1"] = "reachability-plan.v1"
    candidate_id: Text
    hcap_revision: Sha256
    selected_path: SelectedPath
    nfs_version: NfsVersion
    scenario_steps: tuple[ScenarioStep, ...] = Field(min_length=1)
    required_capabilities: tuple[Identifier, ...] = Field(min_length=1)
    capability_uses: tuple[CapabilityUse, ...] = Field(min_length=1)
    q1_observation: Q1Observation
    program_proposal: ProgramProposal
    runtime_selection: RuntimeSelection
    execution_constraints: tuple[ExecutionConstraint, ...] = ()
    uncertainties: tuple[Text, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> ReachabilityPlan:
        _unique(self.required_capabilities, "required capability ID")
        uses = tuple(use.capability_id for use in self.capability_uses)
        _unique(uses, "capability use ID")
        required = set(self.required_capabilities)
        if set(uses) != required:
            raise ValueError("each required capability needs exactly one use")
        if any(step.capability_id not in required for step in self.scenario_steps):
            raise ValueError("scenario step references a non-required capability")
        if self.q1_observation.capability_id not in required:
            raise ValueError("Q1 oracle must reference a required capability")
        if self.nfs_version != self.runtime_selection.nfs_version:
            raise ValueError("plan and runtime NFS versions differ")
        return self


_ARTIFACT_ERRORS = (OSError, ValueError, TypeError, RecursionError)


def _check_ref(ref: str) -> None:
    # ArtifactStore assumes valid digests; validate before touching its path.
    if not isinstance(ref, str) or re.fullmatch(r"[0-9a-f]{64}", ref) is None:
        raise ValueError("artifact reference must be a lowercase SHA-256 digest")


class ArtifactHcapChecker:
    """components.HcapChecker over content-addressed, canonical artifacts.

    Failures produce stable violations (or False for vocabulary checks),
    including missing/corrupt dependencies. There is no mutable catalog
    cache: repeated calls revalidate bytes. Authority/evidence bytes are
    checked for integrity only, never interpreted as promotion or admission.
    """

    def __init__(self, store: ArtifactStore) -> None:
        self.store = store

    def _verify_artifact(self, ref: str) -> None:
        _check_ref(ref)
        self.store.get(ref)

    def load_catalog(self, revision: str) -> HcapCatalog:
        """Load a pinned catalog and verify its direct dependencies.

        Invalid references/schema/canonical bytes raise ValueError; missing
        or unreadable files raise OSError. This does not approve the catalog
        or validate the authority-specific schemas of its dependencies.
        """
        _check_ref(revision)
        catalog = load_record(self.store, revision, HcapCatalog)
        refs = {ref.artifact_ref for ref in catalog.authority_refs}
        for capability in catalog.capabilities:
            refs.update(ref.artifact_ref for ref in capability.authority_refs)
            refs.update(capability.evidence_refs)
        for ref in sorted(refs):
            self._verify_artifact(ref)
        return catalog

    def knows_capability(self, hcap_revision: str,
                         missing_capability_id: str) -> bool:
        if not isinstance(missing_capability_id, str):
            return False
        try:
            catalog = self.load_catalog(hcap_revision)
        except _ARTIFACT_ERRORS:
            return False
        return missing_capability_id in catalog.missing_capability_ids

    def judge_versions(self, hcap_revision: str) -> JudgeVersions | None:
        """Select the Q1 authorities approved with a harness's HCAP.

        Catalogs predating these authority references use the Controller's
        configured default. A partial Q1 authority pair is ambiguous and is
        therefore rejected instead of being combined with an unrelated
        default.
        """
        catalog = self.load_catalog(hcap_revision)
        refs = (*catalog.authority_refs,
                *(ref for capability in catalog.capabilities
                  for ref in capability.authority_refs))
        by_kind = {ref.kind: ref.artifact_ref for ref in refs}
        profile = by_kind.get("Q1AdmissibilityProfile")
        boundary = by_kind.get("RemoteKcovSupportBoundary")
        if profile is None and boundary is None:
            return None
        if profile is None or boundary is None:
            raise ValueError("HCAP must pin both Q1 authority artifacts")
        return JudgeVersions(judge_profile_id=profile,
                             support_boundary_id=boundary)

    def _check_plan(self, plan_ref: str, hcap_revision: str, *,
                    require_revision: bool) -> HcapCheck:
        # A missing or unreadable artifact is a host availability failure:
        # OSError propagates, like the Materializer's, so the caller keeps
        # the pending work and retries. Invalid catalog bytes are a host
        # integrity failure, not an Agent repair finding.
        try:
            catalog = self.load_catalog(hcap_revision)
        except OSError:
            raise
        except _ARTIFACT_ERRORS:
            return HcapCheck(violations=("invalid_hcap_artifact",),
                             host_authority=True)
        try:
            _check_ref(plan_ref)
            plan = load_record(self.store, plan_ref, ReachabilityPlan)
        except OSError:
            raise
        except _ARTIFACT_ERRORS:
            return HcapCheck(violations=("invalid_plan_artifact",))
        proposal = plan.program_proposal
        try:
            self._verify_artifact(proposal.artifact_ref)
            if proposal.seed_manifest_ref is not None:
                self._verify_artifact(proposal.seed_manifest_ref)
        except FileNotFoundError:
            # An inline program was stored by the executor, and a seed the
            # host's trusted manifest lists is a host artifact: their
            # absence is the host's.  Any other seed reference is one the
            # Agent proposed, so one that does not exist is a plan finding.
            if proposal.kind != "seed" or self._trusted_seed(catalog,
                                                              proposal):
                raise
            return HcapCheck(violations=("seed_reference_not_found",))
        except OSError:
            raise
        except _ARTIFACT_ERRORS:
            return HcapCheck(violations=("invalid_plan_artifact",))

        violations: list[str] = []
        if require_revision and plan.hcap_revision != hcap_revision:
            violations.append("hcap_revision_mismatch")
        by_id = {cap.id: cap for cap in catalog.capabilities}
        interfaces: set[str] = set()
        for use in plan.capability_uses:
            cap = by_id.get(use.capability_id)
            if cap is None:
                violations.append(f"unknown_capability:{use.capability_id}")
                continue
            if "agent_stage1" not in cap.usable_by:
                violations.append(f"not_usable_by_agent_stage1:{cap.id}")
            if "stage1" not in cap.usable_stage:
                violations.append(f"not_usable_in_stage1:{cap.id}")
            if use.status != cap.status:
                violations.append(f"capability_status_mismatch:{cap.id}")
            for scope in sorted(set(use.scope) - set(cap.scope)):
                violations.append(f"undeclared_scope:{cap.id}:{scope}")
            if cap.status == "validated":
                unvalidated: set[str] = set()
            elif cap.status == "validated_subset":
                unvalidated = set(use.scope) - set(cap.validated_scope)
            else:
                unvalidated = set(use.scope)
            if set(use.unvalidated_scope) != unvalidated:
                violations.append(f"unvalidated_scope_not_explicit:{cap.id}")
            # Exact interface descriptions only, no wildcard expansion and
            # no host_tooling. Actual program calls need CallAdmissionProfile.
            interfaces.update(cap.interface.syz_calls)
            interfaces.update(cap.interface.runtime_features)
        for interface in plan.runtime_selection.enabled_interfaces:
            if interface not in interfaces:
                violations.append(f"interface_not_declared:{interface}")
        return HcapCheck(violations=tuple(violations))

    def _trusted_seed(self, catalog: HcapCatalog,
                      proposal: ProgramProposal) -> bool:
        """True if the catalog's one NormalFlowSeedManifest is the proposal's
        and lists its seed_id with exactly its program."""
        from .materializer import NormalFlowSeedManifest  # import cycle

        trusted = {
            ref.artifact_ref
            for ref in (*catalog.authority_refs,
                        *(ref for capability in catalog.capabilities
                          for ref in capability.authority_refs))
            if ref.kind == "NormalFlowSeedManifest"
        }
        if trusted != {proposal.seed_manifest_ref}:
            return False
        try:
            manifest = load_record(self.store, proposal.seed_manifest_ref,
                                   NormalFlowSeedManifest)
        except OSError:
            raise
        except _ARTIFACT_ERRORS:
            return False
        return any(seed.seed_id == proposal.seed_id
                   and seed.program_ref == proposal.artifact_ref
                   for seed in manifest.seeds)

    def check_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        """Validate a newly submitted Agent plan, including its revision."""
        return self._check_plan(plan_ref, hcap_revision,
                                require_revision=True)

    def revalidate_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        """Validate stored plan semantics against a replacement catalog."""
        return self._check_plan(plan_ref, hcap_revision,
                                require_revision=False)
