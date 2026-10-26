"""Generate every host record ``stage1.json`` references, from one spec.

Inputs are the operator's statements (capabilities, call admission source,
neutral programs, runtime selections, Q1 profile, model policy) and the
host's build outputs (``tools/bootstrap-kcov-env.py`` env directory and the
``tools/syzkaller/build.py`` parser bundle).  Output, all in
``artifact_root`` and ``state_dir``:

* pins of the kernel, image, lane script and syzkaller binaries, and the
  KCOV instrumentation manifest (kernel patch series and .config);
* the syzkaller identity graph, CallAdmissionProfile, NeutralControlCatalog,
  Q1AdmissibilityProfile, RemoteKcovSupportBoundary and the HCAP that pins
  them;
* the ExecutionHarnessDescriptor, its approval and the HarnessCatalog;
  with several ``variants`` (sanitizers, #81 D10) one of each per
  variant: its kernel, instrumentation, descriptor, KVM evidence, support
  boundary, HCAP revision and binding, while the syzkaller identity,
  admission profile, neutral controls and judge profile are shared;
* ``stage1.json`` (service config), ``collector.json`` (host command
  config) and ``generated.json`` (every digest, for the record).
* with a ``stage2`` section (#81 D17), the Stage 2 syz-manager config of
  each variant (``stage2-manager.json``) and its frozen lane template.

Generation checks the cross-record rules the service enforces later, so a
wrong spec fails here and not in the middle of a run.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ...admission import (NeutralControlCatalog, NeutralControlEntry,
                          SyzkallerBuildManifest, SyzkallerCallTable,
                          SyzkallerTargetIdentity, _neutral_key)
from ...admission_generation import (AdmissionProfileSource,
                                     PinnedSyzkallerInputs,
                                     generate_call_admission_profile)
from ...artifacts import ArtifactStore
from ...contracts import (PIPELINE_GAP_IDS, CampaignMode, HarnessBinding,
                          JobPolicy, JudgeVersions, Sanitizer, Sha256)
from ...data import canonical_json, put_record
from ...hcap import (STAGE1_LAYOUT, AuthorityRef, Capability, ExecutionLayout,
                      GapContract, HcapCatalog, RuntimeSelection,
                      calls_in_layout, layout_refusals)
from ...materializer import (ExecutionHarnessApproval,
                             ExecutionHarnessDescriptor, HarnessBuildArtifact,
                             _runtime_key, descriptor_id)
from ...promotion import (PromotionProbeEvidence,
                          argument_generality_refusals,
                          gap_contract_refusals, promotion_refusals)
from ...q1 import (KernelIdentity, Q1AdmissibilityProfile,
                   RemoteKcovSupportBoundary)
from ...qemu_accel import Accel, AccelChoice, resolve, slowdown
from ...qemu_accel import qemu_args as accel_qemu_args
from ...registry import HarnessCatalog, HarnessRegistration
from ..config import EngineConfig, SlotsConfig, Stage1Config
from .collector import CollectorConfig, guest_cmdline
from .pins import InstrumentationManifest, file_sha256, pin_file

REPO = Path(__file__).resolve().parents[3]
DEFAULT_CMDLINE = "root=/dev/sda console=ttyS0 nokaslr nfs.localio_enabled=N"


class GenerationError(ValueError):
    pass


class _Spec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class NeutralControlSpec(_Spec):
    runtime_selection: RuntimeSelection
    program: Path
    required_capability_ids: tuple[str, ...]


class BoundarySpec(_Spec):
    name: str
    revision: str
    supported_contexts: tuple[str, ...]


class EngineSpec(_Spec):
    resource_key: str = "kvm-lane-0"
    timeout_s: float = 1800
    max_output_bytes: int = 1_048_576
    #: The KVM slot pool (09 §8): a guest is the collector's cpus and
    #: memory, and the host keeps this much for itself.
    reserve_cpus: int = Field(default=2, ge=0)
    reserve_memory_mb: int = Field(default=4096, ge=0)
    max_slots: int | None = Field(default=None, ge=1, le=256)


class CollectorSpec(_Spec):
    qemu: str = "qemu-system-x86_64"
    #: ``auto`` uses KVM when the generating host can open ``/dev/kvm``
    #: and TCG otherwise.  The timeouts here are KVM-speed budgets: under
    #: TCG the boot, fixture and engine budgets and the execprog slowdown
    #: are scaled by ``qemu_accel.TCG_SLOWDOWN``.
    accel: AccelChoice = "auto"
    memory_mb: int = 4096
    cpus: int = 4
    boot_timeout_s: float = 300
    fixture_timeout_s: float = 180
    grace_s: float = 11
    drain_s: float = 10
    exec_timeout_s: float = 600


HCAP11_PROBES = ("break_deleg", "create_session", "exchange_id")


class Hcap11ProbeHits(_Spec):
    """Per-run counts of attributed PCs in each public probe range."""

    #: nfsd_break_deleg_cb: client1's OPEN recalls the write delegation of
    #: the courtesy client0 and marks it expirable.
    break_deleg: tuple[int, ...]
    #: nfsd4_create_session: client0's recovered session.
    create_session: tuple[int, ...]
    #: nfsd4_exchange_id: client0's recovered client record.
    exchange_id: tuple[int, ...]

    def each(self, name: str) -> tuple[int, ...]:
        return getattr(self, name)


class Hcap11RunEvidence(_Spec):
    completed: int = Field(ge=3, le=999)
    probe_hits: Hcap11ProbeHits
    #: lane.sh status passed (both clients mounted, link up) after every run.
    status_checks_passed: int = Field(ge=0)
    #: Generation contract held for every run.
    attributed_generations: int = Field(ge=0)

    @model_validator(mode="after")
    def _count(self) -> Self:
        for name in HCAP11_PROBES:
            if len(self.probe_hits.each(name)) != self.completed:
                raise ValueError(f"{name} length differs from completed")
        if self.status_checks_passed != self.completed:
            raise ValueError("a run left the lane fixture unhealthy")
        if self.attributed_generations != self.completed:
            raise ValueError("a run lacks one attributed generation")
        return self


class Hcap11RunsEvidence(_Spec):
    #: Neutral control: client0 lane I/O, no lock, partition or recovery.
    control: Hcap11RunEvidence
    #: client0 read-write open, partition past the lease, client1 open of
    #: the same file, heal, client0 I/O.
    stimulus: Hcap11RunEvidence


class Hcap11GenerationEvidence(_Spec):
    generation_begin_each: Literal[1]
    aggregate_published_each: Literal[1]
    generation_aborted_each: Literal[0]
    scratch_overflow_each: Literal[0]
    merge_truncation_each: Literal[0]
    outstanding_tokens_after_each: Literal[0]
    remote_refs_after_each: Literal[0]
    minimum_remote_start_ok: int = Field(ge=1)


#: Server trace order of one validated stimulus run: client1's OPEN
#: recalls the write delegation of the courtesy client0, the laundromat
#: expires and purges client0 and the OPEN is granted; then client0, healed,
#: recovers with a fresh EXCHANGE_ID and a CREATE_SESSION that confirms the
#: new client.
HCAP11_RECOVERY_ORDER = (
    "nfsd_cb_recall", "nfsd_mark_client_expired", "nfsd_clid_purged",
    "OP_OPEN", "nfsd_clid_fresh", "OP_EXCHANGE_ID",
    "nfsd_slot_seqid_unconf", "nfsd_clid_confirmed", "OP_CREATE_SESSION",
)
#: The single fixture's NFSv4 lease and the partition that outlasts it
#: (syzkaller patch 0032).
HCAP11_LEASE_TIME_S = 10
HCAP11_PARTITION_HOLD_S = 15


class Hcap11KvmEvidence(_Spec):
    schema_version: Literal["hcap-kvm-evidence.v1"]
    capability_id: Literal["HCAP-11"]
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    scenario: Literal["v41-courtesy-expiry"]
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    #: Digest of each public probe mapping, keyed by probe name.
    probe_mapping_sha256: dict[str, Sha256]
    campaign_result_sha256: Sha256
    guest_lane_script_sha256: Sha256
    guest_nfs_proxy_sha256: Sha256
    nfsv4_lease_time_s: Literal[10]
    partition_hold_s: Literal[15]
    #: The Stage 1 collector's layout: one proc on lane 0.
    layout: ExecutionLayout
    runs: Hcap11RunsEvidence
    generation_contract: Hcap11GenerationEvidence
    recovery_order: tuple[str, ...]
    crash_signature_count: int = Field(ge=0)
    raw_artifact_error_count: int = Field(ge=0)
    shareable_result_contains_target_metadata_or_addresses: bool

    @model_validator(mode="after")
    def _validated_campaign(self) -> Self:
        if self.execution_harness_id != self.mapping_identity.execution_harness_id:
            raise ValueError("mapping and campaign harness identities differ")
        if tuple(sorted(self.probe_mapping_sha256)) != HCAP11_PROBES:
            raise ValueError("probe mappings differ from the HCAP-11 probe set")
        control = self.runs.control.probe_hits
        if any(any(control.each(name)) for name in HCAP11_PROBES):
            raise ValueError("control run reached an HCAP-11 probe")
        stimulus = self.runs.stimulus.probe_hits
        for name in HCAP11_PROBES:
            if not all(stimulus.each(name)):
                raise ValueError(f"stimulus run missed {name}")
        if self.recovery_order != HCAP11_RECOVERY_ORDER:
            raise ValueError("recovery order differs from the validated contract")
        if self.crash_signature_count != 0 or self.raw_artifact_error_count != 0:
            raise ValueError("campaign contains a crash or artifact error")
        if self.shareable_result_contains_target_metadata_or_addresses:
            raise ValueError("shareable campaign evidence contains private target data")
        return self


HCAP13_PROBES = ("clnt_grant", "svc_grant_blocked", "svc_grant_callback",
                 "svc_lock", "svc_share", "svc_testlock", "svc_unlock")
#: Probes that only a granted blocked lock reaches.
HCAP13_GRANT_PROBES = ("clnt_grant", "svc_grant_blocked", "svc_grant_callback")


class Hcap13ProbeHits(_Spec):
    """Per-run counts of attributed PCs in each public lockd probe range."""

    clnt_grant: tuple[int, ...]
    #: The server lockd thread grants the blocked lock (lockd context).
    svc_grant_blocked: tuple[int, ...]
    #: rpciod completes the GRANTED_MSG callback (lockd context).
    svc_grant_callback: tuple[int, ...]
    svc_lock: tuple[int, ...]
    svc_share: tuple[int, ...]
    svc_testlock: tuple[int, ...]
    svc_unlock: tuple[int, ...]

    def each(self, name: str) -> tuple[int, ...]:
        return getattr(self, name)


class Hcap13RunEvidence(_Spec):
    completed: int = Field(ge=3, le=999)
    probe_hits: Hcap13ProbeHits
    #: lane.sh status passed (lockd and rpc.statd registered in every lane
    #: namespace, knfsd mounts lock) after every run.
    status_checks_passed: int = Field(ge=0)
    #: Generation contract held for every run (HCAP-11 invariants).
    attributed_generations: int = Field(ge=0)

    @model_validator(mode="after")
    def _count(self) -> Self:
        for name in HCAP13_PROBES:
            if len(self.probe_hits.each(name)) != self.completed:
                raise ValueError(f"{name} length differs from completed")
        if self.status_checks_passed != self.completed:
            raise ValueError("a run left the lane fixture unhealthy")
        if self.attributed_generations != self.completed:
            raise ValueError("a run lacks one attributed generation")
        return self


class Hcap13RunsEvidence(_Spec):
    #: Neutral control: lane I/O on the NLM fixture, no lock.
    control: Hcap13RunEvidence
    #: Kernel NFS client byte-range lock, test and unlock (fcntl$lock).
    lock: Hcap13RunEvidence
    #: Raw NLM LOCK, TEST, UNLOCK, SHARE and UNSHARE (syz_send_nlm_rpc).
    rpc: Hcap13RunEvidence
    #: Raw blocking LOCK behind a client1 lock; its release makes the server
    #: lockd thread grant it with a GRANTED_MSG callback, run by rpciod, to
    #: the client0 lockd.
    blocked: Hcap13RunEvidence


#: Probes each phase must reach in every run; the control reaches none.
HCAP13_REQUIRED_PROBES = {
    "lock": ("svc_lock", "svc_unlock"),
    "rpc": ("svc_lock", "svc_share", "svc_testlock", "svc_unlock"),
    "blocked": ("clnt_grant", "svc_grant_blocked", "svc_grant_callback",
                "svc_lock", "svc_unlock"),
}


class Hcap13KvmEvidence(_Spec):
    schema_version: Literal["hcap-kvm-evidence.v1"]
    capability_id: Literal["HCAP-13"]
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    scenario: Literal["v3-nlm-lock"]
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    #: Digest of each public probe mapping, keyed by probe name.
    probe_mapping_sha256: dict[str, Sha256]
    campaign_result_sha256: Sha256
    guest_lane_script_sha256: Sha256
    guest_nfs_proxy_sha256: Sha256
    #: The Stage 1 collector's layout: one proc on lane 0.
    layout: ExecutionLayout
    runs: Hcap13RunsEvidence
    generation_contract: Hcap11GenerationEvidence
    crash_signature_count: int = Field(ge=0)
    raw_artifact_error_count: int = Field(ge=0)
    shareable_result_contains_target_metadata_or_addresses: bool

    @model_validator(mode="after")
    def _validated_campaign(self) -> Self:
        if self.execution_harness_id != self.mapping_identity.execution_harness_id:
            raise ValueError("mapping and campaign harness identities differ")
        if tuple(sorted(self.probe_mapping_sha256)) != HCAP13_PROBES:
            raise ValueError("probe mappings differ from the lockd probe set")
        hits = self.runs.control.probe_hits
        if any(any(hits.each(name)) for name in HCAP13_PROBES):
            raise ValueError("control run reached a lockd probe")
        for phase, names in HCAP13_REQUIRED_PROBES.items():
            run = getattr(self.runs, phase)
            for name in names:
                if not all(run.probe_hits.each(name)):
                    raise ValueError(f"{phase} run missed {name}")
        if any(any(self.runs.lock.probe_hits.each(name))
               for name in HCAP13_GRANT_PROBES):
            raise ValueError("lock run reached a grant callback")
        if self.crash_signature_count != 0 or self.raw_artifact_error_count != 0:
            raise ValueError("campaign contains a crash or artifact error")
        if self.shareable_result_contains_target_metadata_or_addresses:
            raise ValueError("shareable campaign evidence contains private target data")
        return self


#: Capabilities one lane-topology campaign validates together: the lane
#: syscalls it runs on every lane, their remote-KCOV generation attribution
#: and the topology itself.
LANE_TOPOLOGY_CAPABILITIES = ("HCAP-01", "HCAP-03", "HCAP-04")
#: Fewest generation-attributed campaign executions each lane must have.
LANE_TOPOLOGY_MIN_EXECUTIONS = 8
# Digest of tools/nfs-lifecycle/programs/v41-client-io-topology.prog.
LANE_TOPOLOGY_PROGRAM_SHA256 = (
    "6a25622bc0e62701ec80a40de47f846d2b1e61827a987a294e023fcd6d6c7d25")


class LaneTopologyLane(_Spec):
    """One lane of a lane-topology campaign (``agent_pipeline.stage2.topology``)."""

    lane: int = Field(ge=0)
    #: Campaign executions syz-manager's evidence spool recorded on the lane.
    executions: int = Field(ge=0)
    #: Of those, executions with a remote-KCOV generation and attributed PCs.
    attributed_executions: int = Field(ge=0)
    #: Distinct generations among them (a reused one is a restart).
    distinct_generations: int = Field(ge=0)
    #: Executions whose NFS proxy activation and deactivation were acked.
    proxy_acked_executions: int = Field(ge=0)
    #: Executions that ran, cleared their lease, did not hang and had no error.
    healthy_executions: int = Field(ge=0)
    #: GENERATION_OPEN events on the lane's own journal channel.
    journal_generations: int = Field(ge=0)
    #: Attributed generations with no GENERATION_OPEN on the lane's channel.
    generations_missing_from_journal: int = Field(ge=0)
    #: Journal events on the lane's channel that name another lane or
    #: belong to another lane's session series.
    foreign_journal_events: int = Field(ge=0)


class LaneTopologyEvidence(_Spec):
    """A bounded Stage 2 manager campaign at ``layout.procs`` procs (#99):
    every lane has its own generation-attributed remote KCOV, NFS proxy
    activation and journal stream, and nothing is attributed across lanes."""

    schema_version: Literal["hcap-kvm-evidence.v1"]
    capability_id: Literal["HCAP-04"]
    #: The capabilities this campaign validates, LANE_TOPOLOGY_CAPABILITIES.
    capability_ids: tuple[str, ...]
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    scenario: Literal["stage2-lane-topology"]
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    campaign_result_sha256: Sha256
    program_sha256: Sha256
    guest_lane_script_sha256: Sha256
    layout: ExecutionLayout
    min_executions_per_lane: int = Field(ge=LANE_TOPOLOGY_MIN_EXECUTIONS)
    lanes: tuple[LaneTopologyLane, ...]
    manager_exited_unexpectedly: bool
    crash_signature_count: int = Field(ge=0)
    shareable_result_contains_target_metadata_or_addresses: bool

    @model_validator(mode="after")
    def _validated_campaign(self) -> Self:
        if self.execution_harness_id != self.mapping_identity.execution_harness_id:
            raise ValueError("mapping and campaign harness identities differ")
        if self.capability_ids != LANE_TOPOLOGY_CAPABILITIES:
            raise ValueError("lane-topology evidence names other capabilities")
        if self.program_sha256 != LANE_TOPOLOGY_PROGRAM_SHA256:
            raise ValueError(
                "lane-topology evidence did not use the trusted "
                "lane-topology corpus")
        if self.layout.lanes != tuple(range(self.layout.procs)):
            raise ValueError("a lane-topology campaign exercises every lane "
                             "of its procs")
        if tuple(item.lane for item in self.lanes) != self.layout.lanes:
            raise ValueError("lane results differ from the layout")
        for item in self.lanes:
            if item.executions < self.min_executions_per_lane:
                raise ValueError(f"lane {item.lane} ran too few executions")
            if not (item.executions == item.attributed_executions
                    == item.distinct_generations
                    == item.proxy_acked_executions
                    == item.healthy_executions):
                raise ValueError(f"lane {item.lane} has an unattributed, "
                                 "repeated, unacked or unhealthy execution")
            if item.journal_generations < item.distinct_generations or \
                    item.generations_missing_from_journal:
                raise ValueError(f"lane {item.lane} journal lacks a generation")
            if item.foreign_journal_events:
                raise ValueError(f"lane {item.lane} journal has another "
                                 "lane's events")
        if self.manager_exited_unexpectedly or self.crash_signature_count:
            raise ValueError("campaign contains a crash or a manager exit")
        if self.shareable_result_contains_target_metadata_or_addresses:
            raise ValueError("shareable campaign evidence contains private target data")
        return self


class Stage2ManagerSpec(_Spec):
    """``stage2``: the syz-manager config a Stage 2 lease runs (#81 D17).
    Generation writes it from each variant's descriptor, so its kernel,
    image, lane script, syzkaller binaries, command line, SSH key and QEMU
    are the ones the Stage 1 collector runs."""

    #: The runtime selection the manager boots; it may be left out when
    #: the spec has one.  A Stage 2 lease checks it against its harness.
    runtime_selection: RuntimeSelection | None = None
    #: Left out, the procs ``runtime_selection_capability`` (HCAP-04) is
    #: validated for: its ``validated_layout`` (#99), one proc without it.
    #: Given, it must not exceed them.
    procs: int | None = Field(default=None, ge=1, le=64)
    #: ``experimental.nfs_proxy_window``; the Stage 2 preflight requires
    #: at least ``Stage2Config.crash_window_bound``.
    nfs_proxy_window: int = Field(default=6, ge=1, le=64)
    #: Calls the manager enables.  Left out, they are the approved calls:
    #: every admitted call and every call a runtime selection enables.
    #: Given, they must include all of them.
    enable_syscalls: tuple[str, ...] | None = None


class VariantSpec(_Spec):
    """One sanitizer build of the shared harness (#81 D10).  Its kernel is
    ``env_dir/images/<sanitizer>``; capability evidence is pinned to its
    own descriptor, so each variant names the KVM evidence collected on
    it."""

    sanitizer: Sanitizer
    capability_evidence: dict[str, tuple[Path, ...]] = Field(
        default_factory=dict)


CAPABILITY_EVIDENCE_MODELS = {
    **{capability_id: LaneTopologyEvidence
       for capability_id in LANE_TOPOLOGY_CAPABILITIES},
    "HCAP-11": Hcap11KvmEvidence,
    "HCAP-13": Hcap13KvmEvidence,
}


class HostSpec(_Spec):
    """``host-spec.json``; relative paths are relative to the spec file."""

    schema_version: str = Field("stage1-host-spec.v1",
                                pattern=r"^stage1-host-spec\.v1$")
    state_dir: Path
    artifact_root: Path
    #: ``tools/bootstrap-kcov-env.py`` TARGET_DIR.
    env_dir: Path
    #: The single variant of a spec without ``variants``.
    variant: Sanitizer = Sanitizer.KASAN
    #: Several sanitizer variants of the same harness; the first is the
    #: default the host tools use.  Each carries its own capability
    #: evidence, so the top-level ``capability_evidence`` stays empty.
    variants: tuple[VariantSpec, ...] = ()
    ssh_key: Path
    #: The ``bundle`` directory written by ``tools/syzkaller/build.py``;
    #: its sibling ``checkout`` is the patched syzkaller tree it built.
    syzkaller_bundle: Path
    guest_kernel_command_line: str = DEFAULT_CMDLINE
    capabilities: tuple[Capability, ...] = Field(min_length=1)
    #: Capability ID -> repository evidence files to store and bind into the
    #: generated HCAP catalog. Paths are relative to this spec.
    capability_evidence: dict[str, tuple[Path, ...]] = Field(
        default_factory=dict)
    #: The contract each gap ID's capability must declare (04 §3.3).
    gap_contracts: tuple[GapContract, ...] = ()
    #: The capability whose constraints list the allowed runtime selections.
    #: The Agent reads capabilities through its HCAP lookup tool and must
    #: plan with one of these selections exactly.
    runtime_selection_capability: str | None = None
    missing_capability_ids: tuple[str, ...] = ()
    admission_source: AdmissionProfileSource
    runtime_selections: tuple[RuntimeSelection, ...] = Field(min_length=1)
    neutral_controls: tuple[NeutralControlSpec, ...] = Field(min_length=1)
    judge_profile: Q1AdmissibilityProfile
    support_boundary: BoundarySpec
    policies: tuple[JobPolicy, ...] = Field(min_length=1)
    engine: EngineSpec = EngineSpec()
    collector: CollectorSpec = CollectorSpec()
    stage2: Stage2ManagerSpec | None = None

    @model_validator(mode="after")
    def _variants(self) -> Self:
        if not self.variants:
            return self
        if "variant" in self.model_fields_set:
            raise ValueError("give variant or variants, not both")
        if self.capability_evidence:
            raise ValueError("with variants, capability_evidence belongs "
                             "to each variant (it is pinned to its "
                             "descriptor)")
        names = [v.sanitizer for v in self.variants]
        if len(set(names)) != len(names):
            raise ValueError("a sanitizer is listed twice in variants")
        return self

    def variant_specs(self) -> tuple[VariantSpec, ...]:
        return self.variants or (VariantSpec(
            sanitizer=self.variant,
            capability_evidence=self.capability_evidence),)


def capability_baseline_sha256(capability: Capability) -> str:
    """The digest ``legacy_capabilities`` pins: the spec entry without its
    validated layout, which lane-topology evidence widens on its own (#99),
    and without generated evidence references."""
    entry = capability.model_dump(
        mode="json", exclude={"validated_layout", "evidence_refs"})
    return hashlib.sha256(canonical_json(entry)).hexdigest()


#: ``capability_baseline_sha256`` of each capability promoted before the
#: promotion criteria (#100), as the checked-in specs declare it
#: (``template/host-spec.json``, ``stage1-host-live/host-spec.json``).  The
#: repository pins them here, so a spec cannot exempt a capability itself.
LEGACY_CAPABILITY_BASELINES: dict[str, frozenset[str]] = {
    "HCAP-01": frozenset({
        "7eda8c8105255246dfd25dc06c65e42461d88782000497f41a969d20ef7a9ff3",
    }),
    "HCAP-03": frozenset({
        "bd33c79879dfaddb358acf7bb2ffbd8c0d00c604c52645adb07b0fb777518eee",
    }),
    "HCAP-04": frozenset({
        "023a636701aeec882c157de3fe6024e4e2476fa4eca18b0d943e4b5b8fb254cb",
        "c9f8ff612235085419c3b91c8acae70322fe0a85719134e10aece2d2528502b1",
        "9ef22b8308adc7b81b43d10bb733ac430316ae923163560d43f85a35c8699f85",
    }),
    "HCAP-11": frozenset({
        "7315aeedfeb596d88a56e6006008175e53fbd88406c7607a6e2709c11e317f6e",
    }),
    "HCAP-13": frozenset({
        "499b5103293c9b078d58e2ae25ccc20f139d5526538005093c55f1950c222f81",
    }),
    "HCAP-14": frozenset({
        "096aa8aa37724038105100a892507e68f7834cb94311aeaa1289cd9c62a6bca3",
    }),
}


def promoted_by_criteria(spec: HostSpec) -> tuple[Capability, ...]:
    """The capabilities the promotion criteria judge: every one that is not
    an unchanged legacy entry (#100)."""
    return tuple(c for c in spec.capabilities
                 if capability_baseline_sha256(c)
                 not in LEGACY_CAPABILITY_BASELINES.get(c.id, frozenset()))


def _gap_vocabulary(spec: HostSpec) -> tuple[str, ...]:
    """The spec's gap IDs and the ones the pipeline emits itself (#81 D6),
    so every generated HCAP revision lists them explicitly (04 §1.1)."""
    return tuple(sorted(set(spec.missing_capability_ids) |
                        set(PIPELINE_GAP_IDS)))


def _resolve(base: Path, path: Path) -> Path:
    return (path if path.is_absolute() else base / path).resolve()


def _validated_capability_evidence(
        capability_id: str, path: Path, *,
        expected_mapping_identity: KernelIdentity,
        lane_script_sha256: str,
) -> tuple[bytes, ExecutionLayout, PromotionProbeEvidence | None]:
    """Validate identity-sensitive evidence before it can promote an HCAP.

    Evidence is typed: a promotion probe campaign (#100) for any capability,
    or the capability's own KVM evidence model (CAPABILITY_EVIDENCE_MODELS).
    Untyped evidence is refused for every capability.  Either kind must be
    bound to the generated execution harness, its full mapping identity and
    the pinned guest lane script.  Returns the bytes, the executor layout
    the evidence ran and the probe campaign, if it is one.
    """
    contents = path.read_bytes()
    try:
        schema = json.loads(contents).get("schema_version")
    except (ValueError, AttributeError) as error:
        raise GenerationError(
            f"{capability_id} evidence {path} is not a JSON object") from error
    if schema == "promotion-probe-evidence.v1":
        model = PromotionProbeEvidence
    else:
        model = CAPABILITY_EVIDENCE_MODELS.get(capability_id)
    if model is None:
        raise GenerationError(
            f"{capability_id} evidence {path} has no typed evidence model; "
            "give promotion-probe-evidence.v1 (#100)")
    try:
        evidence = model.model_validate_json(contents)
    except ValidationError as error:
        raise GenerationError(
            f"invalid {capability_id} KVM evidence {path}: {error}") from error
    if evidence.mapping_identity != expected_mapping_identity:
        raise GenerationError(
            f"{capability_id} evidence mapping identity differs from the "
            "generated execution harness")
    if evidence.execution_harness_id != \
            expected_mapping_identity.execution_harness_id:
        raise GenerationError(
            f"{capability_id} evidence names another execution harness")
    if evidence.guest_lane_script_sha256 != lane_script_sha256:
        raise GenerationError(
            f"{capability_id} evidence names another guest lane script")
    if capability_id not in getattr(evidence, "capability_ids",
                                    (evidence.capability_id,)):
        raise GenerationError(
            f"{capability_id} evidence validates other capabilities")
    probe = evidence if isinstance(evidence, PromotionProbeEvidence) else None
    return contents, evidence.layout, probe


def _with_gap(spec: HostSpec, gap: GapContract) -> HostSpec:
    """The spec with the Controller's gap contract, which a contract the
    spec gives the same gap must equal."""
    gap_id = gap.missing_capability_id
    own = [g for g in spec.gap_contracts if g.missing_capability_id == gap_id]
    if any(g.contract != gap.contract for g in own):
        raise GenerationError(
            f"the spec gives gap {gap_id} another contract than the "
            "Controller's (#100)")
    if gap_id not in _gap_vocabulary(spec):
        raise GenerationError(f"gap {gap_id} is not in the spec's vocabulary")
    contracts = (*(g for g in spec.gap_contracts
                   if g.missing_capability_id != gap_id), gap)
    return spec.model_copy(update={"gap_contracts": tuple(
        sorted(contracts, key=lambda g: g.missing_capability_id))})


def _changed_capabilities(spec: HostSpec,
                          base: HostSpec) -> tuple[Capability, ...]:
    """The capabilities ``spec`` adds to ``base`` or changes in it, compared
    the way the legacy baselines are.  A patch set adds capabilities and
    never removes one."""
    before = {c.id: capability_baseline_sha256(c) for c in base.capabilities}
    removed = sorted(set(before) - {c.id for c in spec.capabilities})
    if removed:
        raise GenerationError(
            f"the patch set removes {', '.join(removed)} from the base spec")
    return tuple(c for c in spec.capabilities
                 if before.get(c.id) != capability_baseline_sha256(c))


def _check_fills(capabilities: tuple[Capability, ...], gap_id: str) -> None:
    """#100: a Harness Generation patch set adds or changes only
    capabilities that fill the gap it was generated for."""
    if not capabilities:
        raise GenerationError(
            f"the patch set adds or changes no capability for gap {gap_id}")
    for capability in capabilities:
        if capability.fills_gap != gap_id:
            raise GenerationError(
                f"{capability.id} does not fill gap {gap_id}, the gap this "
                "generation is for (#100)")


def _check_gap_contracts(spec: HostSpec,
                         capabilities: tuple[Capability, ...]) -> None:
    """#100: a capability filling a gap declares that gap's vocabulary
    contract, not one fitted to the candidate that raised it."""
    gaps = HcapCatalog(capabilities=(),
                       missing_capability_ids=_gap_vocabulary(spec),
                       gap_contracts=spec.gap_contracts)
    for capability in capabilities:
        if capability.fills_gap is None:
            continue
        refusals = gap_contract_refusals(gaps, capability.fills_gap,
                                         capability)
        if refusals:
            raise GenerationError(
                f"{capability.id} does not meet the promotion criteria "
                f"(#100): {', '.join(refusals)}")


def _check_argument_generality(capabilities: tuple[Capability, ...],
                               bundle: Path,
                               identity: SyzkallerTargetIdentity) -> None:
    """#100: the syz call arguments of each capability the promotion
    criteria judge carry only the literals its contract fixes, read from
    the pinned target's argument shapes."""
    contracts = [(c, c.contract) for c in capabilities
                 if c.contract is not None and c.contract.syz_calls()]
    if not contracts:
        return
    from ...syzkaller.adapter import PinnedSyzParser
    calls = sorted({call for _, contract in contracts
                    for call in contract.syz_calls()})
    with PinnedSyzParser(bundle, identity=identity) as parser:
        shapes = parser.describe(calls)
    for capability, contract in contracts:
        refusals = argument_generality_refusals(contract, shapes)
        if refusals:
            raise GenerationError(
                f"{capability.id} syz call arguments are not general "
                f"(#100): {', '.join(refusals)}")


def _check_layout(capability: Capability,
                  layouts: list[ExecutionLayout]) -> None:
    """A capability's ``validated_layout`` is the layout its typed evidence
    ran (#99): every typed evidence file must have run exactly it, and a
    layout beyond Stage 1's needs one."""
    declared = capability.layout()
    for layout in layouts:
        if layout != declared:
            raise GenerationError(
                f"{capability.id} evidence ran {layout.procs} proc(s) on "
                f"lanes {list(layout.lanes)}, not its validated_layout "
                f"({declared.procs} proc(s), lanes {list(declared.lanes)})")
    if declared != STAGE1_LAYOUT and not layouts:
        raise GenerationError(
            f"{capability.id} validated_layout needs typed evidence that "
            "ran it")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def series_fingerprint(kind: str) -> str:
    """The checked-in ``bundle/patches/<kind>`` series digest.  It is the
    ``series_sha256`` ``tools/bootstrap-kcov-env.py`` records for a build,
    and, for syzkaller, the ``patch_series_sha256`` of the parser bundle
    ``tools/syzkaller/build.py`` makes (same bytes: name, NUL, patch, NUL)."""
    digest = hashlib.sha256()
    for path in sorted((REPO / "bundle" / "patches" / kind).glob("*.patch")):
        digest.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def _build_record(path: Path, kind: str, tree: Path) -> dict:
    """A bootstrap build record that matches the checked-in series and the
    tree as it is now; the same rules as the bootstrap's ``stale_build``."""
    try:
        record = _read_json(path)
    except (OSError, ValueError):
        raise GenerationError(f"{path} is missing or unreadable; rebuild "
                              "with tools/bootstrap-kcov-env.py") from None
    current = series_fingerprint(kind)
    if record.get("series_sha256") != current:
        raise GenerationError(
            f"{path}: the {kind} build used another patch series "
            f"({record.get('series_sha256')}, checked-in {current}); "
            "rebuild with tools/bootstrap-kcov-env.py")
    head = _git(tree, "rev-parse", "HEAD")
    if record.get("head") != head:
        raise GenerationError(
            f"{path}: {tree} moved since the {kind} build (built "
            f"{record.get('head')}, now {head}); rebuild or check out that "
            "commit")
    return record


def _sorted_selections(items):
    return tuple(sorted(items, key=_runtime_key))


class GeneratedVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_harness_id: str
    hcap_revision: str


class Generated(BaseModel):
    """``execution_harness_id`` and ``hcap_revision`` are the first
    variant's; ``variants`` has every one, by sanitizer."""

    model_config = ConfigDict(extra="forbid")

    stage1_config: Path
    collector_config: Path
    report: Path
    kernel_commit: str
    execution_harness_id: str
    hcap_revision: str
    variants: dict[str, GeneratedVariant] = {}
    #: Sanitizer -> the Stage 2 manager config generated for it.
    stage2_managers: dict[str, Path] = {}
    digests: dict[str, str]


#: Descriptor build artifacts that differ between sanitizer variants.
VARIANT_FILES = ("bzimage", "kernel")

#: boot-fixture.sh always sets up this many lanes; the manager gets one
#: journal channel for each (and at least one for each proc).
GUEST_LANES = 4


def _approved_calls(profile, table: SyzkallerCallTable,
                    selection: RuntimeSelection) -> set[str]:
    """Every admitted call and every call the selection enables; its other
    interfaces are runtime features (``remote_cover``)."""
    calls = set(table.calls)
    return ({e.call for e in profile.entries}
            | {i for i in selection.enabled_interfaces if i in calls})


def _stage2_selection(spec: HostSpec) -> RuntimeSelection:
    wanted = spec.stage2.runtime_selection
    if wanted is None:
        if len(spec.runtime_selections) != 1:
            raise GenerationError("stage2.runtime_selection is required when "
                                  "the spec has several runtime selections")
        return spec.runtime_selections[0]
    match = [s for s in spec.runtime_selections
             if _runtime_key(s) == _runtime_key(wanted)]
    if not match:
        raise GenerationError("stage2.runtime_selection is not one of "
                              "runtime_selections")
    return match[0]


def _stage2_procs(spec: HostSpec) -> int:
    """The manager's procs: at most what the topology capability's
    validated layout covers (#99)."""
    if spec.runtime_selection_capability is None:
        raise GenerationError("stage2 needs runtime_selection_capability: "
                              "its validated_layout bounds the procs")
    topology = next(c for c in spec.capabilities
                    if c.id == spec.runtime_selection_capability)
    layout = topology.layout()
    validated = max(n for n in range(1, layout.procs + 1)
                    if layout.covers(n))
    wanted = spec.stage2.procs
    if wanted is None:
        return validated
    if wanted > validated:
        raise GenerationError(
            f"stage2.procs {wanted} exceeds the {validated} proc(s) "
            f"{topology.id} is validated for")
    return wanted


def _stage2_calls(spec: HostSpec, profile, table: SyzkallerCallTable,
                  selection: RuntimeSelection,
                  procs: int) -> tuple[str, ...]:
    """The approved calls, less the admitted calls no capability is
    validated for at ``procs`` procs (#99).  Given calls must include the
    rest and none of those."""
    catalog = HcapCatalog(capabilities=spec.capabilities,
                          missing_capability_ids=())
    refusals = layout_refusals(catalog, profile.entries, enabled_calls=(),
                               runtime_features=("remote_cover",),
                               procs=procs)
    if refusals:
        raise GenerationError(f"stage2 at {procs} proc(s): {refusals[0]}")
    outside = ({e.call for e in profile.entries}
               - calls_in_layout(catalog, profile.entries, procs))
    approved = _approved_calls(profile, table, selection) - outside
    given = spec.stage2.enable_syscalls
    if given is None:
        return tuple(sorted(approved))
    refusals = layout_refusals(catalog, profile.entries, enabled_calls=given,
                               runtime_features=(), procs=procs)
    if refusals:
        raise GenerationError(f"stage2.enable_syscalls at {procs} proc(s): "
                              + refusals[0])
    missing = sorted(approved - set(given))
    if missing:
        raise GenerationError("stage2.enable_syscalls lacks approved calls: "
                              + ", ".join(missing))
    unknown = sorted(set(given) - set(table.calls))
    if unknown:
        raise GenerationError("stage2.enable_syscalls names calls the "
                              "syzkaller build lacks: " + ", ".join(unknown))
    if len(set(given)) != len(given):
        raise GenerationError("stage2.enable_syscalls repeats a call")
    return given


def _stage2_manager(spec: HostSpec, *, accel: Accel,
                    descriptor: ExecutionHarnessDescriptor,
                    selection: RuntimeSelection, calls: tuple[str, ...],
                    procs: int,
                    files: dict[str, Path], template: Path, lane_sha256: str,
                    syzkaller: Path, ssh_key: Path, state: Path) -> dict:
    """The syz-manager config of one variant, in the shape the Stage 2
    preflight and KVM step check (``stage2/host.py``, ``stage2/kvm.py``).
    The step replaces the workdir, the lane template, the HTTP address
    and the journal channels for each lease."""
    s2 = spec.stage2
    cmdline = " ".join([guest_cmdline(descriptor, selection, lane_sha256),
                        "koov.nfs_target=1"])
    sockets = state / "stage2-journal"
    if any(c.isspace() or c == "," for c in str(sockets)):
        raise GenerationError("state_dir cannot contain whitespace or commas "
                              "(it is in the manager's QEMU arguments)")
    qemu_args = [
        *accel_qemu_args(accel),
        "-fsdev", ("local,id=koov_lane,path={{TEMPLATE}},"
                   "security_model=none,readonly=on"),
        "-device", "virtio-9p-pci,fsdev=koov_lane,mount_tag=koov-lane",
        "-device", "virtio-serial-pci,id=nfspser"]
    for lane in range(max(GUEST_LANES, procs)):
        qemu_args += [
            "-chardev", (f"socket,id=nfspj{lane},"
                         f"path={sockets / f'lane{lane}.sock'},server=off"),
            "-device", (f"virtserialport,bus=nfspser.0,chardev=nfspj{lane},"
                        f"name=nfsp-journal-{lane}")]
    return {
        "name": f"stage2-{descriptor.sanitizer.value}",
        "target": descriptor.syzkaller_identity.target,
        "http": "",
        "workdir": str(state / "stage2-workdir"),
        "workdir_template": str(template),
        "kernel_obj": str(files["kernel"].parent),
        "image": str(files["vm-image"]),
        "sshkey": str(ssh_key),
        "syzkaller": str(syzkaller),
        "procs": procs,
        "type": "qemu",
        "enable_syscalls": list(calls),
        "experimental": {"remote_cover": True,
                         "nfs_proxy_window": s2.nfs_proxy_window},
        "vm": {"count": 1, "cpu": spec.collector.cpus,
               "mem": spec.collector.memory_mb, "qemu": spec.collector.qemu,
               "kernel": str(files["bzimage"]), "cmdline": cmdline,
               "qemu_args": " ".join(qemu_args)},
    }


def generate(spec_path: Path, *, python: str = sys.executable,
             now: str | None = None,
             gap: GapContract | None = None,
             base_spec: Path | None = None) -> Generated:
    """``gap`` is the Controller's contract for the gap a Harness
    Generation patch set fills (#100), and ``base_spec`` the spec the patch
    set started from.  Both come from outside the spec, which the patch set
    can change: every capability the patch set adds or changes must fill
    that gap, and the spec cannot give the gap another contract."""
    if (gap is None) != (base_spec is None):
        raise GenerationError("give the gap and the base spec together")
    spec_path = Path(spec_path).resolve()
    base = spec_path.parent
    spec = HostSpec.model_validate_json(spec_path.read_bytes())
    if gap is not None:
        spec = _with_gap(spec, gap)
        changed = _changed_capabilities(spec, HostSpec.model_validate_json(
            Path(base_spec).read_bytes()))
    state = _resolve(base, spec.state_dir)
    root = _resolve(base, spec.artifact_root)
    env = _resolve(base, spec.env_dir)
    bundle = _resolve(base, spec.syzkaller_bundle)
    ssh_key = _resolve(base, spec.ssh_key)
    variants = spec.variant_specs()
    sanitizers = {v.sanitizer for v in variants}
    wrong = [p.policy_id for p in spec.policies
             if p.sanitizer not in sanitizers]
    if wrong:
        names = "/".join(v.sanitizer.value for v in variants)
        raise GenerationError(f"policies {wrong} use another sanitizer than "
                              f"the {names} harness")
    mutate = [p.policy_id for p in spec.policies
              if p.campaign_mode is CampaignMode.MUTATE]
    if mutate:
        # #81 D16: generation writes no Stage 2 backend, no Proxy for the
        # Rule Compiler and no promoted semantic registry yet, so a mutate
        # job could only stop after Q1.
        raise GenerationError(
            f"policies {mutate} use campaign_mode mutate, which needs a Stage "
            "2 backend, an nfs_proxy and a promoted semantic subset; this "
            "generator configures none of them. Use campaign_mode none")
    state.mkdir(parents=True, exist_ok=True)
    store = ArtifactStore(root)
    digests: dict[str, str] = {}
    several = len(variants) > 1

    def key(variant: VariantSpec, name: str) -> str:
        """A variant's own digest; a single variant keeps the plain key."""
        return f"{variant.sanitizer.value}:{name}" if several else name

    # ---------------------------------------------------- host files
    images = env / "images"
    kernel_repo = env / "linux"
    common = {
        "vm-image": images / "bookworm-kcov-fresh.qcow2",
        "lane-script": REPO / "bundle" / "lane" / "lane.sh",
        "syz-executor": env / "syzkaller" / "bin" / "linux_amd64" /
        "syz-executor",
        "syz-execprog": env / "syzkaller" / "bin" / "linux_amd64" /
        "syz-execprog",
        "syz-manager": env / "syzkaller" / "bin" / "syz-manager",
    }
    file_pins = {}
    common_builds: list[HarnessBuildArtifact] = []
    for name, path in sorted(common.items()):
        pin = pin_file(name, path)
        ref = put_record(store, pin)
        file_pins[name] = pin
        common_builds.append(HarnessBuildArtifact(name=name,
                                                  artifact_ref=ref))
        digests[f"pin:{name}"] = ref
    patches = REPO / "bundle" / "patches" / "kernel"
    series = [p for p in sorted(patches.glob("*.patch"))]
    kernel_builds: dict[Sanitizer, dict] = {}
    variant_files: dict[Sanitizer, dict[str, Path]] = {}
    variant_builds: dict[Sanitizer, list[HarnessBuildArtifact]] = {}
    instrumentation_refs: dict[Sanitizer, str] = {}
    for v in variants:
        directory = images / v.sanitizer.value
        # The instrumentation manifest below pins the checked-in kernel
        # series, so the kernel must have been built from exactly that
        # series.
        kernel_builds[v.sanitizer] = _build_record(
            directory / "build.json", "kernel", kernel_repo)
        files = {"bzimage": directory / "bzImage",
                 "kernel": directory / "vmlinux"}
        builds = list(common_builds)
        for name, path in sorted(files.items()):
            ref = put_record(store, pin_file(name, path))
            builds.append(HarnessBuildArtifact(name=name, artifact_ref=ref))
            digests[key(v, f"pin:{name}")] = ref
        instrumentation = InstrumentationManifest(
            kernel_patches=tuple(pin_file(p.name, p) for p in series),
            kernel_config=pin_file(".config", directory / ".config"))
        ref = put_record(store, instrumentation)
        builds.append(HarnessBuildArtifact(name="instrumentation",
                                           artifact_ref=ref))
        digests[key(v, "instrumentation")] = ref
        builds.sort(key=lambda b: b.name)
        variant_files[v.sanitizer] = files
        variant_builds[v.sanitizer] = builds
        instrumentation_refs[v.sanitizer] = ref
    # Every variant is a build of the same kernel tree, at its HEAD.
    kernel_commit = kernel_builds[variants[0].sanitizer]["head"]

    # ---------------------------------------------------- syzkaller
    # The executor binaries, the tree they were built from and the parser
    # bundle must all be the checked-in syzkaller series: the binaries'
    # build record names their series and tree, the bundle's identity
    # names its series, and both trees must be the same.
    checkout = bundle.parent / "checkout"
    provenance = _read_json(bundle / "provenance.json")
    syz_build = _build_record(env / "syzkaller" / "bin" / "build.json",
                              "syzkaller", env / "syzkaller")
    syz_tree = _git(env / "syzkaller", "rev-parse", "HEAD^{tree}")
    if syz_tree != provenance["source_tree"]:
        raise GenerationError(
            "env/syzkaller (the executor binaries) and the parser bundle "
            f"were built from different trees: {syz_tree} vs "
            f"{provenance['source_tree']}")
    identity = SyzkallerTargetIdentity.model_validate_json(
        (bundle / "identity.json").read_bytes())
    series_bytes = (bundle / "patch-series.bin").read_bytes()
    if (identity.patch_series_sha256 != series_fingerprint("syzkaller")
            or hashlib.sha256(series_bytes).hexdigest()
            != identity.patch_series_sha256):
        raise GenerationError(
            "the parser bundle was built from another syzkaller patch series "
            f"({identity.patch_series_sha256}, checked-in "
            f"{series_fingerprint('syzkaller')}); rebuild it with "
            "tools/syzkaller/build.py")
    manifest = SyzkallerBuildManifest.model_validate_json(
        (bundle / "build-manifest.json").read_bytes())
    table = SyzkallerCallTable.model_validate_json(
        (bundle / "call-table.json").read_bytes())
    for f in manifest.files:
        if store.put((bundle / f.path).read_bytes()) != f.artifact_ref:
            raise GenerationError(f"bundle file {f.path} differs from its "
                                  "build manifest")
    store.put(series_bytes)
    for record in (manifest, table):
        put_record(store, record)
    if (identity.build_manifest_sha256 != put_record(store, manifest)
            or identity.call_table_sha256 != put_record(store, table)):
        raise GenerationError("bundle identity.json disagrees with its files")
    judged = promoted_by_criteria(spec)
    if gap is not None:
        _check_fills(changed, gap.missing_capability_id)
    _check_gap_contracts(spec, judged)
    _check_argument_generality(judged, bundle, identity)

    # ---------------------------------------------------- authorities
    capabilities = list(spec.capabilities)
    capability_indexes = {capability.id: index
                          for index, capability in enumerate(capabilities)}
    for v in variants:
        unknown_evidence = sorted(set(v.capability_evidence) -
                                  set(capability_indexes))
        if unknown_evidence:
            raise GenerationError("capability_evidence names no capability: "
                                  + unknown_evidence[0])
        for capability_id, paths in sorted(v.capability_evidence.items()):
            if not paths:
                raise GenerationError(
                    f"capability_evidence for {capability_id} is empty")
    if spec.runtime_selection_capability is not None:
        index = next((i for i, c in enumerate(capabilities)
                      if c.id == spec.runtime_selection_capability), None)
        if index is None:
            raise GenerationError("runtime_selection_capability names no "
                                  "capability in the spec")
        listed = tuple(
            "allowed runtime_selection (use exactly): "
            + canonical_json(s).decode()
            for s in _sorted_selections(spec.runtime_selections))
        cap = capabilities[index]
        capabilities[index] = cap.model_copy(update={
            "constraints": (*cap.constraints, *listed)})
    admission_draft = HcapCatalog(
        capabilities=tuple(capabilities),
        missing_capability_ids=_gap_vocabulary(spec),
        gap_contracts=spec.gap_contracts)
    with tempfile.TemporaryDirectory() as tmp:
        source_path = Path(tmp) / "source.json"
        hcap_path = Path(tmp) / "hcap.json"
        source_path.write_bytes(canonical_json(spec.admission_source))
        hcap_path.write_bytes(canonical_json(admission_draft))
        profile = generate_call_admission_profile(PinnedSyzkallerInputs(
            checkout=checkout, expected_commit=identity.syzkaller_commit,
            patch_series=bundle / "patch-series.bin", build_root=bundle,
            build_manifest=bundle / "build-manifest.json",
            call_table=bundle / "call-table.json",
            target=identity.target), mapping_path=source_path,
            hcap_path=hcap_path)
    if profile.identity != identity:
        raise GenerationError("admission identity differs from the bundle")
    profile_ref = put_record(store, profile)
    digests["call_admission_profile"] = profile_ref

    admitted = {c for e in profile.entries for c in e.capability_ids}
    neutral_entries = []
    for item in spec.neutral_controls:
        program = _resolve(base, item.program).read_bytes()
        if len(program) > profile.limits.max_program_bytes:
            raise GenerationError(f"{item.program} exceeds max_program_bytes")
        caps = tuple(sorted(item.required_capability_ids))
        if not set(caps) <= admitted:
            raise GenerationError(f"{item.program}: capabilities not "
                                  f"admitted: {sorted(set(caps) - admitted)}")
        selection = item.runtime_selection.model_copy(update={
            "enabled_interfaces": tuple(
                sorted(item.runtime_selection.enabled_interfaces))})
        neutral_entries.append(NeutralControlEntry(
            runtime_selection=selection, program_ref=store.put(program),
            required_capability_ids=caps))
    neutral_entries.sort(key=_neutral_key)
    selections = {_runtime_key(s) for s in spec.runtime_selections}
    uncovered = [s for s in spec.runtime_selections if _runtime_key(s)
                 not in {_runtime_key(e.runtime_selection)
                         for e in neutral_entries}]
    if uncovered:
        raise GenerationError("every runtime selection needs a neutral "
                              f"control: {uncovered[0].model_dump()}")
    if any(_runtime_key(e.runtime_selection) not in selections
           for e in neutral_entries):
        raise GenerationError("a neutral control names a runtime selection "
                              "not in runtime_selections")
    neutral = NeutralControlCatalog(
        identity=identity, call_admission_profile_ref=profile_ref,
        entries=tuple(neutral_entries))
    neutral_ref = put_record(store, neutral)
    digests["neutral_control_catalog"] = neutral_ref
    if spec.stage2 is not None:
        stage2_selection = _stage2_selection(spec)
        stage2_procs = _stage2_procs(spec)
        stage2_calls = _stage2_calls(spec, profile, table, stage2_selection,
                                     stage2_procs)
    judge_profile_ref = put_record(store, spec.judge_profile)
    digests["q1_admissibility_profile"] = judge_profile_ref
    if "nokaslr" not in spec.guest_kernel_command_line.split():
        raise GenerationError("guest_kernel_command_line must contain "
                              "nokaslr (the Q1 identity assumes no KASLR)")

    # ---------------------------------------------------- per variant
    results: dict[Sanitizer, tuple[str, str, str, HarnessBinding,
                                   RemoteKcovSupportBoundary]] = {}
    descriptors: dict[Sanitizer, ExecutionHarnessDescriptor] = {}
    for v in variants:
        # The descriptor must exist before identity-sensitive capability
        # evidence can promote a validated HCAP.  This prevents a stale KVM
        # campaign from a different lane, kernel, image, syzkaller build,
        # runtime selection or sanitizer from being rebound to the newly
        # generated harness.
        descriptor = ExecutionHarnessDescriptor(
            kernel_commit=kernel_commit, sanitizer=v.sanitizer,
            syzkaller_identity=identity,
            build_artifacts=tuple(variant_builds[v.sanitizer]),
            guest_kernel_command_line=spec.guest_kernel_command_line,
            allowed_runtime_selections=_sorted_selections(
                entry.runtime_selection for entry in neutral_entries))
        harness_id = put_record(store, descriptor)
        assert harness_id == descriptor_id(descriptor)
        build_refs = {item.name: item.artifact_ref
                      for item in descriptor.build_artifacts}
        expected_mapping_identity = KernelIdentity(
            execution_harness_id=harness_id, kernel_commit=kernel_commit,
            instrumentation_sha256=build_refs["instrumentation"],
            vmlinux_sha256=build_refs["kernel"],
            kaslr_enabled=False, kaslr_offset=0)
        variant_capabilities = list(capabilities)
        evidence_layouts: dict[str, list[ExecutionLayout]] = {}
        probe_evidence: list[PromotionProbeEvidence] = []
        for capability_id, paths in sorted(v.capability_evidence.items()):
            refs = []
            for path in paths:
                resolved = _resolve(base, path)
                if not resolved.is_file():
                    raise GenerationError(
                        f"capability evidence is not a file: {resolved}")
                contents, layout, probe = _validated_capability_evidence(
                    capability_id, resolved,
                    expected_mapping_identity=expected_mapping_identity,
                    lane_script_sha256=file_pins["lane-script"].sha256)
                evidence_layouts.setdefault(capability_id, []).append(layout)
                if probe is not None:
                    probe_evidence.append(probe)
                refs.append(store.put(contents))
            index = capability_indexes[capability_id]
            capability = variant_capabilities[index]
            variant_capabilities[index] = capability.model_copy(update={
                "evidence_refs": tuple(sorted(set(capability.evidence_refs)
                                              | set(refs)))})
        for capability in variant_capabilities:
            _check_layout(capability, evidence_layouts.get(capability.id, []))
        for capability in judged:
            refusals = promotion_refusals(capability, probe_evidence)
            if refusals:
                raise GenerationError(
                    f"{capability.id} does not meet the promotion criteria "
                    f"(#100): {', '.join(refusals)}")
        draft = HcapCatalog(
            capabilities=tuple(variant_capabilities),
            missing_capability_ids=_gap_vocabulary(spec),
            gap_contracts=spec.gap_contracts)
        boundary = RemoteKcovSupportBoundary(
            name=spec.support_boundary.name,
            revision=spec.support_boundary.revision,
            kernel_commit=kernel_commit,
            instrumentation_sha256=instrumentation_refs[v.sanitizer],
            supported_contexts=spec.support_boundary.supported_contexts)
        boundary_ref = put_record(store, boundary)
        digests[key(v, "remote_kcov_support_boundary")] = boundary_ref
        hcap = draft.model_copy(update={"authority_refs": (
            AuthorityRef(kind="CallAdmissionProfile",
                         artifact_ref=profile_ref),
            AuthorityRef(kind="NeutralControlCatalog",
                         artifact_ref=neutral_ref),
            AuthorityRef(kind="Q1AdmissibilityProfile",
                         artifact_ref=judge_profile_ref),
            AuthorityRef(kind="RemoteKcovSupportBoundary",
                         artifact_ref=boundary_ref))})
        hcap = HcapCatalog.model_validate(hcap.model_dump())
        hcap_ref = put_record(store, hcap)
        digests[key(v, "hcap")] = hcap_ref
        approval = ExecutionHarnessApproval(
            descriptor=descriptor, approved_hcap_revisions=(hcap_ref,))
        approval_ref = put_record(store, approval)
        binding = HarnessBinding(kernel_commit=kernel_commit,
                                 sanitizer=v.sanitizer,
                                 execution_harness_id=harness_id,
                                 hcap_revision=hcap_ref)
        digests[key(v, "execution_harness_descriptor")] = harness_id
        digests[key(v, "execution_harness_approval")] = approval_ref
        results[v.sanitizer] = (harness_id, hcap_ref, approval_ref, binding,
                                boundary_ref)
        descriptors[v.sanitizer] = descriptor
    first = results[variants[0].sanitizer]

    # ---------------------------------------------------- harness
    report = {
        "schema_version": "stage1-host-generation.v1",
        "generated_at": now or datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "spec_sha256": hashlib.sha256(
            spec_path.read_bytes()).hexdigest(),
        "kernel_commit": kernel_commit,
        "kernel_build": kernel_builds[variants[0].sanitizer],
        "syzkaller_build": syz_build, "syzkaller_provenance": provenance,
        "execution_harness_id": first[0], "hcap_revision": first[1],
        "digests": dict(sorted(digests.items())),
    }
    if several:
        report["variants"] = {
            s.value: {"kernel_build": kernel_builds[s],
                      "execution_harness_id": r[0], "hcap_revision": r[1]}
            for s, r in results.items()}
    evidence_ref = store.put(canonical_json(report))
    catalog = HarnessCatalog(registrations=tuple(
        HarnessRegistration(binding=r[3], evidence_refs=(evidence_ref,))
        for r in results.values()))
    catalog_ref = put_record(store, catalog)
    digests.update({"harness_catalog": catalog_ref,
                    "registration_evidence": evidence_ref})

    # ---------------------------------------------------- configs
    collector_path = state / "collector.json"
    if several:
        collector_files = dict(common)
        per_variant = {s.value: files for s, files in variant_files.items()}
    else:
        collector_files = {**common, **variant_files[variants[0].sanitizer]}
        per_variant = {}
    accel = resolve(spec.collector.accel)
    scale = slowdown(accel)
    timings = spec.collector.model_dump(exclude={"accel"})
    timings["boot_timeout_s"] *= scale
    timings["fixture_timeout_s"] *= scale
    collector = CollectorConfig(
        artifact_root=root, ssh_key=ssh_key, pin_cache=state / "pins.json",
        files={n: p.resolve() for n, p in collector_files.items()},
        variant_files={s: {n: p.resolve() for n, p in files.items()}
                       for s, files in per_variant.items()},
        accel=accel, exec_slowdown=scale, **timings)
    collector_path.write_text(collector.model_dump_json(indent=2) + "\n")
    config = Stage1Config(
        state_dir=state, artifact_root=root, kernel_repo=kernel_repo,
        harness_catalog_ref=catalog_ref,
        execution_harness_approvals=tuple(r[2] for r in results.values()),
        syzkaller_bundle=bundle, syzkaller_identity=identity,
        policies=spec.policies,
        # Each binding's HCAP names its own Q1 authorities; this default
        # is the first variant's.
        judge_versions=JudgeVersions(judge_profile_id=judge_profile_ref,
                                     support_boundary_id=first[4]),
        engine=EngineConfig(
            argv=(python, "-m", "agent_pipeline.stage1.host", "collect",
                  "--config", str(collector_path), "{input}", "{output}"),
            cwd=REPO, env={"LANG": "C.UTF-8",
                           "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                           "HOME": os.environ.get("HOME", str(state))},
            resource_key=spec.engine.resource_key,
            collector_id="stage1-host-collector",
            timeout_s=spec.engine.timeout_s * scale,
            max_output_bytes=spec.engine.max_output_bytes),
        slots=SlotsConfig(
            vm_cpus=spec.collector.cpus,
            vm_memory_mb=spec.collector.memory_mb,
            reserve_cpus=spec.engine.reserve_cpus,
            reserve_memory_mb=spec.engine.reserve_memory_mb,
            max_slots=spec.engine.max_slots))
    managers: dict[Sanitizer, Path] = {}
    if spec.stage2 is not None:
        # A frozen copy of the pinned lane script is the manager's lane
        # template (tools/prepare-live-lane-config.py does the same).
        lane = file_pins["lane-script"]
        template = state / f"lane-template-{lane.sha256[:16]}"
        template.mkdir(exist_ok=True)
        frozen = template / "lane.sh"
        if not frozen.exists() or file_sha256(frozen) != lane.sha256:
            frozen.unlink(missing_ok=True)
            frozen.write_bytes(common["lane-script"].read_bytes())
            frozen.chmod(0o444)
        for v in variants:
            manager = _stage2_manager(
                spec, accel=accel, descriptor=descriptors[v.sanitizer],
                selection=stage2_selection, calls=stage2_calls,
                procs=stage2_procs,
                files={n: p.resolve() for n, p in
                       {**common, **variant_files[v.sanitizer]}.items()},
                template=template, lane_sha256=lane.sha256,
                syzkaller=(env / "syzkaller").resolve(), ssh_key=ssh_key,
                state=state)
            name = (f"stage2-manager-{v.sanitizer.value}.json" if several
                    else "stage2-manager.json")
            data = (json.dumps(manager, indent=2) + "\n").encode()
            (state / name).write_bytes(data)
            managers[v.sanitizer] = state / name
            digests[key(v, "stage2_manager")] = \
                hashlib.sha256(data).hexdigest()
    config_path = state / "stage1.json"
    config_path.write_text(config.model_dump_json(indent=2) + "\n")
    report_path = state / "generated.json"
    report["digests"] = dict(sorted(digests.items()))
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True)
                           + "\n")
    return Generated(stage1_config=config_path,
                     collector_config=collector_path, report=report_path,
                     kernel_commit=kernel_commit,
                     execution_harness_id=first[0], hcap_revision=first[1],
                     variants={s.value: GeneratedVariant(
                         execution_harness_id=r[0], hcap_revision=r[1])
                         for s, r in results.items()},
                     stage2_managers={s.value: p
                                      for s, p in managers.items()},
                     digests=digests)
