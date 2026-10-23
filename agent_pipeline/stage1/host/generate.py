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
from ...hcap import (AuthorityRef, Capability, HcapCatalog, RuntimeSelection)
from ...materializer import (ExecutionHarnessApproval,
                             ExecutionHarnessDescriptor, HarnessBuildArtifact,
                             _runtime_key, descriptor_id)
from ...q1 import (KernelIdentity, Q1AdmissibilityProfile,
                   RemoteKcovSupportBoundary)
from ...registry import HarnessCatalog, HarnessRegistration
from ..config import EngineConfig, SlotsConfig, Stage1Config
from .collector import CollectorConfig
from .pins import InstrumentationManifest, pin_file

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
    memory_mb: int = 4096
    cpus: int = 4
    boot_timeout_s: float = 300
    fixture_timeout_s: float = 180
    grace_s: float = 11
    drain_s: float = 10
    exec_timeout_s: float = 600


class Hcap11RunEvidence(_Spec):
    completed: int = Field(ge=1, le=999)
    target_hit_counts: tuple[int, ...]

    @model_validator(mode="after")
    def _count(self) -> Self:
        if len(self.target_hit_counts) != self.completed:
            raise ValueError("target_hit_counts length differs from completed")
        return self


class Hcap11RunsEvidence(_Spec):
    control: Hcap11RunEvidence
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


HCAP11_RECOVERY_ORDER = (
    "nfsd_clid_admin_expired", "nfsd_clid_fresh", "OP_EXCHANGE_ID",
    "nfsd_slot_seqid_unconf", "nfsd_clid_confirmed", "OP_CREATE_SESSION",
)


class Hcap11KvmEvidence(_Spec):
    schema_version: Literal["hcap-kvm-evidence.v1"]
    capability_id: Literal["HCAP-11"]
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    scenario: Literal["v41-client-expiry"]
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    target_mapping_sha256: Sha256
    campaign_result_sha256: Sha256
    guest_lane_script_sha256: Sha256
    guest_nfs_proxy_sha256: Sha256
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
        if any(self.runs.control.target_hit_counts):
            raise ValueError("control run reached the target mapping")
        if not all(count > 0 for count in self.runs.stimulus.target_hit_counts):
            raise ValueError("stimulus run missed the target mapping")
        if self.recovery_order != HCAP11_RECOVERY_ORDER:
            raise ValueError("recovery order differs from the validated contract")
        if self.crash_signature_count != 0 or self.raw_artifact_error_count != 0:
            raise ValueError("campaign contains a crash or artifact error")
        if self.shareable_result_contains_target_metadata_or_addresses:
            raise ValueError("shareable campaign evidence contains private target data")
        return self


HCAP12_PROBES = ("cld_create", "cld_create_error", "pipe_wait_for_open")


class Hcap12ProbeHits(_Spec):
    """Per-run counts of attributed PCs in each public CLD probe range."""

    cld_create: tuple[int, ...]
    cld_create_error: tuple[int, ...]
    pipe_wait_for_open: tuple[int, ...]

    def each(self, name: str) -> tuple[int, ...]:
        return getattr(self, name)


class Hcap12BrokerDelta(_Spec):
    """Broker counter deltas across one phase (tools/nfs-proxy/src/cld.h)."""

    reconnect_ok: int = Field(ge=0)
    reconnect_fail: int = Field(ge=0)
    down_ok: int = Field(ge=0)
    down_fail: int = Field(ge=0)
    daemon_stop_fail: int = Field(ge=0)
    daemon_start_fail: int = Field(ge=0)
    refused_busy: int = Field(ge=0)
    refused_identity: int = Field(ge=0)
    restore_ok: int = Field(ge=0)
    restore_fail: int = Field(ge=0)


class Hcap12RunEvidence(_Spec):
    completed: int = Field(ge=3, le=999)
    probe_hits: Hcap12ProbeHits
    broker: Hcap12BrokerDelta
    #: lane.sh status passed (broker-validated idle nfsdcld) after every run.
    status_checks_passed: int = Field(ge=0)
    #: Generation contract held for every run (HCAP-11 invariants).
    attributed_generations: int = Field(ge=0)

    @model_validator(mode="after")
    def _count(self) -> Self:
        for name in HCAP12_PROBES:
            if len(self.probe_hits.each(name)) != self.completed:
                raise ValueError(f"{name} length differs from completed")
        if self.status_checks_passed != self.completed:
            raise ValueError("a run left the lane fixture unhealthy")
        b = self.broker
        if (b.reconnect_fail or b.down_fail or b.daemon_stop_fail
                or b.daemon_start_fail or b.refused_busy
                or b.refused_identity or b.restore_ok or b.restore_fail):
            raise ValueError("broker recorded a failed or refused transaction")
        return self


class Hcap12RunsEvidence(_Spec):
    #: Neutral control: no expiry, no nfsdcld control.
    control: Hcap12RunEvidence
    #: A: expiry, then client0 recovery with the daemon untouched.
    normal: Hcap12RunEvidence
    #: C: expiry, one bounded reconnect, then client0 recovery.
    reconnect: Hcap12RunEvidence
    #: B: expiry, daemon down past the upcall timeout, then recovery.
    #: Fixture evidence only; it never promotes an admitted call.
    daemon_down: Hcap12RunEvidence


class Hcap12KvmEvidence(_Spec):
    schema_version: Literal["hcap-kvm-evidence.v1"]
    capability_id: Literal["HCAP-12"]
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    scenario: Literal["v41-cld-lifecycle"]
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    #: Digest of each public probe TargetPcMapping, keyed by probe name.
    probe_mapping_sha256: dict[str, Sha256]
    campaign_result_sha256: Sha256
    guest_lane_script_sha256: Sha256
    guest_nfs_proxy_sha256: Sha256
    runs: Hcap12RunsEvidence
    generation_contract: Hcap11GenerationEvidence
    crash_signature_count: int = Field(ge=0)
    raw_artifact_error_count: int = Field(ge=0)
    shareable_result_contains_target_metadata_or_addresses: bool

    @model_validator(mode="after")
    def _validated_campaign(self) -> Self:
        if self.execution_harness_id != self.mapping_identity.execution_harness_id:
            raise ValueError("mapping and campaign harness identities differ")
        if tuple(sorted(self.probe_mapping_sha256)) != HCAP12_PROBES:
            raise ValueError("probe mappings differ from the CLD probe set")
        runs = self.runs
        attributed = (runs.control, runs.normal, runs.reconnect)
        if any(run.attributed_generations != run.completed
               for run in attributed):
            raise ValueError("a run lacks one attributed generation")
        hits = runs.control.probe_hits
        if any(any(hits.each(name)) for name in HCAP12_PROBES):
            raise ValueError("control run reached a CLD probe")
        if any(runs.control.broker.model_dump().values()):
            raise ValueError("control run invoked the nfsdcld broker")
        for name, run in (("normal", runs.normal),
                          ("reconnect", runs.reconnect)):
            if not all(run.probe_hits.cld_create):
                raise ValueError(f"{name} run missed the CLD create upcall")
            if any(run.probe_hits.cld_create_error):
                raise ValueError(f"{name} run reached the create error path")
        if any(runs.normal.probe_hits.pipe_wait_for_open):
            raise ValueError("normal run queued without a pipe reader")
        if any(runs.normal.broker.model_dump().values()):
            raise ValueError("normal run invoked the nfsdcld broker")
        if not all(runs.reconnect.probe_hits.pipe_wait_for_open):
            raise ValueError("reconnect run missed the reader-loss requeue")
        if runs.reconnect.broker.reconnect_ok != runs.reconnect.completed \
                or runs.reconnect.broker.down_ok:
            raise ValueError("reconnect broker transactions differ from runs")
        if runs.daemon_down.broker.down_ok != runs.daemon_down.completed \
                or runs.daemon_down.broker.reconnect_ok:
            raise ValueError("daemon-down broker transactions differ from runs")
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


class VariantSpec(_Spec):
    """One sanitizer build of the shared harness (#81 D10).  Its kernel is
    ``env_dir/images/<sanitizer>``; capability evidence is pinned to its
    own descriptor, so each variant names the KVM evidence collected on
    it."""

    sanitizer: Sanitizer
    capability_evidence: dict[str, tuple[Path, ...]] = Field(
        default_factory=dict)


CAPABILITY_EVIDENCE_MODELS = {
    "HCAP-11": Hcap11KvmEvidence,
    "HCAP-12": Hcap12KvmEvidence,
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
        lane_script_sha256: str) -> bytes:
    """Validate identity-sensitive evidence before it can promote an HCAP.

    Capabilities with a typed KVM evidence model (CAPABILITY_EVIDENCE_MODELS)
    accept only evidence of that model bound to the generated execution
    harness, its full mapping identity and the pinned guest lane script.
    """
    contents = path.read_bytes()
    model = CAPABILITY_EVIDENCE_MODELS.get(capability_id)
    if model is None:
        return contents
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
    return contents


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
    digests: dict[str, str]


#: Descriptor build artifacts that differ between sanitizer variants.
VARIANT_FILES = ("bzimage", "kernel")


def generate(spec_path: Path, *, python: str = sys.executable,
             now: str | None = None) -> Generated:
    spec_path = Path(spec_path).resolve()
    base = spec_path.parent
    spec = HostSpec.model_validate_json(spec_path.read_bytes())
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
        missing_capability_ids=_gap_vocabulary(spec))
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
    judge_profile_ref = put_record(store, spec.judge_profile)
    digests["q1_admissibility_profile"] = judge_profile_ref
    if "nokaslr" not in spec.guest_kernel_command_line.split():
        raise GenerationError("guest_kernel_command_line must contain "
                              "nokaslr (the Q1 identity assumes no KASLR)")

    # ---------------------------------------------------- per variant
    results: dict[Sanitizer, tuple[str, str, str, HarnessBinding,
                                   RemoteKcovSupportBoundary]] = {}
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
        for capability_id, paths in sorted(v.capability_evidence.items()):
            refs = []
            for path in paths:
                resolved = _resolve(base, path)
                if not resolved.is_file():
                    raise GenerationError(
                        f"capability evidence is not a file: {resolved}")
                contents = _validated_capability_evidence(
                    capability_id, resolved,
                    expected_mapping_identity=expected_mapping_identity,
                    lane_script_sha256=file_pins["lane-script"].sha256)
                refs.append(store.put(contents))
            index = capability_indexes[capability_id]
            capability = variant_capabilities[index]
            variant_capabilities[index] = capability.model_copy(update={
                "evidence_refs": tuple(sorted(set(capability.evidence_refs)
                                              | set(refs)))})
        draft = HcapCatalog(
            capabilities=tuple(variant_capabilities),
            missing_capability_ids=_gap_vocabulary(spec))
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
    collector = CollectorConfig(
        artifact_root=root, ssh_key=ssh_key, pin_cache=state / "pins.json",
        files={n: p.resolve() for n, p in collector_files.items()},
        variant_files={s: {n: p.resolve() for n, p in files.items()}
                       for s, files in per_variant.items()},
        **spec.collector.model_dump())
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
            timeout_s=spec.engine.timeout_s,
            max_output_bytes=spec.engine.max_output_bytes),
        slots=SlotsConfig(
            vm_cpus=spec.collector.cpus,
            vm_memory_mb=spec.collector.memory_mb,
            reserve_cpus=spec.engine.reserve_cpus,
            reserve_memory_mb=spec.engine.reserve_memory_mb,
            max_slots=spec.engine.max_slots))
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
                     digests=digests)
