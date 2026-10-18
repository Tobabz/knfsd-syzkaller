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

from pydantic import BaseModel, ConfigDict, Field

from ...admission import (NeutralControlCatalog, NeutralControlEntry,
                          SyzkallerBuildManifest, SyzkallerCallTable,
                          SyzkallerTargetIdentity, _neutral_key)
from ...admission_generation import (AdmissionProfileSource,
                                     PinnedSyzkallerInputs,
                                     generate_call_admission_profile)
from ...artifacts import ArtifactStore
from ...contracts import (HarnessBinding, JobPolicy, JudgeVersions, Sanitizer)
from ...data import canonical_json, put_record
from ...hcap import (AuthorityRef, Capability, HcapCatalog, RuntimeSelection)
from ...materializer import (ExecutionHarnessApproval,
                             ExecutionHarnessDescriptor, HarnessBuildArtifact,
                             _runtime_key, descriptor_id)
from ...q1 import Q1AdmissibilityProfile, RemoteKcovSupportBoundary
from ...registry import HarnessCatalog, HarnessRegistration
from ..config import EngineConfig, Stage1Config
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


class CollectorSpec(_Spec):
    qemu: str = "qemu-system-x86_64"
    memory_mb: int = 4096
    cpus: int = 4
    boot_timeout_s: float = 300
    fixture_timeout_s: float = 180
    grace_s: float = 11
    drain_s: float = 10
    exec_timeout_s: float = 600


class HostSpec(_Spec):
    """``host-spec.json``; relative paths are relative to the spec file."""

    schema_version: str = Field("stage1-host-spec.v1",
                                pattern=r"^stage1-host-spec\.v1$")
    state_dir: Path
    artifact_root: Path
    #: ``tools/bootstrap-kcov-env.py`` TARGET_DIR.
    env_dir: Path
    variant: Sanitizer = Sanitizer.KASAN
    ssh_key: Path
    #: The ``bundle`` directory written by ``tools/syzkaller/build.py``;
    #: its sibling ``checkout`` is the patched syzkaller tree it built.
    syzkaller_bundle: Path
    guest_kernel_command_line: str = DEFAULT_CMDLINE
    capabilities: tuple[Capability, ...] = Field(min_length=1)
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


def _resolve(base: Path, path: Path) -> Path:
    return (path if path.is_absolute() else base / path).resolve()


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


class Generated(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage1_config: Path
    collector_config: Path
    report: Path
    kernel_commit: str
    execution_harness_id: str
    hcap_revision: str
    digests: dict[str, str]


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
    wrong = [p.policy_id for p in spec.policies if p.sanitizer != spec.variant]
    if wrong:
        raise GenerationError(f"policies {wrong} use another sanitizer than "
                              f"the {spec.variant.value} harness")
    state.mkdir(parents=True, exist_ok=True)
    store = ArtifactStore(root)
    digests: dict[str, str] = {}

    # ---------------------------------------------------- host files
    images = env / "images"
    variant = images / spec.variant.value
    kernel_repo = env / "linux"
    # The instrumentation manifest below pins the checked-in kernel series,
    # so the kernel must have been built from exactly that series.
    build = _build_record(variant / "build.json", "kernel", kernel_repo)
    kernel_commit = build["head"]
    files = {
        "bzimage": variant / "bzImage",
        "kernel": variant / "vmlinux",
        "vm-image": images / "bookworm-kcov-fresh.qcow2",
        "lane-script": REPO / "bundle" / "lane" / "lane.sh",
        "syz-executor": env / "syzkaller" / "bin" / "linux_amd64" /
        "syz-executor",
        "syz-execprog": env / "syzkaller" / "bin" / "linux_amd64" /
        "syz-execprog",
        "syz-manager": env / "syzkaller" / "bin" / "syz-manager",
    }
    builds: list[HarnessBuildArtifact] = []
    for name, path in sorted(files.items()):
        ref = put_record(store, pin_file(name, path))
        builds.append(HarnessBuildArtifact(name=name, artifact_ref=ref))
        digests[f"pin:{name}"] = ref
    patches = REPO / "bundle" / "patches" / "kernel"
    series = [p for p in sorted(patches.glob("*.patch"))]
    instrumentation = InstrumentationManifest(
        kernel_patches=tuple(pin_file(p.name, p) for p in series),
        kernel_config=pin_file(".config", variant / ".config"))
    instrumentation_ref = put_record(store, instrumentation)
    builds.append(HarnessBuildArtifact(name="instrumentation",
                                       artifact_ref=instrumentation_ref))
    digests["instrumentation"] = instrumentation_ref
    builds.sort(key=lambda b: b.name)

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
    draft = HcapCatalog(capabilities=tuple(capabilities),
                        missing_capability_ids=tuple(
                            sorted(spec.missing_capability_ids)))
    with tempfile.TemporaryDirectory() as tmp:
        source_path = Path(tmp) / "source.json"
        hcap_path = Path(tmp) / "hcap.json"
        source_path.write_bytes(canonical_json(spec.admission_source))
        hcap_path.write_bytes(canonical_json(draft))
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
    boundary = RemoteKcovSupportBoundary(
        name=spec.support_boundary.name,
        revision=spec.support_boundary.revision,
        kernel_commit=kernel_commit,
        instrumentation_sha256=instrumentation_ref,
        supported_contexts=spec.support_boundary.supported_contexts)
    boundary_ref = put_record(store, boundary)
    digests["q1_admissibility_profile"] = judge_profile_ref
    digests["remote_kcov_support_boundary"] = boundary_ref
    hcap = draft.model_copy(update={"authority_refs": (
        AuthorityRef(kind="CallAdmissionProfile", artifact_ref=profile_ref),
        AuthorityRef(kind="NeutralControlCatalog", artifact_ref=neutral_ref),
        AuthorityRef(kind="Q1AdmissibilityProfile",
                     artifact_ref=judge_profile_ref),
        AuthorityRef(kind="RemoteKcovSupportBoundary",
                     artifact_ref=boundary_ref))})
    hcap = HcapCatalog.model_validate(hcap.model_dump())
    hcap_ref = put_record(store, hcap)
    digests["hcap"] = hcap_ref

    # ---------------------------------------------------- harness
    descriptor = ExecutionHarnessDescriptor(
        kernel_commit=kernel_commit, sanitizer=spec.variant,
        syzkaller_identity=identity, build_artifacts=tuple(builds),
        guest_kernel_command_line=spec.guest_kernel_command_line,
        allowed_runtime_selections=_sorted_selections(
            e.runtime_selection for e in neutral_entries))
    if "nokaslr" not in descriptor.guest_kernel_command_line.split():
        raise GenerationError("guest_kernel_command_line must contain "
                              "nokaslr (the Q1 identity assumes no KASLR)")
    harness_id = put_record(store, descriptor)
    assert harness_id == descriptor_id(descriptor)
    approval = ExecutionHarnessApproval(descriptor=descriptor,
                                        approved_hcap_revisions=(hcap_ref,))
    approval_ref = put_record(store, approval)
    binding = HarnessBinding(kernel_commit=kernel_commit,
                             sanitizer=spec.variant,
                             execution_harness_id=harness_id,
                             hcap_revision=hcap_ref)
    report = {
        "schema_version": "stage1-host-generation.v1",
        "generated_at": now or datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "spec_sha256": hashlib.sha256(
            spec_path.read_bytes()).hexdigest(),
        "kernel_commit": kernel_commit, "kernel_build": build,
        "syzkaller_build": syz_build, "syzkaller_provenance": provenance,
        "execution_harness_id": harness_id, "hcap_revision": hcap_ref,
        "digests": dict(sorted(digests.items())),
    }
    evidence_ref = store.put(canonical_json(report))
    catalog = HarnessCatalog(registrations=(HarnessRegistration(
        binding=binding, evidence_refs=(evidence_ref,)),))
    catalog_ref = put_record(store, catalog)
    digests.update({"execution_harness_descriptor": harness_id,
                    "execution_harness_approval": approval_ref,
                    "harness_catalog": catalog_ref,
                    "registration_evidence": evidence_ref})

    # ---------------------------------------------------- configs
    collector_path = state / "collector.json"
    collector = CollectorConfig(
        artifact_root=root, ssh_key=ssh_key, pin_cache=state / "pins.json",
        files={n: p.resolve() for n, p in files.items()},
        **spec.collector.model_dump())
    collector_path.write_text(collector.model_dump_json(indent=2) + "\n")
    config = Stage1Config(
        state_dir=state, artifact_root=root, kernel_repo=kernel_repo,
        harness_catalog_ref=catalog_ref,
        execution_harness_approvals=(approval_ref,),
        syzkaller_bundle=bundle, syzkaller_identity=identity,
        policies=spec.policies,
        judge_versions=JudgeVersions(judge_profile_id=judge_profile_ref,
                                     support_boundary_id=boundary_ref),
        engine=EngineConfig(
            argv=(python, "-m", "agent_pipeline.stage1.host", "collect",
                  "--config", str(collector_path), "{input}", "{output}"),
            cwd=REPO, env={"LANG": "C.UTF-8",
                           "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                           "HOME": os.environ.get("HOME", str(state))},
            resource_key=spec.engine.resource_key,
            collector_id="stage1-host-collector",
            timeout_s=spec.engine.timeout_s,
            max_output_bytes=spec.engine.max_output_bytes))
    config_path = state / "stage1.json"
    config_path.write_text(config.model_dump_json(indent=2) + "\n")
    report_path = state / "generated.json"
    report["digests"] = dict(sorted(digests.items()))
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return Generated(stage1_config=config_path,
                     collector_config=collector_path, report=report_path,
                     kernel_commit=kernel_commit,
                     execution_harness_id=harness_id, hcap_revision=hcap_ref,
                     digests=digests)
