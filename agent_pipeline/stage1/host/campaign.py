"""The promotion probe campaign of a capability (07 §5.3, #100).

``python -m agent_pipeline.stage1.host probe-campaign --config C OUT`` runs
the campaign ``PromotionProbeEvidence`` describes, on one binding (an
approved harness, or a staged one a Harness Generation validation passed):

- **Probes.** The capability contract's ``boundary_functions``, mapped to
  the coverage call sites of the binding's vmlinux.  The campaign never
  chooses them; a boundary function no call site is in refuses it.
- **Programs.** The parser bridge's ``generate`` makes them from the
  contract's entry syz calls: a minimal program per entry call, and
  distinct generated and mutated programs over the admission profile's
  calls that each call an entry point.  Every program is parsed and
  admitted the way the Materializer admits a plan's program; one the
  admission refuses is dropped, and so is one whose digest the
  Controller withheld (the candidate's programs).
- **Runs**, each a fresh guest as ``collect`` boots it: the minimal
  programs, every generated program ``runs_per_generated`` times, and the
  binding's neutral control of the selection.

``OUT/campaign.json`` says ``evidence`` (and ``OUT/evidence.json`` is the
``PromotionProbeEvidence`` a host spec's ``capability_evidence`` takes),
``refused`` (the campaign ran and does not meet the criteria, or cannot
run on this contract) or ``inconclusive`` (a guest did not boot, or a run
did not reach its program).  A contract without an entry syz call is
refused: the criteria's generated programs are defined by their entry
call.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ...admission import (NeutralControlCatalog,
                          load_call_admission_authority)
from ...artifacts import ArtifactStore
from ...contracts import Sha256
from ...data import canonical_json, load_record
from ...hcap import ArtifactHcapChecker, ExecutionLayout, Identifier
from ...materializer import (ExecutionHarnessDescriptor, SyzParseFailure,
                             _runtime_key)
from ...promotion import (MIN_GENERATED_PROGRAMS, MIN_GENERATED_RUNS,
                          MIN_MINIMAL_RUNS, MIN_NEUTRAL_RUNS,
                          GeneratedProgram, PromotionProbeEvidence,
                          contract_sha256, promotion_refusals)
from ...q1 import KernelIdentity
from ..config import Stage1Config
from .collector import CollectorConfig, CollectorError, verify_pins
from .guest_run import run_program
from .pins import HostFilePin
from .target_pcs import function_callsite_map
from .vm import QemuGuest

#: The executor layout of a campaign run: one proc on lane 0.
LAYOUT = ExecutionLayout(procs=1, lanes=(0,))
#: Generated programs asked of the bridge per program kept, so admission
#: refusals and withheld programs still leave enough.
OVERSAMPLE = 4
MAX_BRIDGE_PROGRAMS = 1024


class CampaignConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    stage1: Path
    #: The service's collector.json (``staged_files`` boots a staged
    #: binding).  Default: ``state_dir/collector.json``.
    collector: Path | None = None
    #: The binding: the descriptor and the HCAP revision it runs with.
    execution_harness_id: Sha256
    hcap_revision: Sha256
    capability_id: Identifier
    #: The candidate's programs; never run.
    withheld_program_sha256s: tuple[Sha256, ...] = ()
    #: Index into the descriptor's allowed runtime selections.
    selection: int = Field(default=0, ge=0)
    seed: int = 0
    minimal_runs: int = Field(default=MIN_MINIMAL_RUNS, ge=1, le=64)
    generated_programs: int = Field(default=MIN_GENERATED_PROGRAMS, ge=1,
                                    le=256)
    runs_per_generated: int = Field(
        default=math.ceil(MIN_GENERATED_RUNS / MIN_GENERATED_PROGRAMS),
        ge=1, le=16)
    neutral_runs: int = Field(default=MIN_NEUTRAL_RUNS, ge=1, le=64)
    max_calls: int = Field(default=8, ge=1, le=64)

    @classmethod
    def load(cls, path: Path) -> CampaignConfig:
        return cls.model_validate_json(path.read_bytes())


class End(Exception):
    def __init__(self, result: str, reason: str, detail: str = "") -> None:
        super().__init__(f"{result}: {reason}: {detail}")
        self.result, self.reason, self.detail = result, reason, detail


def _refuse(reason: str, detail: str = "") -> End:
    return End("refused", reason, detail)


def _inconclusive(reason: str, detail: str = "") -> End:
    return End("inconclusive", reason, detail)


class Campaign:
    def __init__(self, config: CampaignConfig, out: Path, *,
                 guest_factory: Callable = QemuGuest,
                 sleep: Callable[[float], None] = time.sleep,
                 callsite_map: Callable | None = None,
                 today: Callable[[], str] | None = None) -> None:
        self.config = config
        self.out = out
        self.guest_factory = guest_factory
        self.sleep = sleep
        self.callsite_map = callsite_map or self._callsite_map
        self.today = today or (lambda: datetime.now(timezone.utc)
                               .strftime("%Y-%m-%d"))
        self.runs: list[dict] = []
        self.counts = {"admission_refused": 0, "withheld": 0}

    def run(self) -> dict:
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            report = self._campaign()
        except End as end:
            report = {"result": end.result, "reason": end.reason,
                      "detail": end.detail[:4000]}
        report["runs"] = len(self.runs)
        report.update(self.counts)
        (self.out / "runs.json").write_text(
            json.dumps(self.runs, indent=2, sort_keys=True) + "\n")
        (self.out / "campaign.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n")
        return report

    # -- setup ---------------------------------------------------------

    def _campaign(self) -> dict:
        c = self.config
        stage1 = Stage1Config.load(c.stage1)
        collector = CollectorConfig.load(
            c.collector or Path(stage1.state_dir) / "collector.json")
        store = ArtifactStore(stage1.artifact_root)
        descriptor = load_record(store, c.execution_harness_id,
                                 ExecutionHarnessDescriptor)
        hcap = ArtifactHcapChecker(store).load_catalog(c.hcap_revision)
        capability = next((x for x in hcap.capabilities
                           if x.id == c.capability_id), None)
        if capability is None:
            raise _refuse("capability_missing", c.capability_id)
        contract = capability.contract
        if contract is None:
            raise _refuse("contract_missing", c.capability_id)
        entry = contract.syz_calls()
        if not entry:
            raise _refuse("entry_points_without_syz_call", ", ".join(
                f"{e.kind}:{e.name}" for e in contract.entry_points))
        if c.selection >= len(descriptor.allowed_runtime_selections):
            raise _refuse("selection_missing", str(c.selection))
        selection = descriptor.allowed_runtime_selections[c.selection]
        files = verify_pins(collector, descriptor)
        builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
        kernel = load_record(store, builds[stage1.vmlinux_artifact_name],
                             HostFilePin)
        identity = KernelIdentity(
            execution_harness_id=c.execution_harness_id,
            kernel_commit=descriptor.kernel_commit,
            instrumentation_sha256=builds["instrumentation"],
            vmlinux_sha256=builds[stage1.vmlinux_artifact_name],
            kaslr_enabled=False, kaslr_offset=0)
        probes, digests = self._probes(
            files[stage1.vmlinux_artifact_name], kernel.sha256,
            contract.boundary_functions, identity)
        minimal, generated = self._programs(stage1, store, hcap, entry)
        neutral = self._neutral(store, hcap, selection)
        lane = load_record(store, builds["lane-script"], HostFilePin)

        def runs(kind: str, items: list[tuple[str, bytes]]) -> dict:
            hitting, hit = 0, set()
            for i, (digest, text) in enumerate(items):
                reached = self._run(f"{kind}-{i}", digest, text, selection,
                                    descriptor, collector, files, probes)
                hitting += bool(reached)
                hit |= reached
            return {"program_sha256s": sorted({d for d, _ in items}),
                    "runs": len(items), "runs_hitting": hitting,
                    "probes_hit": sorted(hit)}

        minimal_runs = [minimal[i % len(minimal)]
                        for i in range(max(c.minimal_runs, len(minimal)))]
        evidence = {
            "schema_version": "promotion-probe-evidence.v1",
            "capability_id": capability.id,
            "contract_sha256": contract_sha256(contract),
            "observed_at": self.today(),
            "execution_harness_id": c.execution_harness_id,
            "mapping_identity": identity.model_dump(mode="json"),
            "guest_lane_script_sha256": lane.sha256,
            "layout": LAYOUT.model_dump(mode="json"),
            "accelerator": collector.accel,
            "exec_slowdown": collector.exec_slowdown,
            "probes": sorted(probes),
            "probe_mapping_sha256": digests,
            "minimal": runs("minimal", minimal_runs),
            "generated": runs("generated", [
                p for p in generated for _ in range(c.runs_per_generated)]),
            "neutral": runs("neutral", [neutral] * c.neutral_runs),
            "withheld_program_sha256s": sorted(
                set(c.withheld_program_sha256s)),
            "generated_without_entry_call": 0,
            "crash_signature_count": sum(r["crash"] is not None
                                         for r in self.runs),
            "shareable_result_contains_target_metadata_or_addresses": False,
        }
        data = canonical_json(evidence)
        (self.out / "campaign-evidence.json").write_bytes(data)
        try:
            model = PromotionProbeEvidence.model_validate_json(data)
        except ValidationError as error:
            raise _refuse("criteria_not_met", "; ".join(
                e["msg"] for e in error.errors())) from None
        refusals = promotion_refusals(capability, [model])
        if refusals:
            raise _refuse("criteria_not_met", ", ".join(refusals))
        (self.out / "evidence.json").write_bytes(data)
        return {"result": "evidence", "reason": "criteria_met",
                "evidence": "evidence.json",
                "evidence_sha256": hashlib.sha256(data).hexdigest()}

    def _callsite_map(self, vmlinux: Path, functions, sha256: str
                      ) -> dict[str, tuple[int, ...]]:
        return function_callsite_map(vmlinux, functions,
                                     cache=self.out / "pcs-cache",
                                     vmlinux_file_sha256=sha256)

    def _probes(self, vmlinux: Path, sha256: str, functions,
                identity: KernelIdentity
                ) -> tuple[dict[str, frozenset[int]], dict[str, str]]:
        """Each probe's call sites and the digest of its mapping record,
        kept beside the runs for audit."""
        mapped = self.callsite_map(vmlinux, functions, sha256)
        missing = [f for f in functions if not mapped.get(f)]
        if missing:
            raise _refuse("probe_not_instrumented", ", ".join(missing))
        probes, digests = {}, {}
        for name in sorted(functions):
            record = canonical_json({
                "schema_version": "promotion-probe-mapping.v1",
                "probe": name, "identity": identity.model_dump(mode="json"),
                "pcs": [f"{pc:#x}" for pc in mapped[name]]})
            (self.out / f"probe-{name}.json").write_bytes(record)
            probes[name] = frozenset(mapped[name])
            digests[name] = hashlib.sha256(record).hexdigest()
        return probes, digests

    def _programs(self, stage1: Stage1Config, store: ArtifactStore, hcap,
                  entry: tuple[str, ...]
                  ) -> tuple[list[tuple[str, bytes]], list[tuple[str, bytes]]]:
        from ...syzkaller import adapter
        c = self.config
        authority = load_call_admission_authority(
            store, c.hcap_revision,
            expected_identity=stage1.syzkaller_identity)
        enabled = [e.call for e in authority.profile.entries]
        missing = [call for call in entry if call not in enabled]
        if missing:
            raise _refuse("entry_call_not_admitted", ", ".join(missing))
        required = tuple(sorted(x.id for x in hcap.capabilities
                                if "agent_stage1" in x.usable_by))
        withheld = set(c.withheld_program_sha256s)
        with adapter.PinnedSyzParser(
                stage1.syzkaller_bundle,
                identity=stage1.syzkaller_identity) as parser:
            try:
                programs = parser.generate(
                    enabled=enabled, entry=list(entry), seed=c.seed,
                    generated=min(MAX_BRIDGE_PROGRAMS,
                                  c.generated_programs * OVERSAMPLE),
                    max_calls=c.max_calls)
            except SyzParseFailure as error:
                raise _refuse("programs_not_generated", str(error)) from None

            def kept(program: GeneratedProgram) -> bool:
                if program.sha256 in withheld:
                    self.counts["withheld"] += 1
                    return False
                text = program.text.encode()
                try:
                    parsed = parser.parse(text,
                                          identity=stage1.syzkaller_identity)
                except SyzParseFailure:
                    self.counts["admission_refused"] += 1
                    return False
                if not authority.check_limits(parsed.usage).accepted or any(
                        not authority.admit(
                            call.call, required,
                            identity=parsed.identity,
                            resource_facts=call.resource_facts).admitted
                        for call in parsed.calls):
                    self.counts["admission_refused"] += 1
                    return False
                return True

            minimal = [p for p in programs.minimal if kept(p)]
            if {p.entry_call for p in minimal} != set(entry):
                raise _refuse("minimal_programs_not_admitted", ", ".join(
                    sorted(set(entry) - {p.entry_call for p in minimal})))
            generated = []
            for program in programs.generated:
                if len(generated) == c.generated_programs:
                    break
                if kept(program):
                    generated.append(program)
        if len(generated) < c.generated_programs:
            raise _refuse("generated_programs_short",
                          f"{len(generated)} of {c.generated_programs} "
                          "admitted")
        directory = self.out / "programs"
        directory.mkdir(exist_ok=True)
        for p in (*minimal, *generated):
            (directory / f"{p.sha256}.syz").write_text(p.text)
        return ([(p.sha256, p.text.encode()) for p in minimal],
                [(p.sha256, p.text.encode()) for p in generated])

    def _neutral(self, store: ArtifactStore, hcap, selection
                 ) -> tuple[str, bytes]:
        ref = next(r.artifact_ref for r in hcap.authority_refs
                   if r.kind == "NeutralControlCatalog")
        catalog = load_record(store, ref, NeutralControlCatalog)
        entry = next((e for e in catalog.entries
                      if _runtime_key(e.runtime_selection)
                      == _runtime_key(selection)), None)
        if entry is None:
            raise _refuse("neutral_control_missing")
        if entry.program_ref in set(self.config.withheld_program_sha256s):
            raise _refuse("neutral_control_withheld")
        return entry.program_ref, store.get(entry.program_ref)

    # -- runs ------------------------------------------------------------

    def _run(self, label: str, digest: str, text: bytes, selection,
             descriptor, collector, files, probes) -> set[str]:
        """The probes one run reached."""
        out = self.out / "runs" / label
        program = self.out / "runs" / f"{label}.syz"
        program.parent.mkdir(parents=True, exist_ok=True)
        program.write_bytes(text)
        try:
            done = run_program(program, selection, descriptor, collector,
                               files, out, guest_factory=self.guest_factory,
                               sleep=self.sleep)
        except CollectorError as exc:
            raise _refuse("guest_cmdline", str(exc)) from exc
        reached = {name for name, pcs in probes.items()
                   if done.lane.pcs & pcs}
        self.runs.append({"label": label, "program_sha256": digest,
                          "facts": done.facts,
                          "runtime_errors": done.lane.runtime_errors,
                          "published_pcs": len(done.lane.pcs),
                          "probes_hit": sorted(reached),
                          "crash": done.crash})
        if not done.lane.boot_ok:
            raise _inconclusive("vm_boot_failed",
                                f"{label}: {done.lane.runtime_errors}")
        if done.crash is None and not done.clean:
            # A crash ends the run; it counts against the campaign.
            raise _inconclusive("run_incomplete",
                                f"{label}: {done.lane.runtime_errors}")
        return reached


def probe_campaign(config: CampaignConfig, out: Path, **kw) -> dict:
    return Campaign(config, out, **kw).run()
