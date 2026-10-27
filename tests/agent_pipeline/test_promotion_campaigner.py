"""07 §5.3: a promotion probe campaign run by a host command.

Real: CommandCampaigner over the validation command machinery, its store,
the evidence model and the CAS.  Synthetic: the host command, which writes
a report and evidence instead of booting guests.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

from agent_pipeline.artifacts import ArtifactStore
from agent_pipeline.contracts import HarnessBinding, Sanitizer
from agent_pipeline.controller.promotion import CampaignInput
from agent_pipeline.data import load_record
from agent_pipeline.stage1.campaigns import (CampaignRecord, CampaignStore,
                                             CommandCampaigner,
                                             CommandCampaignerConfig)
from agent_pipeline.stage1.validation import ValidatorBusy

from .test_materializer import world as materializer_world  # noqa: F401
from .test_promotion import IDENTITY, evidence
from .test_runner_q1_receipts import build, versions  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux process sessions")

WITHHELD = "c" * 64
BINDING = HarnessBinding(kernel_commit="a" * 40, sanitizer=Sanitizer.KASAN,
                         execution_harness_id=IDENTITY.execution_harness_id,
                         hcap_revision="d" * 64)

# The host command: records its campaign.json, then reports as MODE says.
COMMAND = r'''
import json, os, sys
from pathlib import Path
config, out = Path(sys.argv[1]), Path(sys.argv[2])
mode = os.environ["MODE"]
Path(os.environ["SEEN"]).write_bytes(config.read_bytes())
(out / "runs.json").write_text("[]\n")
if mode == "exit":
    sys.exit(3)
report = {"evidence": {"result": "evidence", "reason": "criteria_met",
                       "evidence": "evidence.json"},
          "refused": {"result": "refused", "reason": "criteria_not_met",
                      "detail": "minimal runs reached the probes"},
          "inconclusive": {"result": "inconclusive",
                           "reason": "vm_boot_failed"},
          "untyped": {"result": "refused", "reason": "Not A Reason"},
          }[mode if mode in ("refused", "inconclusive", "untyped")
            else "evidence"]
if report["result"] == "evidence":
    (out / "evidence.json").write_bytes(
        Path(os.environ["EVIDENCE"]).read_bytes())
(out / "campaign.json").write_text(json.dumps(report))
'''


def _evidence_bytes(**change) -> bytes:
    change.setdefault("withheld_program_sha256s", [WITHHELD])
    return evidence(**change).model_dump_json().encode()


def _campaigner(tmp_path: Path, mode: str, data: bytes | None = None):
    script = tmp_path / "campaign.py"
    script.write_text(COMMAND)
    (tmp_path / "evidence.json").write_bytes(data or _evidence_bytes())
    state = tmp_path / "state"
    state.mkdir(exist_ok=True)
    artifacts = ArtifactStore(tmp_path / "cas")
    store = CampaignStore(state / "campaigns.sqlite")
    return artifacts, store, CommandCampaigner(CommandCampaignerConfig(
        argv=(sys.executable, "-I", str(script), "{input}/campaign.json",
              "{output}"),
        cwd=tmp_path, work_root=state / "campaign-runs",
        resource_key="test-campaign", stage1=tmp_path / "stage1.json",
        env={"LANG": "C.UTF-8", "MODE": mode,
             "SEEN": str(tmp_path / "seen.json"),
             "EVIDENCE": str(tmp_path / "evidence.json")},
        campaign={"selection": 1, "neutral_runs": 4}),
        store, artifacts, state / "campaign.lock")


def _input(capability="CAP-new", seed=3) -> CampaignInput:
    return CampaignInput(promotion_id="gen-1.p", generation_id="gen-1",
                         capability_id=capability, binding=BINDING,
                         withheld_program_sha256s=(WITHHELD,), seed=seed)


def _run(campaigner, task_input=None, task_id="gen-1.p.c0.r1"):
    st = campaigner.submit(task_id, task_input or _input())
    assert st.state == "running"
    assert campaigner.wait(30)
    campaigner.close()
    return campaigner.status(task_id)


def test_evidence_is_stored_with_the_programs_it_ran(tmp_path):
    artifacts, store, campaigner = _campaigner(tmp_path, "evidence")
    st = _run(campaigner)
    assert st.state == "evidence" and st.reason == "criteria_met"
    data = (tmp_path / "evidence.json").read_bytes()
    assert st.evidence_ref == hashlib.sha256(data).hexdigest()
    assert artifacts.get(st.evidence_ref) == data
    model = evidence()
    assert set(st.program_sha256s) == set(model.minimal.program_sha256s) | \
        set(model.generated.program_sha256s)
    record = load_record(artifacts, st.record_ref, CampaignRecord)
    assert (record.result, record.capability_id) == ("evidence", "CAP-new")
    assert artifacts.get(record.runs_ref) == b"[]\n"
    # The command got the host's config and the task's binding.
    seen = json.loads((tmp_path / "seen.json").read_bytes())
    assert seen["stage1"] == str(tmp_path / "stage1.json")
    assert seen["execution_harness_id"] == BINDING.execution_harness_id
    assert seen["hcap_revision"] == BINDING.hcap_revision
    assert seen["capability_id"] == "CAP-new"
    assert seen["withheld_program_sha256s"] == [WITHHELD]
    assert (seen["seed"], seen["selection"], seen["neutral_runs"]) == \
        (3, 1, 4)


@pytest.mark.parametrize("mode, state, reason", [
    ("refused", "refused", "criteria_not_met"),
    ("inconclusive", "inconclusive", "vm_boot_failed"),
    ("exit", "inconclusive", "command_exit_3"),
])
def test_what_a_campaign_ends_without_evidence(tmp_path, mode, state,
                                               reason):
    artifacts, _, campaigner = _campaigner(tmp_path, mode)
    st = _run(campaigner)
    assert (st.state, st.reason, st.evidence_ref) == (state, reason, None)
    record = load_record(artifacts, st.record_ref, CampaignRecord)
    assert record.result == state


@pytest.mark.parametrize("mode, data, reason", [
    ("untyped", None, "untyped reason"),
    ("evidence", _evidence_bytes(capability_id="CAP-other"),
     "evidence_binding_mismatch"),
    ("evidence", _evidence_bytes(withheld_program_sha256s=[]),
     "evidence_withheld_mismatch"),
])
def test_a_report_that_does_not_hold_is_inconclusive(tmp_path, mode, data,
                                                     reason):
    _, _, campaigner = _campaigner(tmp_path, mode, data)
    st = _run(campaigner)
    assert st.state == "inconclusive"
    assert st.reason == f"malformed_report:{reason}"


def test_submit_is_idempotent_and_one_process_owns_the_store(tmp_path):
    _, store, campaigner = _campaigner(tmp_path, "evidence")
    campaigner.submit("gen-1.p.c0.r1", _input())
    campaigner.submit("gen-1.p.c0.r1", _input(seed=9))
    with pytest.raises(ValidatorBusy, match="campaign"):
        CommandCampaigner(campaigner.config, store, campaigner.artifacts,
                          tmp_path / "state" / "campaign.lock")
    assert campaigner.wait(30)
    campaigner.close()
    assert store.input("gen-1.p.c0.r1").seed == 3
    assert (tmp_path / "state" / "campaign-runs").iterdir().__next__().name \
        == "gen-1.p.c0.r1"


def test_a_task_left_running_ends_inconclusive_on_restart(tmp_path):
    _, store, campaigner = _campaigner(tmp_path, "evidence")
    campaigner.close()
    store.insert("gen-1.p.c0.r1", _input())
    again = CommandCampaigner(campaigner.config, store, campaigner.artifacts,
                              tmp_path / "state" / "campaign.lock")
    st = again.status("gen-1.p.c0.r1")
    assert (st.state, st.reason) == ("inconclusive", "runner_restart")
    again.close()


# ------------------------------------------------------------ the service

# The host command of the service test: evidence for the task's capability
# and binding, withholding what the task withholds.
SERVICE_COMMAND = r'''
import json, os, sys
from pathlib import Path
config, out = json.loads(Path(sys.argv[1]).read_text()), Path(sys.argv[2])
evidence = json.loads(Path(os.environ["EVIDENCE"]).read_text())
evidence.update(capability_id=config["capability_id"],
                execution_harness_id=config["execution_harness_id"],
                withheld_program_sha256s=config["withheld_program_sha256s"])
evidence["mapping_identity"]["execution_harness_id"] = \
    config["execution_harness_id"]
(out / "evidence.json").write_text(json.dumps(evidence))
(out / "campaign.json").write_text(json.dumps({
    "result": "evidence", "reason": "criteria_met",
    "evidence": "evidence.json"}))
'''


def test_a_staged_harness_is_campaigned_reviewed_and_promoted(tmp_path,
                                                              build):
    """The whole path in the service: a gap is generated and validated, the
    job reaches its target on the staged revision, the Controller runs the
    campaign of the capability the staged HCAP added without the job's
    program, a person approves, and the registry that carries the evidence
    ends the promotion and resolves the gap's issue."""
    from agent_pipeline.components import InMemoryRegistry
    from agent_pipeline.controller.promotion import PromotionState
    from agent_pipeline.data import put_record
    from agent_pipeline.hcap import (GapContract, HcapCatalog,
                                     ReachabilityPlan)
    from agent_pipeline.materializer import (ArtifactHarnessMaterializer,
                                             ExecutionHarnessApproval,
                                             StaticExecutionHarnessAuthority)
    from agent_pipeline.stage1.service import GenerationParts
    from agent_pipeline.stage1.validation import (
        StagedExecutionHarnessAuthority)

    from .fakes import policy
    from .test_harness_validation import (GAP, ScriptedGenerator,
                                          _validator)
    from .test_promotion import capability, contract
    from .test_stage1_service import (ScriptedRuntime, make_service,
                                      register_mapping, stopped, submit)
    b = build
    hcap = load_record(b.store, b.hcap_ref, HcapCatalog)
    gap_contract = contract()
    base_hcap = put_record(b.store, HcapCatalog.model_validate_json(
        hcap.model_copy(update={
            "missing_capability_ids": (GAP.missing_capability_id,),
            "gap_contracts": (GapContract(
                missing_capability_id=GAP.missing_capability_id,
                contract=gap_contract),)}).model_dump_json()))
    lock = capability(gap_contract, id="CAP-lock",
                      fills_gap=GAP.missing_capability_id)
    staged = HcapCatalog.model_validate_json(hcap.model_copy(update={
        "missing_capability_ids": (GAP.missing_capability_id,),
        "gap_contracts": (GapContract(
            missing_capability_id=GAP.missing_capability_id,
            contract=gap_contract),),
        "capabilities": hcap.capabilities + (lock,)}).model_dump_json())
    staged_ref = put_record(b.store, staged)
    # The Agent plans on the staged revision.
    b.plan = b.plan.model_copy(update={"hcap_revision": staged_ref})
    base = b.binding.model_copy(update={"hcap_revision": base_hcap})
    registry = InMemoryRegistry()
    registry.put(base)
    static = StaticExecutionHarnessAuthority((ExecutionHarnessApproval(
        descriptor=b.descriptor, approved_hcap_revisions=(base_hcap,)),))
    store, validator = _validator(tmp_path, b, mode="same_build")
    (tmp_path / "hcap.json").write_bytes(b.store.get(staged_ref))
    b.materializer = ArtifactHarnessMaterializer(
        b.store, StagedExecutionHarnessAuthority(static, store, b.store),
        b.parser)
    script = tmp_path / "campaign.py"
    script.write_text(SERVICE_COMMAND)
    (tmp_path / "evidence.json").write_bytes(_evidence_bytes())
    campaigns = CampaignStore(tmp_path / "state" / "campaigns.sqlite")
    campaigner = CommandCampaigner(CommandCampaignerConfig(
        argv=(sys.executable, "-I", str(script), "{input}/campaign.json",
              "{output}"),
        cwd=tmp_path, work_root=tmp_path / "state" / "campaign-runs",
        resource_key="test-campaign", stage1=tmp_path / "stage1.json",
        env={"LANG": "C.UTF-8",
             "EVIDENCE": str(tmp_path / "evidence.json")}),
        campaigns, b.store, tmp_path / "state" / "campaign.lock")

    class GapThenPlan(ScriptedRuntime):
        def run(self, request):
            if request.task.value == "reachability_planning" and \
                    "reachability_planning" not in self.calls:
                from agent_pipeline.agent_tasks.runtime import RuntimeResult
                from agent_pipeline.contracts import UnsupportedOutput
                self.calls.append(request.task.value)
                value = request.output_type.model_validate_json(json.dumps(
                    UnsupportedOutput(
                        gap_class=GAP.gap_class,
                        missing_capability_id=GAP.missing_capability_id,
                        reason="no LOCK operation").model_dump(mode="json")))
                return RuntimeResult(output=request.validate_output(value),
                                     model_id="test:scripted")
            return super().run(request)

    with make_service(
            tmp_path, b, registry=registry, runtime=GapThenPlan(b),
            policies=(policy(harness_generation_budget=1),),
            generation=GenerationParts(
                executor=ScriptedGenerator(b.store), validator=validator,
                campaigner=campaigner)) as service:
        job_id = submit(service, b)
        register_mapping(service, b, job_id)
        service.start_worker(idle_s=0.05)

        def reviewed() -> bool:
            p = service.store.promotions()
            return stopped(service, job_id)() and bool(p) and \
                p[0].state is not PromotionState.CAMPAIGNING and \
                p[0].state is not PromotionState.COLLECTING
        assert service.run(reviewed, interval_s=0.05, timeout_s=60), (
            service.store.effect_failures())
        job = service.job(job_id)
        assert job.binding.hcap_revision == staged_ref
        (p,) = service.store.promotions()
        assert p.state is PromotionState.REVIEW, (
            p, service.store.effect_failures())
        plan = load_record(b.store, job.plan_ref, ReachabilityPlan)
        program = plan.program_proposal.artifact_ref
        assert p.withheld_program_sha256s == (program,)
        (c,) = p.capabilities
        assert c.capability_id == "CAP-lock" and c.evidence_ref
        run_input = json.loads((tmp_path / "state" / "campaign-runs" /
                                p.task_id(0) / "input" /
                                "campaign.json").read_text())
        assert run_input["hcap_revision"] == staged_ref
        assert run_input["withheld_program_sha256s"] == [program]

        service.controller.approve_promotion(p.promotion_id, "review-1")
        # The host promotes: CAP-lock with its evidence in the registry's
        # HCAP (a promoted build, here the same one).
        promoted = put_record(b.store, HcapCatalog.model_validate_json(
            staged.model_copy(update={"capabilities": hcap.capabilities + (
                lock.model_copy(update={
                    "evidence_refs": (c.evidence_ref,)}),)})
            .model_dump_json()))
        registry.put(base.model_copy(update={"hcap_revision": promoted}))
        service.controller.on_registry_changed()
        (p,) = service.store.promotions()
        assert p.state is PromotionState.PROMOTED and p.issue_resolved
        (issue,) = service.issues.issues()
        assert issue["status"] == "resolved"
    store.close()
    campaigns.close()
