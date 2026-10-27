"""07 §5.2: the validation of a generated patch set by a host command.

Real: CommandValidator, ValidationStore, the staged authority, the
Materializer, and (in the service test) the whole Stage 1 service with the
Controller's generation path.  Synthetic: the host command, which writes a
report instead of rebuilding and booting a guest, and the generation Agent.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from agent_pipeline.agent_tasks.generation import HarnessPatchSet
from agent_pipeline.components import InMemoryRegistry
from agent_pipeline.contracts import GapClass, GapRef, UnsupportedOutput
from agent_pipeline.controller.generation import (ExtensionOutput,
                                                  GenerationState,
                                                  ValidationInput)
from agent_pipeline.controller.records import JobState
from agent_pipeline.data import canonical_json, load_record, put_record
from agent_pipeline.hcap import HcapCatalog
from agent_pipeline.materializer import (ArtifactHarnessMaterializer,
                                         ExecutionHarnessApproval,
                                         Materialized,
                                         StaticExecutionHarnessAuthority,
                                         descriptor_id)
from agent_pipeline.stage1.service import GenerationParts
from agent_pipeline.stage1.validation import (CommandValidator,
                                              CommandValidatorConfig,
                                              DeferredValidator,
                                              StagedExecutionHarnessAuthority,
                                              ValidationDeferred,
                                              ValidationRecord,
                                              ValidationStore, ValidatorBusy)

from .fakes import policy
from .test_materializer import world as materializer_world  # noqa: F401
from .test_runner_q1_receipts import build, versions  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="Linux process sessions")

GAP = GapRef(gap_class=GapClass.SYZLANG,
             missing_capability_id="syzlang.nfs4.op_lock")
PATCH = b"diff --git a/bundle/x b/bundle/x\n"

# The host command: checks its input, then reports as MODE says.
COMMAND = r'''
import json, os, sys, time
from pathlib import Path
inp, out = Path(sys.argv[1]), Path(sys.argv[2])
mode = os.environ["MODE"]
v = json.loads((inp / "validation.json").read_text())
with open(os.environ["RUNS"], "a") as f:
    f.write(v["task_id"] + " " + sys.argv[3] + "\n")
assert (inp / "patch.diff").read_bytes() == PATCH
assert json.loads((inp / "patch_set.json").read_text())["patch_ref"]
assert (inp / "base_hcap.json").exists() == (v["base_binding"] is not None)
print("validating", v["task_id"])
report = {}
if mode in ("passed", "same_build", "wrong_commit"):
    d = json.loads((inp / "base_descriptor.json").read_text())
    if mode == "passed":
        d["guest_kernel_command_line"] += " staged=1"
    if mode == "wrong_commit":
        d["kernel_commit"] = "c" * 40
    (out / "descriptor.json").write_text(json.dumps(d))
    (out / "hcap.json").write_bytes(Path(os.environ["HCAP"]).read_bytes())
    (out / "smoke.log").write_text("smoke reached\n")
    report = {"result": "passed", "descriptor": "descriptor.json",
              "hcap": "hcap.json", "artifacts": [
                  {"identity": "smoke", "type": "text/plain",
                   "path": "smoke.log"}]}
elif mode == "rejected":
    report = {"result": "rejected", "reason": "smoke_unreached"}
elif mode == "untyped":
    report = {"result": "rejected", "reason": "Not A Reason"}
elif mode == "inconclusive":
    report = {"result": "inconclusive", "reason": "vm_boot_timeout"}
elif mode == "exit":
    sys.exit(3)
elif mode == "sleep":
    time.sleep(120)
(out / "report.json").write_text(json.dumps(report))
'''.replace("PATCH", repr(PATCH))


def _patch_set(store, generation_id="gen-1"):
    return put_record(store, HarnessPatchSet(
        generation_id=generation_id, task_id=f"{generation_id}.a1",
        attempt=1, gap=GAP, base_commit="0" * 40,
        patch_ref=store.put(PATCH), files=("bundle/x",),
        summary="LOCK operation"))


def _input(b, generation_id="gen-1", base=True):
    return ValidationInput(
        generation_id=generation_id, gap=GAP,
        kernel_commit=b.binding.kernel_commit, sanitizer=b.binding.sanitizer,
        base_binding=b.binding if base else None,
        patch_set_ref=_patch_set(b.store, generation_id))


def _config(tmp_path, mode, **kw):
    script = tmp_path / "validate.py"
    script.write_text(COMMAND)
    return CommandValidatorConfig(
        argv=(sys.executable, "-I", str(script), "{input}", "{output}",
              "{resource}"),
        cwd=tmp_path, work_root=tmp_path / "state" / "validation-runs",
        resource_key="test-validate",
        env={"LANG": "C.UTF-8", "MODE": mode,
             "RUNS": str(tmp_path / "runs.txt"),
             "HCAP": str(tmp_path / "hcap.json")}, **kw)


def _validator(tmp_path, b, mode="passed", **kw):
    (tmp_path / "state").mkdir(exist_ok=True)
    put_record(b.store, b.descriptor)
    (tmp_path / "hcap.json").write_bytes(b.store.get(b.hcap_ref))
    store = ValidationStore(tmp_path / "state" / "validations.sqlite")
    return store, CommandValidator(
        _config(tmp_path, mode, **kw), store, b.store,
        tmp_path / "state" / "validation.lock")


def _finish(validator, task_id, b, mode=None, **kw):
    st = validator.submit(task_id, _input(b, **kw))
    assert st.state == "running"
    assert validator.wait(30)
    return validator.status(task_id)


def _runs(tmp_path):
    return (tmp_path / "runs.txt").read_text().splitlines()


def test_a_pass_stages_the_hcap_revision_and_its_build(tmp_path, build):
    b = build
    store, v = _validator(tmp_path, b)
    st = _finish(v, "gen-1.a1.v1", b)
    assert st.state == "passed", st
    s = st.binding
    assert s.kernel_commit == b.binding.kernel_commit
    assert s.sanitizer is b.binding.sanitizer
    # A new build identity: the descriptor the command reported.
    assert s.execution_harness_id != b.binding.execution_harness_id
    assert s.hcap_revision == b.hcap_ref
    record = load_record(b.store, st.evidence_ref, ValidationRecord)
    assert record.result == "passed" and record.binding == s
    assert [a.identity for a in record.artifacts] == ["smoke"]
    assert b"validating gen-1.a1.v1" in b.store.get(record.log_ref)
    # The static approvals do not know it; the staged authority does, and
    # the Materializer materializes the plan on it.
    assert b.builds.resolve(s) is None
    authority = StagedExecutionHarnessAuthority(b.builds, store, b.store)
    approval = authority.resolve(s)
    assert descriptor_id(approval.descriptor) == s.execution_harness_id
    assert approval.approved_hcap_revisions == (s.hcap_revision,)
    assert approval_ref_is_stored(b, record, approval)
    m = ArtifactHarnessMaterializer(b.store, authority, b.parser)
    assert isinstance(m.materialize(b.plan_ref, s), Materialized)
    # The base binding still resolves to its static approval.
    assert authority.resolve(b.binding) == b.builds.resolve(b.binding)
    v.close()
    store.close()


def approval_ref_is_stored(b, record, approval) -> bool:
    return load_record(b.store, record.approval_ref,
                       ExecutionHarnessApproval) == approval


def test_a_staged_revision_of_the_same_build_adds_an_approval(tmp_path,
                                                              build):
    b = build
    staged_hcap = load_record(b.store, b.hcap_ref, HcapCatalog)
    staged_hcap = staged_hcap.model_copy(
        update={"missing_capability_ids": ("syzlang.other",)})
    staged_ref = put_record(b.store, staged_hcap)
    store, v = _validator(tmp_path, b, mode="same_build")
    (tmp_path / "hcap.json").write_bytes(b.store.get(staged_ref))
    st = _finish(v, "gen-1.a1.v1", b)
    assert st.state == "passed", st
    assert st.binding.execution_harness_id == b.binding.execution_harness_id
    assert st.binding.hcap_revision == staged_ref
    authority = StagedExecutionHarnessAuthority(b.builds, store, b.store)
    assert staged_ref in authority.resolve(st.binding).approved_hcap_revisions
    assert b.builds.resolve(st.binding).approved_hcap_revisions == (
        b.hcap_ref,)
    v.close()
    store.close()


@pytest.mark.parametrize("mode,state,reason", [
    ("rejected", "rejected", "smoke_unreached"),
    ("inconclusive", "inconclusive", "vm_boot_timeout"),
    ("exit", "inconclusive", "command_exit_3"),
    ("untyped", "inconclusive", "malformed_report:rejected needs a typed "
                                "reason"),
    ("wrong_commit", "inconclusive",
     "malformed_report:descriptor_build_key_mismatch"),
])
def test_what_is_not_a_pass(tmp_path, build, mode, state, reason):
    store, v = _validator(tmp_path, build, mode=mode)
    st = _finish(v, "gen-1.a1.v1", build)
    assert (st.state, st.reason, st.binding) == (state, reason, None)
    record = load_record(build.store, st.evidence_ref, ValidationRecord)
    assert record.result == state and record.approval_ref is None
    authority = StagedExecutionHarnessAuthority(build.builds, store,
                                                build.store)
    assert store.approval_refs(build.binding.execution_harness_id) == []
    assert authority.resolve(build.binding) == build.builds.resolve(
        build.binding)
    v.close()
    store.close()


def test_a_timeout_is_inconclusive(tmp_path, build):
    store, v = _validator(tmp_path, build, mode="sleep", timeout_s=0.5,
                          term_grace_s=0.5)
    st = _finish(v, "gen-1.a1.v1", build)
    assert (st.state, st.reason) == ("inconclusive", "command_timeout")
    v.close()
    store.close()


def test_submit_is_idempotent_by_task_id(tmp_path, build):
    store, v = _validator(tmp_path, build, mode="rejected")
    first = _finish(v, "gen-1.a1.v1", build)
    again = v.submit("gen-1.a1.v1", _input(build))
    assert again == first
    assert _runs(tmp_path) == ["gen-1.a1.v1 test-validate"]
    assert v.status("gen-1.a1.v2").state == "unknown"
    with pytest.raises(ValueError):
        v.submit("../escape", _input(build))
    v.close()
    store.close()


def test_one_process_owns_the_store(tmp_path, build):
    store, v = _validator(tmp_path, build)
    with pytest.raises(ValidatorBusy):
        CommandValidator(_config(tmp_path, "passed"), store, build.store,
                         tmp_path / "state" / "validation.lock")
    # A one-shot command reads statuses and leaves submits to the loop.
    deferred = DeferredValidator(store)
    with pytest.raises(ValidationDeferred):
        deferred.submit("gen-1.a1.v1", _input(build))
    assert deferred.status("gen-1.a1.v1").state == "unknown"
    v.close()
    store.close()


def _ticks(pid):
    raw = Path(f"/proc/{pid}/stat").read_text()
    return int(raw[raw.rindex(")") + 2:].split()[19])


def test_a_task_left_running_by_a_previous_process_is_inconclusive(
        tmp_path, build):
    """The earlier process died with its command running: the next one
    kills that session and reports runner_restart, so the Controller runs
    the validation again as a new task."""
    b = build
    (tmp_path / "state").mkdir()
    put_record(b.store, b.descriptor)
    store = ValidationStore(tmp_path / "state" / "validations.sqlite")
    left = subprocess.Popen([sys.executable, "-c", "import time; "
                             "time.sleep(120)"], start_new_session=True)
    try:
        assert store.insert("gen-1.a1.v1", _input(b))
        store.started("gen-1.a1.v1", left.pid, _ticks(left.pid),
                      Path("/proc/sys/kernel/random/boot_id")
                      .read_text().strip())
        # A recorded session id that is now someone else's is not killed.
        assert store.insert("gen-2.a1.v1", _input(b, "gen-2"))
        store.started("gen-2.a1.v1", os.getpid(), 1, "another-boot")
        (tmp_path / "hcap.json").write_bytes(b.store.get(b.hcap_ref))
        v = CommandValidator(_config(tmp_path, "passed"), store, b.store,
                             tmp_path / "state" / "validation.lock")
        assert left.wait(10) == -9
        for task_id in ("gen-1.a1.v1", "gen-2.a1.v1"):
            st = v.status(task_id)
            assert (st.state, st.reason) == ("inconclusive",
                                             "runner_restart")
        assert v.submit("gen-1.a1.v1", _input(b)).state == "inconclusive"
        assert not (tmp_path / "runs.txt").exists()
        v.close()
    finally:
        if left.poll() is None:
            left.kill()
            left.wait()
        store.close()


def test_close_stops_a_running_command(tmp_path, build):
    store, v = _validator(tmp_path, build, mode="sleep")
    v.submit("gen-1.a1.v1", _input(build))
    deadline = time.monotonic() + 10
    while not (tmp_path / "runs.txt").exists():
        assert time.monotonic() < deadline
        time.sleep(0.02)
    v.close(timeout_s=10)
    st = store.status("gen-1.a1.v1")
    assert (st.state, st.reason) == ("inconclusive", "command_stopped")
    store.close()


# ------------------------------------------------------------ the service


class ScriptedGenerator:
    """The generation Agent: answers each try with one stored patch set."""

    def __init__(self, store) -> None:
        self.store = store
        self.sink = None
        self.requests = []

    def start(self, request) -> None:
        self.requests.append(request)
        ref = put_record(self.store, HarnessPatchSet(
            generation_id=request.generation_id, task_id=request.task_id,
            attempt=request.attempt, gap=request.gap, base_commit="0" * 40,
            patch_ref=self.store.put(PATCH), files=("bundle/x",),
            summary="LOCK operation"))
        threading.Thread(target=self.sink.on_generation_result, args=(
            request.task_id, request.attempt,
            ExtensionOutput(patch_set_ref=ref))).start()


def test_a_gap_is_generated_validated_and_reached_on_the_staged_binding(
        tmp_path, build):
    """The whole path in the service: Planning reports a gap the base HCAP
    lists, generation answers a patch set, the host command passes it, and
    the job plans, materializes and reaches its target on the staged
    revision the validator approved."""
    from .test_stage1_service import (ScriptedRuntime, make_service,
                                      register_mapping, stopped, submit)
    b = build
    staged_ref = b.hcap_ref
    hcap = load_record(b.store, staged_ref, HcapCatalog)
    base_hcap = put_record(b.store, hcap.model_copy(update={
        "missing_capability_ids": (GAP.missing_capability_id,)}))
    base = b.binding.model_copy(update={"hcap_revision": base_hcap})
    registry = InMemoryRegistry()
    registry.put(base)
    static = StaticExecutionHarnessAuthority((ExecutionHarnessApproval(
        descriptor=b.descriptor, approved_hcap_revisions=(base_hcap,)),))
    store, validator = _validator(tmp_path, b, mode="same_build")
    b.materializer = ArtifactHarnessMaterializer(
        b.store, StagedExecutionHarnessAuthority(static, store, b.store),
        b.parser)

    class GapThenPlan(ScriptedRuntime):
        def run(self, request):
            if request.task.value == "reachability_planning" and \
                    "reachability_planning" not in self.calls:
                self.calls.append(request.task.value)
                value = request.output_type.model_validate_json(json.dumps(
                    UnsupportedOutput(
                        gap_class=GAP.gap_class,
                        missing_capability_id=GAP.missing_capability_id,
                        reason="no LOCK operation").model_dump(mode="json")))
                from agent_pipeline.agent_tasks.runtime import RuntimeResult
                return RuntimeResult(output=request.validate_output(value),
                                     model_id="test:scripted")
            return super().run(request)

    generator = ScriptedGenerator(b.store)
    with make_service(
            tmp_path, b, registry=registry, runtime=GapThenPlan(b),
            policies=(policy(harness_generation_budget=1),),
            generation=GenerationParts(executor=generator,
                                       validator=validator)) as service:
        job_id = submit(service, b)
        register_mapping(service, b, job_id)
        service.start_worker(idle_s=0.05)
        assert service.run(stopped(service, job_id), interval_s=0.05,
                           timeout_s=60)
        job = service.job(job_id)
        assert job.state is JobState.S1_REACHED, (
            job, service.store.effect_failures(job_id))
        assert job.binding.hcap_revision == staged_ref
        assert job.staged.binding == job.binding
        (g,) = service.store.generations()
        assert g.state is GenerationState.PASSED
        assert g.base_binding == base
        (request,) = generator.requests
        assert request.gap == GAP
        assert _runs(tmp_path) == [f"{g.generation_id}.a1.v1 test-validate"]
        assert service.parts.runtime.calls == [
            "candidate_analysis", "reachability_planning",
            "reachability_planning"]
        assert service.controller.replay(job_id) == job
    store.close()


def test_without_generation_parts_a_gap_still_falls_back(tmp_path, build):
    """Unchanged hosts: no generation configured, the gap blocks."""
    from .test_stage1_service import make_service
    with make_service(tmp_path, build) as service:
        assert service.generator is None
        assert service.controller.generations is None


def test_config_carries_the_generation_section():
    from agent_pipeline.stage1.config import HarnessGenerationConfig
    c = HarnessGenerationConfig.model_validate({
        "repo": "/srv/knfsd-syzkaller", "worktree_root": "/srv/gen",
        "launcher": ["/usr/bin/sudo", "-n", "-u", "harness-gen", "--"],
        "validation": {"argv": ["/srv/validate"], "cwd": "/srv",
                       "resource_key": "validate"}})
    assert c.validation.timeout_s == 14_400 and c.workers == 1
    with pytest.raises(ValueError):
        HarnessGenerationConfig.model_validate({
            "repo": "/r", "worktree_root": "/w", "launcher": ["sudo"],
            "validation": {"argv": ["/v"], "cwd": "/", "resource_key": "k"}})
    with pytest.raises(ValueError):
        HarnessGenerationConfig.model_validate({
            "repo": "/r", "worktree_root": "/w", "launcher": [],
            "validation": {"argv": ["/v"], "cwd": "/", "resource_key": "k"}})


def test_canonical_input_files(tmp_path, build):
    """The command's validation.json is the task id and the input, in
    canonical JSON."""
    store, v = _validator(tmp_path, build, mode="rejected")
    task_input = _input(build, base=False)
    v.submit("gen-1.a1.v1", task_input)
    assert v.wait(30)
    run = tmp_path / "state" / "validation-runs" / "gen-1.a1.v1" / "input"
    assert (run / "validation.json").read_bytes() == canonical_json(
        {"task_id": "gen-1.a1.v1", **task_input.model_dump(mode="json")})
    assert not (run / "base_hcap.json").exists()
    v.close()
    store.close()
