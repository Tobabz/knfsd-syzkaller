"""Runner-logic checks for tools/attr-scenario-run.py.

These exercise the parts that must hold without a live kernel: preflight refusal
(missing workload, stale SHA, non-forceable hook) with no output dir created, the
--reuse branch (refused on a NEW cell, copied on a SHA-eligible EXISTING cell
without booting), the counter-capture seam (only manifest-referenced files, both
snapshots, no fixed sleeps), and a full stubbed-VM run whose assembled evidence
dir is accepted by the real combined oracle.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import tarfile
import os
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
ENV_DIR = Path(os.environ.get("KOOV_ENV_DIR", str(ROOT / "env")))
RUNNER = ROOT / "tools" / "attr-scenario-run.py"
DATA = Path(__file__).parent / "data/attr-scenario"
B05_DIR = ROOT / "bundle/corpus/attr-scenarios/B05"
VMLINUX = ENV_DIR / "images/kcsan/vmlinux"
BASE_IMAGE = ENV_DIR / "images/bookworm-kcov-fresh-v1.raw"
BASE_IMAGE_SHA = "cb54598517cb4646f00c3a79e9e8ff9e1ec4a5159318c568b52f1b180e786cbd"
JsonObject = dict[str, Any]


def _load_runner() -> Any:
    spec = importlib.util.spec_from_file_location("attr_run", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


attr_run = _load_runner()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _scenario_dir(tmp_path: Path) -> Path:
    """A self-contained B05-V1 scenario dir (workload + fixture co-located)."""
    case = tmp_path / "scenario"
    case.mkdir()
    shutil.copy(B05_DIR / "B05-V1.json", case / "B05-V1.json")
    shutil.copy(B05_DIR / "reach-copy-offload-x2.prog", case / "reach-copy-offload-x2.prog")
    shutil.copy(B05_DIR / "ab-lane-fixture-v42.sh", case / "ab-lane-fixture-v42.sh")
    return case


def _positive_manifest(case: Path) -> JsonObject:
    """The task-5 positive fixture manifest; matches the shipped fixture data."""
    return {
        "id": "B05-V1", "boundary": "B05", "variant": "V1",
        "polarity": "positive", "workload": "workload.prog",
        "sha256": _sha256(case / "workload.prog"),
        "lane_fixture": "lane.sh", "hooks": [], "mode": "both",
        "counter_expect": [
            {"file": "phase8_stats", "name": "async_child_created", "op": "delta_eq", "value": 1},
            {"file": "phase8_stats", "name": "async_grant_ok", "op": "delta_ge", "value": 1},
            {"file": "phase8_stats", "name": "live_saved_work", "op": "eq", "value": 0},
            {"file": "phase8_stats", "name": "async_completed", "op": "ge", "value": 1},
            {"file": "phase8_stats", "name": "async_dropped", "op": "le", "value": 0},
        ],
        "drain_keys": [
            {"file": "phase8_stats", "name": "live_saved_work"},
            {"file": "phase5_state", "name": "live_tickets"},
            {"file": "phase5_state", "name": "remote_refs"},
            {"file": "phase6_state", "name": "live_scratch"},
            {"file": "phase6_state", "name": "remote_refs"},
            {"file": "phase6_state", "name": "scratch_in_use"},
        ],
        "sentinel": {
            "fs/nfsd": {
                "rule": "on-only", "required": ["nfsd4_do_async_copy"],
                "observed": ["nfsd4_copy"],
                "absent-on-only": ["nfsd4_run_cb_work"],
            }
        },
        "procs": 2, "executions": 10,
    }


# --------------------------------------------------------------------------
# Preflight: no output dir, no boot, when a precondition fails.
# --------------------------------------------------------------------------

def test_missing_workload_fails_preflight_without_output(tmp_path: Path, monkeypatch) -> None:
    case = _scenario_dir(tmp_path)
    (case / "reach-copy-offload-x2.prog").unlink()
    output = tmp_path / "evidence"
    monkeypatch.setattr(attr_run, "_load_module",
                        lambda *a, **k: pytest.fail("must not boot"))
    code = attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output)])
    assert code == 2
    assert not output.exists()


def test_stale_workload_sha_fails_preflight_without_output(tmp_path: Path, monkeypatch) -> None:
    case = _scenario_dir(tmp_path)
    prog = case / "reach-copy-offload-x2.prog"
    prog.write_bytes(prog.read_bytes() + b"\n# drift\n")
    output = tmp_path / "evidence"
    monkeypatch.setattr(attr_run, "_load_module",
                        lambda *a, **k: pytest.fail("must not boot"))
    code = attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output)])
    assert code == 2
    assert not output.exists()


def test_unforceable_hook_is_refused_before_boot(tmp_path: Path, monkeypatch) -> None:
    case = _scenario_dir(tmp_path)
    manifest = json.loads((case / "B05-V1.json").read_text())
    manifest.update({"id": "B04-V4", "boundary": "B04", "variant": "V4",
                     "hooks": [{"id": "v5.cancel-saved-work", "args": {}}]})
    (case / "B04-V4.json").write_text(json.dumps(manifest))
    output = tmp_path / "evidence"
    monkeypatch.setattr(attr_run, "_load_module",
                        lambda *a, **k: pytest.fail("must not boot"))
    code = attr_run.main(["--scenario", str(case / "B04-V4.json"),
                          "--output", str(output)])
    assert code == 2
    assert not output.exists()


# --------------------------------------------------------------------------
# --reuse: only for SHA-eligible EXISTING cells, never a boot.
# --------------------------------------------------------------------------

def _no_boot_loader(monkeypatch) -> None:
    """Permit importing helper tools (e.g. the matrix checker) but fail if the
    reach boot path is loaded -- reuse and preflight refusals must never boot."""
    real_load = attr_run._load_module

    def guard(name: str, path: Any) -> Any:
        if name == "attr_reach_runner":
            pytest.fail("must not boot")
        return real_load(name, path)

    monkeypatch.setattr(attr_run, "_load_module", guard)


def test_reuse_refused_on_new_matrix_cell(tmp_path: Path, monkeypatch) -> None:
    case = _scenario_dir(tmp_path)  # shipped matrix marks B05-V1 NEW
    output = tmp_path / "evidence"
    _no_boot_loader(monkeypatch)
    code = attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output), "--reuse"])
    assert code == 2
    assert not output.exists()


def _reuse_fixture(tmp_path: Path, monkeypatch, *, overall: str = "PASS",
                   stale_metadata: bool = False) -> Path:
    """Build a synthetic EXISTING cell in the exact evidence-file#named-check
    contract the real matrix checker accepts, wired to the real baseline inputs
    so their fresh actual hashes match unless a test perturbs them."""
    case = _scenario_dir(tmp_path)
    baseline = json.loads(attr_run.BASELINE_PATH.read_text())
    input_shas = {key: {"sha256": baseline["inputs"][key]["sha256"]}
                  for key in ("kernel", "vmlinux", "image", "deps_tar",
                              "syz_execprog", "syz_executor")}
    if stale_metadata:
        input_shas["kernel"]["sha256"] = "0" * 64
    existing = tmp_path / "existing-evidence"
    existing.mkdir()
    (existing / "metadata.json").write_text(json.dumps({"inputs": input_shas}))
    (existing / "verdict.json").write_text(
        json.dumps({"scenario": "B05-V1", "checks": {}, "overall": overall}))
    baseline["existing_evidence"] = [{"path": str(existing), "sha_match": True,
                                      "name": "synthetic",
                                      "metadata": str(existing / "metadata.json")}]
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline))
    matrix_path = tmp_path / "matrix.json"
    matrix_path.write_text(json.dumps(
        {"B05": {"V1": {"state": "EXISTING",
                        "ref": f"{existing / 'verdict.json'}#overall"}}}))
    monkeypatch.setattr(attr_run, "BASELINE_PATH", baseline_path)
    monkeypatch.setattr(attr_run, "MATRIX_PATH", matrix_path)
    _no_boot_loader(monkeypatch)
    return case


def test_reuse_copies_matrix_eligible_verdict_without_boot(tmp_path: Path, monkeypatch) -> None:
    case = _reuse_fixture(tmp_path, monkeypatch)
    output = tmp_path / "evidence"
    code = attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output), "--reuse"])
    assert code == 0
    assert json.loads((output / "attr_verdict_B05-V1.json").read_text())["overall"] == "PASS"
    assert json.loads((output / "attr_verdict.json").read_text())["overall"] == "PASS"
    assert not (output / "remote_on").exists()  # no VM evidence


def test_reuse_refused_when_named_check_failed(tmp_path: Path, monkeypatch) -> None:
    case = _reuse_fixture(tmp_path, monkeypatch, overall="FAIL")
    output = tmp_path / "evidence"
    assert attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output), "--reuse"]) == 2
    assert not output.exists()


def test_reuse_refused_on_stale_metadata(tmp_path: Path, monkeypatch) -> None:
    case = _reuse_fixture(tmp_path, monkeypatch, stale_metadata=True)
    output = tmp_path / "evidence"
    assert attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output), "--reuse"]) == 2
    assert not output.exists()


def test_reuse_refused_when_actual_input_changed(tmp_path: Path, monkeypatch) -> None:
    case = _reuse_fixture(tmp_path, monkeypatch)
    # The recorded baseline SHAs still match metadata, but the actual file on
    # disk differs: cached sha_match alone must not authorize reuse.
    baseline_path = attr_run.BASELINE_PATH
    baseline = json.loads(baseline_path.read_text())
    fake_kernel = tmp_path / "fake-bzImage"
    fake_kernel.write_bytes(b"not the baseline kernel")
    baseline["inputs"]["kernel"]["path"] = str(fake_kernel)
    baseline_path.write_text(json.dumps(baseline))
    output = tmp_path / "evidence"
    assert attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output), "--reuse"]) == 2
    assert not output.exists()


# --------------------------------------------------------------------------
# Counter-capture seam: only referenced files, both snapshots, no sleeps.
# --------------------------------------------------------------------------

class _FakeVM:
    """Serves the task-5 fixture stats text, choosing pre/post from the stage."""

    def __init__(self, source: Path) -> None:
        self.source = source
        self.stages: list[str] = []

    def guest(self, stage: str, command: str, timeout: int = 60,
              check: bool = True) -> Any:
        self.stages.append(stage)
        _, phase, name = stage.split("-", 2)
        text = (self.source / phase / f"{name}.txt").read_text(encoding="utf-8")
        return type("R", (), {"stdout": text, "stderr": "", "returncode": 0})()


def test_attrplan_captures_only_referenced_files_both_phases(tmp_path: Path) -> None:
    case = tmp_path / "case"
    case.mkdir()
    (case / "workload.prog").write_bytes(b"prog\n")
    (case / "lane.sh").write_text("#!/bin/sh\n")
    manifest = _positive_manifest(case)
    output = tmp_path / "out"
    output.mkdir()
    plan = attr_run.AttrPlan(output, manifest, [])
    vm = _FakeVM(DATA / "positive")

    plan.before_workload(vm, "off")   # OFF is a no-op
    assert not (output / "counters").exists()
    plan.before_workload(vm, "on")
    plan.after_workload(vm, "on")

    assert plan.captured == {"pre": True, "post": True}
    for phase in ("pre", "post"):
        files = {p.name for p in (output / "counters" / phase).glob("*.txt")}
        assert files == {"phase8_stats.txt", "phase5_state.txt", "phase6_state.txt"}
    # No unparseable multi-lane *_state file was pulled in beyond what the
    # manifest references, and no phase*_stats we did not ask for.
    assert "async_child_created" in (output / "counters/post/phase8_stats.txt").read_text()


PHASE8 = (DATA / "positive/pre/phase8_stats.txt").read_text(encoding="utf-8")


def _hook_entry(hook_id: str, args: JsonObject | None = None) -> JsonObject:
    from tools.attr_hooks import hook_result
    args = args or {}
    return {"id": hook_id, "args": args,
            "manifest": hook_result(hook_id, dry_run=False, args=args)}


def _hook_manifest(hooks: list[JsonObject]) -> JsonObject:
    return {
        "id": "B05-V2", "boundary": "B05", "variant": "V2", "polarity": "positive",
        "workload": "w.prog", "sha256": "0" * 64, "lane_fixture": "l.sh",
        "hooks": hooks, "mode": "both",
        "counter_expect": [{"file": "phase8_stats", "name": "async_grant_ok",
                            "op": "delta_ge", "value": 1}],
        "drain_keys": [{"file": "phase8_stats", "name": "live_saved_work"}],
        "sentinel": {"fs/nfsd": {"rule": "on-only", "required": ["x"], "observed": []}},
        "procs": 2, "executions": 10,
    }


class _RecordVM:
    def __init__(self, baseline: str, observations: list[str]) -> None:
        self.stages: list[str] = []
        self.baseline = baseline
        self.observations = observations
        self.observe_calls = 0
        self.fail_release = False

    def guest(self, stage: str, command: str, timeout: int = 60,
              check: bool = True) -> Any:
        self.stages.append(stage)
        if self.fail_release and stage.endswith("-release"):
            raise RuntimeError("review cleanup failed")
        if stage.startswith("attr-pre-") or stage.startswith("attr-post-"):
            text = PHASE8
        elif stage.startswith("attr-baseline-"):
            text = self.baseline
        elif "observe" in stage:
            index = min(self.observe_calls, len(self.observations) - 1)
            text = self.observations[index]
            self.observe_calls += 1
        else:
            text = ""
        return type("R", (), {"stdout": text, "stderr": "", "returncode": 0})()


_ALL_STAGES = sorted(attr_run._STAGE_ROLE, key=len, reverse=True)


def _labelled(stages: list[str]) -> list[str]:
    labels: list[str] = []
    for stage in stages:
        if stage.startswith("attr-pre-"):
            label = "PRE"
        elif stage.startswith("attr-post-"):
            label = "POST"
        elif stage.startswith("attr-baseline-"):
            label = "BASELINE"
        elif stage.startswith("hook-"):
            label = next((s for s in _ALL_STAGES if stage.endswith("-" + s)), stage)
        else:
            label = stage
        if not labels or labels[-1] != label:
            labels.append(label)
    return labels


def _drive(plan: Any, vm: _RecordVM) -> None:
    plan.before_workload(vm, "on")
    vm.stages.append("EXECUTOR_START")
    plan.during_workload(vm, "on")
    vm.stages.append("DRAIN")
    plan.after_workload(vm, "on")


def test_generation_abort_without_live_owner_is_rejected_before_boot() -> None:
    with pytest.raises(attr_run.PreflightError, match="stage 'abort'.*no lifecycle role"):
        attr_run.validate_hook_stages([_hook_entry("v4.generation-abort-ioctl", {
            "hook_dir": "/tmp/h", "kcov_fd": 9, "generation": 1})])


def test_pause_observes_exact_increment_and_releases_live_executor(tmp_path: Path) -> None:
    hook = _hook_entry("v4.pause-release-async-after-grant")
    plan = attr_run.AttrPlan(tmp_path, _hook_manifest([]), [hook])
    vm = _RecordVM(
        "async_pause_after_grant_entered 7\nasync_pause_after_grant_released 9\n",
        ["async_pause_after_grant_entered 8\nasync_pause_after_grant_released 9\n"])
    _drive(plan, vm)
    labels = _labelled(vm.stages)
    assert labels.index("EXECUTOR_START") < labels.index("observe-entered")
    assert labels.index("release") < labels.index("DRAIN")


def test_redefer_executor_lookup_starts_before_waiting_for_pause(tmp_path: Path) -> None:
    hook = _hook_entry("v5.redefer-cache-revisit")
    plan = attr_run.AttrPlan(tmp_path, _hook_manifest([]), [hook])
    baseline = ("deferred_pause_after_grant_entered 3\n"
                "deferred_pause_after_grant_released 3\ndeferred_redeferred 4\n")
    observations = [
        "deferred_pause_after_grant_entered 4\ndeferred_redeferred 4\n",
        "deferred_pause_after_grant_entered 4\ndeferred_redeferred 5\n",
    ]
    vm = _RecordVM(baseline, observations)
    _drive(plan, vm)
    labels = _labelled(vm.stages)
    assert labels.index("hold-initial-cache") < labels.index("EXECUTOR_START")
    assert labels.index("EXECUTOR_START") < labels.index("resume-first-cache")
    assert labels.index("resume-first-cache") < labels.index("observe-replay-pause")
    assert labels.index("release-replay") < labels.index("observe-redefer")
    assert labels.index("observe-redefer") < labels.index("resume-second-cache-cleanup")
    assert labels.index("resume-second-cache-cleanup") < labels.index("DRAIN")


@pytest.mark.parametrize("observation", [
    "async_pause_after_grant_entered 7\nasync_pause_after_grant_released 100\n",
    "async_pause_after_grant_entered 7\ndeferred_pause_after_grant_entered 100\n",
])
def test_stale_or_unrelated_counter_cannot_satisfy_observe(
        tmp_path: Path, monkeypatch, observation: str) -> None:
    ticks = iter((0.0, 1.0))
    monkeypatch.setattr(attr_run.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(attr_run.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(attr_run, "OBSERVE_TIMEOUT_S", 0.5)
    hook = _hook_entry("v4.pause-release-async-after-grant")
    plan = attr_run.AttrPlan(tmp_path, _hook_manifest([]), [hook])
    vm = _RecordVM(
        "async_pause_after_grant_entered 7\nasync_pause_after_grant_released 9\n",
        [observation])
    plan.before_workload(vm, "on")
    with pytest.raises(RuntimeError, match="did not increment past 7"):
        plan.during_workload(vm, "on")


def test_malformed_observation_is_surfaced(tmp_path: Path) -> None:
    hook = _hook_entry("v4.pause-release-async-after-grant")
    plan = attr_run.AttrPlan(tmp_path, _hook_manifest([]), [hook])
    vm = _RecordVM("async_pause_after_grant_entered 0\n", ["malformed counter\n"])
    plan.before_workload(vm, "on")
    with pytest.raises(Exception, match="phase8_stats:1: malformed counter line"):
        plan.during_workload(vm, "on")


def test_cleanup_error_is_surfaced(tmp_path: Path) -> None:
    hook = _hook_entry("v4.pause-release-async-after-grant")
    plan = attr_run.AttrPlan(tmp_path, _hook_manifest([]), [hook])
    vm = _RecordVM("async_pause_after_grant_entered 0\n", [""])
    plan.before_workload(vm, "on")
    vm.fail_release = True
    with pytest.raises(RuntimeError, match="review cleanup failed"):
        plan.cleanup(vm, "on")


def test_real_attrplan_run_trial_resumes_second_responder_before_completion(
        tmp_path: Path, monkeypatch) -> None:
    """Compose actual AttrPlan + run_trial with completion gated on final resume."""
    reach = attr_run._load_module("reach_redefer_lifecycle", attr_run.REACH_RUNNER)
    instances: list[Any] = []

    class VM:
        ready = True
        scp: list[str] = []

        def __init__(self, _args: Any, _evidence: Any, fail_observe: bool) -> None:
            self.events: list[str] = []
            self.responder_stopped = False
            self.final_resume = False
            self.entered = 7
            self.redeferred = 4
            self.fail_observe = fail_observe

        def counters(self) -> str:
            return (f"deferred_pause_after_grant_entered {self.entered}\n"
                    f"deferred_pause_after_grant_released {self.entered}\n"
                    f"deferred_redeferred {self.redeferred}\n")

        def start(self) -> None:
            self.events.append("boot")

        def put(self, *args: Any, **kwargs: Any) -> None:
            pass

        def guest(self, stage: str, command: str, timeout: int = 60,
                  check: bool = True) -> Any:
            self.events.append(stage)
            stdout, rc = "", 0
            if stage == "allocate-root":
                stdout = "/tmp/frozen-phase9.fake\n"
            elif stage == "fixture-setup":
                stdout = "{}"
            elif stage.startswith("attr-pre-") or stage.startswith("attr-post-"):
                stdout = PHASE8
            elif stage.startswith("attr-baseline-"):
                stdout = self.counters()
            elif stage.endswith("-hold-initial-cache"):
                self.responder_stopped = True
            elif stage.endswith("-resume-first-cache"):
                self.responder_stopped = False
                self.entered += 1
            elif stage.endswith("-observe-replay-pause"):
                stdout = self.counters()
            elif stage.endswith("-invalidate-at-replay"):
                self.responder_stopped = True
            elif stage.endswith("-release-replay"):
                self.redeferred += 1
            elif stage.endswith("-observe-redefer"):
                if self.fail_observe:
                    raise RuntimeError("negative re-defer observation")
                stdout = self.counters()
            elif stage.endswith("-resume-second-cache-cleanup"):
                self.responder_stopped = False
                self.final_resume = True
            elif stage == "executor-start":
                assert self.responder_stopped
                stdout = "123\n"
            elif stage == "executor-poll":
                assert self.final_resume and not self.responder_stopped, (
                    "executor cannot complete until second responder resumes")
            elif stage == "executor-meta":
                stdout = "rc 0\nstart_ns 1\nend_ns 2\n"
            elif stage == "cpu-after":
                stdout = "cpu 2 0 0 2 0 0 0 0\n"
            elif stage == "executor-log":
                stdout = "ok\n"
            elif stage == "callback-trace-stop":
                stdout = "trace\n"
            return type("R", (), {"stdout": stdout, "stderr": "", "returncode": rc})()

        def stop(self) -> None:
            self.events.append("STOP")

    class Phase1:
        write_evidence: Any = None
        fail_observe = False

        @classmethod
        def FrozenPhase1VM(cls, args: Any, evidence: Any) -> VM:
            vm = VM(args, evidence, cls.fail_observe)
            instances.append(vm)
            return vm

    class Phase9:
        @staticmethod
        def validate_fixture_status(value: Any, procs: int) -> JsonObject:
            return {}

        @staticmethod
        def validate_source_tree(*args: Any) -> None:
            pass

        @staticmethod
        def lane_snapshot(vm: VM, modules: Any, root: str, lane: int,
                          stage: str) -> JsonObject:
            return {"nfsd_rpcs": 0}

        @staticmethod
        def memory_snapshot(vm: VM, stage: str) -> JsonObject:
            return {"mem_used_kib": 1, "process_rss_kib": 1}

        @staticmethod
        def wait_for_drains(vm: VM, modules: Any, root: str, procs: int,
                            timeout: int) -> list[JsonObject]:
            vm.events.append("DRAIN")
            assert vm.final_resume and not vm.responder_stopped
            return [{"nfsd_rpcs": 1, "phase6": {"stats": {"scratch_peak": 0}}}]

        @staticmethod
        def cleanup_fixture(*args: Any, **kwargs: Any) -> JsonObject:
            return {}

    image = tmp_path / "image.raw"
    image.write_bytes(b"unchanged")
    dummy = tmp_path / "dummy"
    dummy.write_bytes(b"x")
    args = type("Args", (), {
        "image": image, "deps_tar": dummy, "lane_fixture": dummy,
        "workload": dummy, "syz_executor": dummy, "syz_execprog": dummy,
        "procs": 1, "executions": 1, "trial_timeout": 1,
    })()
    monkeypatch.setattr(reach, "cpu_snapshot", lambda vm, stage: {"total": 1, "idle": 0})
    monkeypatch.setattr(reach, "cpu_percent", lambda before, after: 1.0)
    monkeypatch.setattr(reach, "pull", lambda vm, stage, remote, local: local.write_bytes(b"x"))
    monkeypatch.setattr(reach, "extract_cover", lambda archive, destination: [])
    monkeypatch.setattr(reach, "validate_executor_log", lambda log, executions, procs: {
        "call_count": 1, "local_coverage_records_reported": 1})
    monkeypatch.setattr(reach, "validate_cover_files", lambda *args: {
        "raw_pc_records": 1, "extra_files": 1})
    monkeypatch.setattr(reach, "counter_diagnostics", lambda before, after: {
        "phase6": {"aggregate_committed": 0, "aggregate_discarded": 0}})
    monkeypatch.setattr(reach, "validate_gate", lambda *args: ({}, []))

    hook = _hook_entry("v5.redefer-cache-revisit", {
        "hook_dir": "/tmp/hooks", "server_pid": 42})
    manifest = _hook_manifest([{"id": hook["id"], "args": hook["args"]}])
    plan = attr_run.AttrPlan(tmp_path / "positive-plan", manifest, [hook])
    trial = tmp_path / "trial"
    result = reach.run_trial(args, object(), Phase1, Phase9, "on", 1, trial,
                             attr_plan=plan)
    assert result["status"] == "pass"
    vm = instances[-1]
    observe = next(i for i, value in enumerate(vm.events)
                   if value.endswith("-observe-redefer"))
    resume = next(i for i, value in enumerate(vm.events)
                  if value.endswith("-resume-second-cache-cleanup"))
    assert observe < resume < vm.events.index("executor-poll") < vm.events.index("DRAIN")
    assert sum(value.endswith("-resume-second-cache-cleanup")
               for value in vm.events) == 1

    Phase1.fail_observe = True
    failed_plan = attr_run.AttrPlan(tmp_path / "negative-plan", manifest, [hook])
    failed_trial = tmp_path / "failed-trial"
    with pytest.raises(RuntimeError, match="negative re-defer observation"):
        reach.run_trial(args, object(), Phase1, Phase9, "on", 1, failed_trial,
                        attr_plan=failed_plan)
    failed_vm = instances[-1]
    assert "executor-poll" not in failed_vm.events
    assert failed_vm.final_resume and not failed_vm.responder_stopped
    assert failed_vm.events.index("hook-v5.redefer-cache-revisit-resume-second-cache-cleanup") < failed_vm.events.index("STOP")
    failed_evidence = json.loads((failed_trial / "trial_evidence.json").read_text())
    assert failed_evidence["status"] == "fail"
    assert failed_evidence["failure"]["message"] == "negative re-defer observation"


# --------------------------------------------------------------------------
# Full stubbed-VM run: assembled evidence dir is accepted by the real oracle.
# --------------------------------------------------------------------------

def _fake_reach_module(distinct_dmesg: bool = True) -> Any:
    """A stand-in for run-reach-adapted-window.py that fabricates a two-mode
    baked-VM run and drives the attr_plan seam in the real order, writing
    per-mode serial/dmesg/coverage so the runner's log-exposure and tar contract
    can be checked without a VM."""
    module = type("M", (), {})()

    def main(argv: list[str], attr_plan: Any = None) -> None:
        args = dict(zip(argv[0::2], argv[1::2]))
        output = Path(args["--output"])
        output.mkdir(parents=True)
        (output / "remote_off").mkdir()
        (output / "remote_on").mkdir()
        shutil.copytree(DATA / "coverage_sets", output / "coverage_sets")
        vm = _FakeVM(DATA / "positive")
        for mode in ("off", "on"):
            trial = output / f"remote_{mode}" / "trial_01"
            trial.mkdir(parents=True)
            (trial / "serial.log").write_text(f"serial for remote_{mode}\n")
            marker = f"===remote_{mode}=== BUG-MARKER-{mode}\n" if distinct_dmesg else "clean\n"
            (trial / "dmesg.txt").write_text(marker)
            shutil.copy(DATA / f"remote_{mode}/trial_01/callback-trace.txt",
                        trial / "callback-trace.txt")
            (trial / "coverage").mkdir()
            (trial / "coverage" / "cover_prog1.1").write_text("0x1\n")
            (trial / "coverage.tar.gz").write_bytes(b"stub")
            if mode == "on":
                attr_plan.before_workload(vm, "on")
                attr_plan.during_workload(vm, "on")
                attr_plan.after_workload(vm, "on")

    module.main = main
    return module


def _stub_tools(tmp_path: Path, monkeypatch) -> None:
    """Decouple from the task16-owned oracle and from analyze: both are stubbed;
    this test proves the RUNNER's assembly and hand-off, not oracle semantics."""
    stub_analyze = tmp_path / "stub_analyze.py"
    stub_analyze.write_text("import sys; sys.exit(0)\n")  # coverage_sets pre-written
    stub_assert = tmp_path / "stub_assert.py"
    stub_assert.write_text(
        "import json,sys\n"
        "a=dict(zip(sys.argv[1::2],sys.argv[2::2]))\n"
        "open(a['--out'],'w').write(json.dumps({'scenario':'B05-V1','overall':'PASS'}))\n"
        "sys.exit(0)\n")
    monkeypatch.setattr(attr_run, "ANALYZE_TOOL", stub_analyze)
    monkeypatch.setattr(attr_run, "ASSERT_TOOL", stub_assert)
    monkeypatch.setattr(attr_run, "_load_module",
                        lambda name, path: _fake_reach_module())


def test_full_stubbed_run_assembles_and_exposes_both_modes(tmp_path: Path, monkeypatch) -> None:
    if not BASE_IMAGE.is_file():
        pytest.skip("baked image not present on this host")
    case = tmp_path / "scenario"
    case.mkdir()
    (case / "workload.prog").write_bytes((DATA / "workload.prog").read_bytes())
    (case / "lane.sh").write_bytes((DATA / "lane.sh").read_bytes())
    manifest = _positive_manifest(case)
    (case / "B05-V1.json").write_text(json.dumps(manifest))
    _stub_tools(tmp_path, monkeypatch)

    output = tmp_path / "evidence"
    code = attr_run.main(["--scenario", str(case / "B05-V1.json"),
                          "--output", str(output)])
    assert code == 0
    # Runner hand-off + assembly.
    assert json.loads((output / "attr_verdict_B05-V1.json").read_text())["overall"] == "PASS"
    assert (output / "attr_verdict.json").is_file()
    run = json.loads((output / "run.json").read_text())
    assert run["id"] == "B05-V1" and run["hooks"] == []
    assert run["inputs"]["workload"]["sha256"] == manifest["sha256"]
    assert (output / "image-before.sha256").read_text().strip() == BASE_IMAGE_SHA
    assert (output / "image-after.sha256").read_text().strip() == BASE_IMAGE_SHA
    # Counters captured in both phases (pre before triggers, post after drains).
    for phase in ("pre", "post"):
        assert (output / "counters" / phase / "phase8_stats.txt").is_file()
    # G7-01/G7-05: BOTH per-mode dmesg/serial exposed; OFF diagnostics not lost.
    for mode in ("off", "on"):
        assert (output / f"dmesg.remote_{mode}.txt").is_file()
        assert (output / f"serial.remote_{mode}.txt").is_file()
    combined = (output / "dmesg.txt").read_text()
    assert "BUG-MARKER-off" in combined and "BUG-MARKER-on" in combined
    serial = (output / "serial.log").read_text()
    assert "remote_off" in serial and "remote_on" in serial
    # Tar carries BOTH modes' raw pair, not ON-only.
    with tarfile.open(output / "raw-evidence.tar.gz") as tar:
        names = tar.getnames()
    assert any(n.startswith("remote_off/") for n in names)
    assert any(n.startswith("remote_on/") for n in names)
    for mode in ("off", "on"):
        assert f"remote_{mode}/serial.log" in names
        assert f"remote_{mode}/dmesg.txt" in names


def test_tar_errors_when_required_member_missing(tmp_path: Path) -> None:
    output = tmp_path / "out"
    (output / "remote_on" / "trial_01").mkdir(parents=True)
    (output / "remote_on" / "trial_01" / "serial.log").write_text("x")
    (output / "remote_on" / "trial_01" / "dmesg.txt").write_text("x")
    # coverage.tar.gz deliberately absent
    with pytest.raises(RuntimeError, match="required raw evidence missing"):
        attr_run._tar_raw_evidence(output, ("on",))


# --------------------------------------------------------------------------
# G7-06: retry only the literal SSH deadline; preserve first attempt.
# --------------------------------------------------------------------------

class _FlakyReach:
    def __init__(self, first_error: str | None) -> None:
        self.first_error = first_error
        self.calls: list[int] = []

    def main(self, argv: list[str], attr_plan: Any = None) -> None:
        args = dict(zip(argv[0::2], argv[1::2]))
        budget = int(args["--boot-timeout"])
        self.calls.append(budget)
        output = Path(args["--output"])
        output.mkdir(parents=True, exist_ok=True)
        (output / "serial.log").write_text(f"attempt boot-timeout={budget}\n")
        if self.first_error and len(self.calls) == 1:
            raise RuntimeError(self.first_error)


def _manifest_obj(case: Path) -> JsonObject:
    return json.loads((case / "B05-V1.json").read_text())


def test_ssh_deadline_retried_once_at_360_preserving_first_attempt(tmp_path: Path) -> None:
    case = _scenario_dir(tmp_path)
    baseline = json.loads(attr_run.BASELINE_PATH.read_text())
    reach = _FlakyReach("timed out waiting for guest SSH")
    output = tmp_path / "evidence"
    plan = attr_run.AttrPlan(output, _manifest_obj(case), [])
    attr_run._run_vm(reach, _manifest_obj(case), case / "B05-V1.json",
                     baseline, output, plan)
    assert reach.calls == [180, 360]
    assert (output.with_name(output.name + ".boot-timeout-attempt1")).is_dir()


def test_early_qemu_exit_is_not_retried(tmp_path: Path) -> None:
    case = _scenario_dir(tmp_path)
    baseline = json.loads(attr_run.BASELINE_PATH.read_text())
    reach = _FlakyReach("QEMU exited before SSH became ready")
    output = tmp_path / "evidence"
    plan = attr_run.AttrPlan(output, _manifest_obj(case), [])
    with pytest.raises(RuntimeError, match="QEMU exited"):
        attr_run._run_vm(reach, _manifest_obj(case), case / "B05-V1.json",
                         baseline, output, plan)
    assert reach.calls == [180]  # no retry


def test_other_failure_is_surfaced_not_retried(tmp_path: Path) -> None:
    case = _scenario_dir(tmp_path)
    baseline = json.loads(attr_run.BASELINE_PATH.read_text())
    reach = _FlakyReach("fixture setup rc=1")
    output = tmp_path / "evidence"
    plan = attr_run.AttrPlan(output, _manifest_obj(case), [])
    with pytest.raises(RuntimeError, match="fixture setup"):
        attr_run._run_vm(reach, _manifest_obj(case), case / "B05-V1.json",
                         baseline, output, plan)
    assert reach.calls == [180]
