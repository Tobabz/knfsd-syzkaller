"""Deterministic B06 recall observer and fail-closed counterexamples."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from tools.reach_callback import b06_recall_witness

ROOT = Path(__file__).resolve().parents[2]


def _load_runner():
    path = ROOT / "tools/run-reach-adapted-window.py"
    spec = importlib.util.spec_from_file_location("b06_reach_runner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _line(pid: int, stamp: int, event: str, fields: str = "") -> str:
    return f"task-{pid} [000] ..... 1.{stamp:06d}: {event}: {fields}\n"


def _trace() -> str:
    lines = [
        "# entries-in-buffer/entries-written: 12/12\n",
        _line(1, 1, "tracing_mark_write", "b06-recall-begin"),
        _line(101, 2, "nfs4_set_delegation", "fmode=READ fileid=00:01:7 fhandle=0xaabbccdd"),
        _line(202, 3, "nfsd_cb_recall", "addr=10.0.0.2:0 client 11111111:22222222 stateid 00000001:00000002"),
        _line(202, 4, "nfsd_cb_queue", "addr=10.0.0.2:0 client 11111111:22222222 cb=0x1 (first try) opcode=CB_RECALL"),
        _line(202, 5, "workqueue_queue_work", "work struct=0xfeed function=nfsd4_run_cb_work workqueue=nfsd4_callbacks"),
        _line(303, 6, "workqueue_execute_start", "work struct 0xfeed: function nfsd4_run_cb_work"),
        _line(303, 7, "nfsd_cb_start", "addr=10.0.0.2:0 client 11111111:22222222 state=UP"),
        _line(303, 8, "workqueue_execute_end", "work struct 0xfeed: function nfsd4_run_cb_work"),
        _line(404, 9, "svc_process_bc_entry", "(svc_process_bc+0x0/0x100)"),
        _line(404, 10, "nfs4_cb_recall", "error=0 (OK) fileid=00:01:7 fhandle=0xaabbccdd stateid=1:0x2 dstaddr=10.0.0.1"),
        _line(406, 11, "nfsd_cb_recall_done", "client 11111111:22222222 stateid 00000001:00000002 status=0"),
        _line(1, 12, "tracing_mark_write", "b06-recall-end"),
    ]
    return "".join(lines)


def _verdict(tmp_path: Path, text: str, before: int = 4, after: int = 5,
             attributed: bool = False):
    path = tmp_path / "callback-trace.txt"
    path.write_text(text, encoding="utf-8")
    return b06_recall_witness(path, before, after, 60.0, True, attributed)


def test_complete_chain_is_observed_and_ownerless(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _trace())
    assert verdict["assert"] is True
    assert verdict["status"] == "OBSERVED_OWNERLESS_KCOV"
    assert verdict["matched_recalls"] == 1
    assert verdict["record_backchannel"] == {"before": 4, "after": 5, "delta": 1}


def test_repeated_executions_correlate_within_each_recall_window(tmp_path: Path) -> None:
    first = _trace().splitlines(True)
    second = "".join(first[2:-1])
    second = re.sub(r"1\.000(\d{3})", r"1.100\1", second)
    second = (second.replace("11111111:22222222", "33333333:44444444")
              .replace("0xaabbccdd", "0x11223344")
              .replace("0xfeed", "0xcafe")
              .replace("00000001:00000002", "00000003:00000004"))
    text = (first[0] + first[1] + "".join(first[2:-1]) + second +
            _line(1, 200000, "tracing_mark_write", "b06-recall-end"))
    verdict = _verdict(tmp_path, text, before=4, after=6)
    assert verdict["assert"] is True
    assert verdict["matched_recalls"] == 2


@pytest.mark.parametrize(
    ("mutation", "failed_check"),
    [
        (lambda text: "".join(line for line in text.splitlines(True)
                               if ": nfs4_set_delegation:" not in line),
         "delegation_grant_observed"),
        (lambda text: text.replace("work struct 0xfeed: function", "work struct 0xbeef: function", 1),
         "complete_recall_chain_observed"),
        (lambda text: "".join(line for line in text.splitlines(True)
                               if ": nfs4_cb_recall:" not in line),
         "complete_recall_chain_observed"),
        (lambda text: re.sub(r" fhandle=\S+", "", text),
         "required_identities_present"),
        (lambda text: text.replace(" stateid 00000001:00000002", ""),
         "required_identities_present"),
        (lambda text: text.replace("task-404 [000] ..... 1.000010: nfs4_cb_recall",
                                   "task-999 [000] ..... 1.000010: nfs4_cb_recall"),
         "complete_recall_chain_observed"),
        (lambda text: text.replace("nfs4_cb_recall: error=0",
                                   "nfs4_cb_recall: error=10025"),
         "complete_recall_chain_observed"),
        (lambda text: text.replace("stateid=1:0x2", "stateid="),
         "required_identities_present"),
        (lambda text: text.replace("(svc_process_bc+0x0/0x100)", "not-a-probe"),
         "required_identities_present"),
        (lambda text: text.replace("addr=10.0.0.2:0 client 11111111:22222222 cb=",
                                   "addr=10.0.0.9:0 client 11111111:22222222 cb="),
         "complete_recall_chain_observed"),
        (lambda text: text.replace("stateid 00000001:00000002 status=0",
                                   "stateid 00000009:deadbeef status=0"),
         "complete_recall_chain_observed"),
        (lambda text: text.replace("status=0", "status=10025"),
         "complete_recall_chain_observed"),
    ],
)
def test_missing_or_uncorrelated_physical_events_are_not_observed(
        tmp_path: Path, mutation, failed_check: str) -> None:
    verdict = _verdict(tmp_path, mutation(_trace()))
    assert verdict["assert"] is False
    assert verdict["status"] == "NOT_OBSERVED"
    assert verdict["checks"][failed_check] is False


def test_backchannel_counter_must_advance(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _trace(), before=7, after=7)
    assert verdict["status"] == "NOT_OBSERVED"
    assert verdict["checks"]["record_backchannel_positive"] is False


def test_stale_or_malformed_trace_fails_closed(tmp_path: Path) -> None:
    stale = _trace().replace("b06-recall-end", "b06-recall-begin\n" +
                             "task-1 [000] ..... 1.000013: tracing_mark_write: b06-recall-end")
    verdict = _verdict(tmp_path, stale)
    assert verdict["status"] == "NOT_OBSERVED"
    assert verdict["checks"]["workload_bracketed"] is False


def test_observed_attributed_kcov_is_explicit_failure(tmp_path: Path) -> None:
    verdict = _verdict(tmp_path, _trace(), attributed=True)
    assert verdict["assert"] is False
    assert verdict["status"] == "OBSERVED_ATTRIBUTED_KCOV"
    assert verdict["checks"]["svc_process_bc_ownerless"] is False


def test_preflight_pins_b06_runtime_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = _load_runner()
    fixture = ROOT / "tools/ab-lane-fixture.sh"
    workload = ROOT / "bundle/corpus/nfs-normal/delegation-recall-v41-tcp.prog"
    args = SimpleNamespace(callback_observer="b06-recall", lane_fixture=fixture,
                           workload=workload, procs=1)
    calls = [line for line in workload.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    assert len(calls) == runner.B06_EXPECTED_CALLS == 15
    monkeypatch.setattr(runner, "EXPECTED_CALLS", 15)
    monkeypatch.setattr(runner, "CONFLICT_CALL", -1)
    assert runner.b06_preflight(args)["status"] == "READY"
    monkeypatch.setattr(runner, "EXPECTED_CALLS", 16)
    assert runner.b06_preflight(args)["status"] == "INVALID"
    monkeypatch.setattr(runner, "EXPECTED_CALLS", 15)
    args.procs = 2
    assert runner.b06_preflight(args)["status"] == "INVALID"


@pytest.mark.parametrize("cleanup_fails", [False, True])
def test_partial_arm_failure_runs_real_teardown_and_surfaces_cleanup_error(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        cleanup_fails: bool) -> None:
    runner = _load_runner()

    class VM:
        ready = True
        scp: list[str] = []

        def __init__(self, _args, _evidence):
            self.events: list[str] = []
            self.trace_instance_exists = False
            self.tracing_on = False
            self.probe_registered = False
            self.cleanup_attempts = 0

        def start(self) -> None:
            self.events.append("start")

        def put(self, *args, **kwargs) -> None:
            pass

        def guest(self, stage: str, command: str, timeout: int = 60,
                  check: bool = True):
            self.events.append(stage)
            if stage == "allocate-root":
                stdout = "/tmp/frozen-phase9.partial\n"
            elif stage == "fixture-setup":
                stdout = "{}"
            elif stage == "callback-trace-start":
                instance = trace_root / "instances/reach_callback"
                (instance / "events").mkdir(parents=True)
                (instance / "tracing_on").write_text("1\n")
                (instance / "trace").write_text("partial trace\n")
                (instance / "events/enable").write_text("1\n")
                (trace_root / "kprobe_events").write_text(
                    "p:b06/svc_process_bc_entry svc_process_bc\n")
                self.trace_instance_exists = True
                self.tracing_on = True
                self.probe_registered = True
                raise RuntimeError("injected partial arm failure")
            elif stage == "callback-trace-cleanup":
                self.cleanup_attempts += 1
                root_assignment = "root=" + shlex.quote(str(trace_root))
                script = command.replace(
                    "root=/sys/kernel/tracing", root_assignment, 1)
                script = script.replace(
                    "echo '-:b06/svc_process_bc_entry' >> "
                    '"$root/kprobe_events"',
                    "sed -i '/^p:b06\\/svc_process_bc_entry /d' "
                    '"$root/kprobe_events"')
                script = script.replace(
                    'cd "$root/instances"; rmdir reach_callback',
                    'rm -rf "$root/instances/reach_callback"')
                if cleanup_fails:
                    script = script.replace(
                        root_assignment, root_assignment + "\nexit 71", 1)
                result = subprocess.run(
                    ["bash", "-c", script], capture_output=True, text=True,
                    timeout=5)
                instance = trace_root / "instances/reach_callback"
                tracing = instance / "tracing_on"
                probes = trace_root / "kprobe_events"
                self.trace_instance_exists = instance.exists()
                self.tracing_on = (tracing.is_file()
                                   and tracing.read_text().strip() != "0")
                self.probe_registered = (probes.is_file() and
                                         "p:b06/svc_process_bc_entry "
                                         in probes.read_text())
                if result.returncode:
                    message = ("injected cleanup failure" if cleanup_fails else
                               "cleanup shell failed: " + result.stderr.strip())
                    raise RuntimeError(message)
                stdout = result.stdout
            else:
                stdout = ""
            return SimpleNamespace(stdout=stdout, stderr="", returncode=0)

        def stop(self) -> None:
            self.events.append("stop")

    trace_root = tmp_path / "tracefs"
    trace_root.mkdir()
    instances: list[VM] = []

    class Phase1:
        write_evidence = None

        @staticmethod
        def FrozenPhase1VM(args, evidence):
            vm = VM(args, evidence)
            instances.append(vm)
            return vm

    class Phase9:
        @staticmethod
        def validate_fixture_status(value, procs):
            return {}

        @staticmethod
        def validate_source_tree(*args):
            pass

        @staticmethod
        def lane_snapshot(*args):
            return {}

        @staticmethod
        def memory_snapshot(*args):
            return {}

        @staticmethod
        def cleanup_fixture(*args, **kwargs):
            return {}

    image = tmp_path / "image.raw"
    image.write_bytes(b"unchanged")
    dummy = tmp_path / "input"
    dummy.write_bytes(b"x")
    args = SimpleNamespace(
        image=image, deps_tar=dummy, lane_fixture=dummy, workload=dummy,
        syz_executor=dummy, syz_execprog=dummy, procs=1,
        callback_observer="b06-recall",
    )
    monkeypatch.setattr(runner, "cpu_snapshot", lambda *args: {})
    trial = tmp_path / "trial"
    with pytest.raises(RuntimeError, match="injected partial arm failure"):
        runner.run_trial(args, object(), Phase1, Phase9, "on", 1, trial)

    vm = instances[0]
    assert vm.events.index("callback-trace-start") < vm.events.index(
        "callback-trace-cleanup")
    assert "executor-start" not in vm.events
    assert vm.cleanup_attempts == 1
    evidence = __import__("json").loads((trial / "trial_evidence.json").read_text())
    if cleanup_fails:
        assert vm.tracing_on is True
        assert vm.probe_registered is True
        assert vm.trace_instance_exists is True
        assert evidence["cleanup_errors"] == [
            "callback trace cleanup: injected cleanup failure"]
    else:
        assert vm.tracing_on is False
        assert vm.probe_registered is False
        assert vm.trace_instance_exists is False
        assert evidence.get("cleanup_errors", []) == []
        runner.cleanup_callback_trace(vm)
        assert vm.cleanup_attempts == 2
        assert vm.tracing_on is False
        assert vm.probe_registered is False
        assert vm.trace_instance_exists is False
