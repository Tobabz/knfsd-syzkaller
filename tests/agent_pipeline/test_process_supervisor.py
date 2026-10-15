"""Real Linux child-process lifecycle tests; no VM or live fuzzing processes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

import pytest

from agent_pipeline.runner import process_supervisor as ps
from agent_pipeline.controller.tasks import RunnerInput, RunnerStatus
from agent_pipeline.runner import RUNNER_RESTART, DurableRunner
from agent_pipeline.runner.worker import LeaseControl
from agent_pipeline.runner import _process_guardian as guardian
from agent_pipeline.runner.process_supervisor import (
    CleanupIncomplete, DuplicateExecution, HostCommand, ProcessLimits, ProcessSupervisor,
    ProcessSupervisorError, RecoveryRequired, ResourceBusy,
)


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux pidfd/subreaper required")
PYTHON = sys.executable
ROOT = Path(__file__).resolve().parents[2]


def sha(value):
    return hashlib.sha256(value.encode()).hexdigest()


def eventually(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    raise AssertionError("condition did not become true before deadline")


def reap(pid):
    return eventually(lambda: os.waitpid(pid, os.WNOHANG)[0])


@pytest.fixture
def host(tmp_path):
    runner = DurableRunner(tmp_path / "runner.sqlite", lease_duration_ns=10_000_000_000)
    supervisor = ProcessSupervisor(tmp_path / "state")
    yield runner, supervisor
    runner.close()


def claim(runner, name="task"):
    runner.submit(name, RunnerInput(job_id=name, harness_ref=sha("h"), execution_harness_id=sha("e")))
    lease = runner.claim("worker")
    assert lease is not None
    return lease, LeaseControl(runner, lease)


def command(tmp_path, code, *args):
    return HostCommand((PYTHON, "-c", code, *args), tmp_path)


def limits(**changes):
    values = dict(timeout_s=6, term_grace_s=0.1, kill_grace_s=0.8,
                  renew_interval_s=0.05, heartbeat_timeout_s=5)
    values.update(changes)
    return ProcessLimits(**values)


def run(host, tmp_path, code, *, name="task", key="lane", policy=None):
    runner, supervisor = host
    lease, control = claim(runner, name)
    result = supervisor.run(command(tmp_path, code), lease, control,
                            resource_key=key, limits=policy or limits())
    return result, lease


def record(supervisor, key="lane"):
    return guardian.read_record(supervisor.state_dir / sha(key) / "current.json")


def test_capture_exit_status_literal_argv_and_sanitized_environment(host, tmp_path, monkeypatch):
    monkeypatch.setenv("SUPERVISOR_TEST_SECRET", "do-not-inherit")
    runner, supervisor = host
    lease, control = claim(runner)
    code = ('import os,sys; print(sys.argv[1]); '
            'print(os.environ.get("SUPERVISOR_TEST_SECRET", "absent")); '
            'print("error",file=sys.stderr); sys.exit(7)')
    result = supervisor.run(command(tmp_path, code, "$(touch never); *"), lease, control,
                            resource_key="lane", limits=limits())
    assert result.reason == "completed"
    assert result.returncode == 7
    assert result.stdout == b"$(touch never); *\nabsent\n"
    assert result.stderr == b"error\n"
    assert not (tmp_path / "never").exists()
    assert result.token_sha256 == sha(lease.token)
    assert result.started_at_ns <= result.completed_at_ns
    assert record(supervisor)["state"] == "clean"
    for path in supervisor.state_dir.rglob("*"):
        if path.is_file():
            assert lease.token.encode() not in path.read_bytes()


def test_output_redacts_accidental_bearer_echo_without_persisting_it(host, tmp_path):
    runner, supervisor = host
    lease, control = claim(runner)
    # Secret is deliberately supplied by a separate test fixture, not argv/env.
    (tmp_path / "test-secret").write_text(lease.token)
    result = supervisor.run(command(tmp_path, 'print(open("test-secret").read())'),
                            lease, control, resource_key="lane", limits=limits())
    assert result.stdout == b"[REDACTED]\n"
    assert lease.token not in repr(result)


def test_bearer_cannot_be_passed_in_host_configuration(host, tmp_path):
    runner, supervisor = host
    lease, control = claim(runner)
    with pytest.raises(ValueError, match="bearer"):
        supervisor.run(command(tmp_path, "print('" + lease.token + "')"),
                       lease, control, resource_key="lane")
    assert not list(supervisor.state_dir.iterdir())


def test_timeout_kills_and_reaps_term_ignoring_child(host, tmp_path):
    code = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
            'open("pid","w").write(str(os.getpid())); time.sleep(60)')
    started = time.monotonic()
    result, _ = run(host, tmp_path, code, policy=limits(timeout_s=0.3))
    assert result.reason == "timed_out"
    assert result.returncode == -signal.SIGKILL
    assert not Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()
    assert time.monotonic() - started < 6


@pytest.mark.parametrize("detach", [False, True])
def test_normal_leader_exit_reaps_grandchild_holding_output_pipes(host, tmp_path, detach):
    child_code = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                  'open("grandchild","w").write(str(os.getpid())); time.sleep(60)')
    code = (f'import subprocess,sys,time,os\nsubprocess.Popen([sys.executable,"-c",{child_code!r}],'
            f'start_new_session={detach!r})\n'
            'while not os.path.exists("grandchild"): time.sleep(0.01)\nprint("leader done")')
    result, _ = run(host, tmp_path, code)
    assert result.reason == "completed"
    assert result.returncode == 0
    assert result.stdout == b"leader done\n"
    assert not Path(f"/proc/{(tmp_path / 'grandchild').read_text()}").exists()


def test_overflow_is_bounded_and_child_reaped(host, tmp_path):
    code = ('import os\nopen("pid","w").write(str(os.getpid()))\n'
            'while True: os.write(1,b"x"*65536); os.write(2,b"y"*65536)')
    result, _ = run(host, tmp_path, code, policy=limits(max_output_bytes=1024))
    assert result.reason == "output_limit"
    assert len(result.stdout) + len(result.stderr) == 1024
    assert not Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()


def test_cancel_continues_while_draining_output(host, tmp_path):
    runner, supervisor = host
    lease, control = claim(runner)
    code = ('import os,time\nopen("pid","w").write(str(os.getpid()))\n'
            'while True: os.write(1,b"x"*1024); time.sleep(0.001)')
    with ThreadPoolExecutor() as pool:
        future = pool.submit(supervisor.run, command(tmp_path, code), lease, control,
                             resource_key="lane", limits=limits())
        eventually(lambda: (tmp_path / "pid").exists())
        runner.cancel(lease.binding.task_id)
        result = future.result(timeout=5)
    assert result.reason == "stop_requested"
    assert len(result.stdout) < 1_048_576
    assert not Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()


def test_live_lease_is_renewed_during_long_capture(tmp_path):
    with_runner = DurableRunner(tmp_path / "runner.sqlite", lease_duration_ns=3_000_000_000)
    try:
        lease, control = claim(with_runner)
        result = ProcessSupervisor(tmp_path / "state").run(
            command(tmp_path, 'import time; time.sleep(3.5); print("done")'), lease, control,
            resource_key="lane", limits=limits(timeout_s=8, renew_interval_s=0.05))
        assert result.reason == "completed"
        assert control.lease.expires_at_ns > lease.expires_at_ns + 400_000_000
    finally:
        with_runner.close()


class NoRenew(LeaseControl):
    def renew(self):
        return self.lease


def test_expiry_and_reclaim_do_not_overlap_same_resource(tmp_path):
    runner = DurableRunner(tmp_path / "runner.sqlite", lease_duration_ns=3_000_000_000)
    supervisor = ProcessSupervisor(tmp_path / "state")
    old, _ = claim(runner)
    code = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
            'open("old-pid","w").write(str(os.getpid())); time.sleep(60)')
    try:
        with ThreadPoolExecutor() as pool:
            future = pool.submit(supervisor.run, command(tmp_path, code), old, NoRenew(runner, old),
                                 resource_key="lane", limits=limits(term_grace_s=1.2))
            eventually(lambda: (tmp_path / "old-pid").exists())
            eventually(lambda: time.time_ns() >= old.expires_at_ns)
            # An expired lease is never reclaimed: the task ends
            # runner_restart and the Controller's retry is a new task.
            new, _ = claim(runner, "retry")
            assert runner.status(old.binding.task_id) == RunnerStatus(
                state="ended_unsealed", reason=RUNNER_RESTART)
            replacement = command(tmp_path, 'print("replacement")')
            with pytest.raises(ResourceBusy):
                supervisor.run(replacement, new, LeaseControl(runner, new),
                               resource_key="lane", limits=limits())
            result = future.result(timeout=5)
            assert result.reason in ("lease_lost", "stop_requested")
        assert not Path(f"/proc/{(tmp_path / 'old-pid').read_text()}").exists()
        # Waiting for old cleanup may outlast the replacement's short lease.
        newest, _ = claim(runner, "retry-2")
        result = supervisor.run(replacement, newest, LeaseControl(runner, newest),
                                resource_key="lane", limits=limits())
        assert result.stdout == b"replacement\n"
    finally:
        runner.close()


def test_renewal_failure_stops_child(host, tmp_path):
    runner, supervisor = host
    lease, _ = claim(runner)

    class BrokenRenewal(LeaseControl):
        def renew(self):
            if (tmp_path / "pid").exists():
                raise RuntimeError("private provider diagnostic")
            return super().renew()

    result = supervisor.run(command(tmp_path, 'import os,time; open("pid","w").write(str(os.getpid())); time.sleep(60)'),
                            lease, BrokenRenewal(runner, lease), resource_key="lane", limits=limits())
    assert result.reason == "lease_lost"
    assert not Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()


def test_duplicate_lease_remains_refused_after_restart(host, tmp_path):
    runner, supervisor = host
    lease, control = claim(runner)
    cmd = command(tmp_path, 'print("once")')
    supervisor.run(cmd, lease, control, resource_key="lane", limits=limits())
    restarted = ProcessSupervisor(supervisor.state_dir)
    with pytest.raises(DuplicateExecution):
        restarted.run(cmd, lease, control, resource_key="lane", limits=limits())


def test_guardian_watchdog_cleans_while_parent_callback_is_blocked(host, tmp_path):
    runner, supervisor = host
    lease, _ = claim(runner)
    blocked = threading.Event()
    release = threading.Event()

    class BlockingControl(LeaseControl):
        def stop_requested(self):
            if (tmp_path / "pid").exists():
                blocked.set()
                assert release.wait(timeout=10)
            return super().stop_requested()

    code = 'import os,time; open("pid","w").write(str(os.getpid())); time.sleep(60)'
    with ThreadPoolExecutor() as pool:
        future = pool.submit(supervisor.run, command(tmp_path, code), lease,
            BlockingControl(runner, lease), resource_key="lane",
            limits=limits(heartbeat_timeout_s=1.5))
        try:
            assert blocked.wait(timeout=5)
            pid = int((tmp_path / "pid").read_text())
            eventually(lambda: not Path(f"/proc/{pid}").exists())
            # Cleanup is independent; the synchronous API remains blocked.
            assert not future.done()
            eventually(lambda: record(supervisor).get("state") == "clean")
        finally:
            release.set()
        result = future.result(timeout=5)
    assert result.reason == "heartbeat_lost"


def test_different_leases_and_supervisors_contend_on_resource_not_task_id(host, tmp_path):
    runner, supervisor = host
    first, control = claim(runner)
    second, other = claim(runner, "another-task")
    code = 'import time; open("ready","w").write("ready"); time.sleep(60)'
    with ThreadPoolExecutor() as pool:
        future = pool.submit(supervisor.run, command(tmp_path, code), first, control,
                             resource_key="lane", limits=limits())
        eventually(lambda: (tmp_path / "ready").exists())
        with pytest.raises(ResourceBusy):
            ProcessSupervisor(supervisor.state_dir).run(command(tmp_path, 'print("duplicate")'),
                second, other, resource_key="lane", limits=limits())
        result = ProcessSupervisor(supervisor.state_dir).run(command(tmp_path, 'print("parallel")'),
            second, other, resource_key="different-lane", limits=limits())
        assert result.stdout == b"parallel\n"
        runner.cancel(first.binding.task_id)
        future.result(timeout=5)


@pytest.fixture
def subreaper():
    # Crash tests deliberately orphan test children; adopt and reap them here
    # so no cleanup depends on the host's init process. No unrelated PIDs.
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    try:
        yield
    finally:
        for pid in guardian._children():
            guardian._signal_child(pid, signal.SIGKILL)
            reap(pid)
        assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def test_parent_crash_guardian_cleans_and_restart_can_execute(host, tmp_path, subreaper):
    runner, supervisor = host
    child_code = ('import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
                  'open("payload-pid","w").write(str(os.getpid())); time.sleep(60)')
    worker_code = f'''
from pathlib import Path
import hashlib,sys
from agent_pipeline.runner import DurableRunner
from agent_pipeline.runner.worker import LeaseControl
from agent_pipeline.controller.tasks import RunnerInput
from agent_pipeline.runner.process_supervisor import *
p=Path({str(tmp_path)!r})
r=DurableRunner(p/'runner.sqlite')
d=hashlib.sha256(b'x').hexdigest()
r.submit('crash-task',RunnerInput(job_id='crash-job',harness_ref=d,execution_harness_id=d))
l=r.claim('crashed-worker')
ProcessSupervisor(p/'state').run(HostCommand((sys.executable,'-c',{child_code!r}),p),l,LeaseControl(r,l),resource_key='lane',limits=ProcessLimits(term_grace_s=0.1,kill_grace_s=0.8))
'''
    worker = subprocess.Popen([PYTHON, "-c", worker_code], cwd=ROOT,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        eventually(lambda: (tmp_path / "payload-pid").exists())
        guardian_pid = record(supervisor)["guardian"]["pid"]
        worker.kill()
        worker.wait(timeout=3)
        eventually(lambda: record(supervisor).get("state") == "clean")
        reap(guardian_pid)
        assert not Path(f"/proc/{(tmp_path / 'payload-pid').read_text()}").exists()
        result, _ = run(host, tmp_path, 'print("recovered")', name="replacement")
        assert result.stdout == b"recovered\n"
    finally:
        if worker.poll() is None:
            worker.kill()
            worker.wait(timeout=3)


def test_guardian_crash_before_child_record_refuses_recovery(host, tmp_path, subreaper, monkeypatch):
    runner, supervisor = host
    wrapper = tmp_path / "fault_guardian.py"
    wrapper.write_text(f'''
import importlib.util,os,sys,socket
from pathlib import Path
s=importlib.util.spec_from_file_location('guardian',{guardian.__file__!r})
g=importlib.util.module_from_spec(s); s.loader.exec_module(g)
original=g.write_record
def write(path,record):
    if 'child' in record: os._exit(99)
    original(path,record)
g.write_record=write
g.run(socket.socket(fileno=int(sys.argv[1])),int(sys.argv[2]),Path(sys.argv[3]))
''')
    monkeypatch.setattr(guardian, "__file__", str(wrapper))
    lease, control = claim(runner)
    code = 'import os,time; open("payload-pid","w").write(str(os.getpid())); time.sleep(60)'
    with pytest.raises(RecoveryRequired):
        supervisor.run(command(tmp_path, code), lease, control, resource_key="lane", limits=limits())
    eventually(lambda: (tmp_path / "payload-pid").exists())
    current = record(supervisor)
    assert current["state"] == "active"
    assert "child" not in current
    with pytest.raises(RecoveryRequired):
        supervisor.run(command(tmp_path, 'open("overlap","w").write("bad")'), lease, control,
                       resource_key="lane", limits=limits())
    assert not (tmp_path / "overlap").exists()
    # Fixture owns the adopted payload and performs explicit test-only cleanup.


def test_unprovable_cleanup_keeps_resource_locked_until_proven_empty(host, tmp_path, subreaper, monkeypatch):
    runner, supervisor = host
    wrapper = tmp_path / "quarantine_guardian.py"
    release = tmp_path / "allow-test-cleanup"
    wrapper.write_text(f'''
import importlib.util,sys,socket
from pathlib import Path
s=importlib.util.spec_from_file_location('guardian',{guardian.__file__!r})
g=importlib.util.module_from_spec(s); s.loader.exec_module(g)
original=g._signal_child
def signal_child(pid,sig):
    if not Path({str(release)!r}).exists(): raise PermissionError('test-only signal denial')
    original(pid,sig)
g._signal_child=signal_child
g.run(socket.socket(fileno=int(sys.argv[1])),int(sys.argv[2]),Path(sys.argv[3]))
''')
    monkeypatch.setattr(guardian, "__file__", str(wrapper))
    lease, control = claim(runner)
    code = 'import os,time; open("pid","w").write(str(os.getpid())); time.sleep(60)'
    try:
        with pytest.raises(CleanupIncomplete):
            supervisor.run(command(tmp_path, code), lease, control, resource_key="lane",
                           limits=limits(timeout_s=0.5, term_grace_s=0.1, kill_grace_s=0.2))
        current = record(supervisor)
        assert current["state"] == "quarantined"
        assert Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()
        with pytest.raises(ResourceBusy):
            supervisor.run(command(tmp_path, 'print("overlap")'), lease, control,
                           resource_key="lane", limits=limits())
    finally:
        release.touch()
    eventually(lambda: record(supervisor).get("state") == "clean")
    # The supervisor's background waiter must reap it without another run.
    eventually(lambda: not Path(f"/proc/{current['guardian']['pid']}").exists())
    assert not Path(f"/proc/{(tmp_path / 'pid').read_text()}").exists()


@pytest.mark.parametrize("where", ["socketpair", "selector"])
def test_fd_failure_before_guardian_spawn_leaves_resource_clean(host, tmp_path, monkeypatch, where):
    runner, supervisor = host
    module, name = (ps.socket, "socketpair") if where == "socketpair" else (ps.selectors, "DefaultSelector")
    real = getattr(module, name)
    failed = []

    def once(*args, **kwargs):
        if not failed:
            failed.append(1)
            raise OSError(errno.EMFILE, "Too many open files")
        return real(*args, **kwargs)

    monkeypatch.setattr(module, name, once)
    lease, control = claim(runner, "first")
    with pytest.raises(ProcessSupervisorError, match="could not start"):
        supervisor.run(command(tmp_path, 'open("ran","w")'), lease, control,
                       resource_key="lane", limits=limits())
    assert not (tmp_path / "ran").exists()
    assert record(supervisor)["result"]["reason"] == "spawn_failed"
    lease, control = claim(runner, "second")
    result = supervisor.run(command(tmp_path, 'print("next")'), lease, control,
                            resource_key="lane", limits=limits())
    assert result.stdout == b"next\n"


def fault_guardian(tmp_path, body):
    wrapper = tmp_path / "fault_guardian.py"
    wrapper.write_text(f'''
import importlib.util,os,sys,socket
from pathlib import Path
s=importlib.util.spec_from_file_location('guardian',{guardian.__file__!r})
g=importlib.util.module_from_spec(s); s.loader.exec_module(g)
{body}
g.run(socket.socket(fileno=int(sys.argv[1])),int(sys.argv[2]),Path(sys.argv[3]))
''')
    return str(wrapper)


@pytest.mark.parametrize("body", [
    # No pidfds (ENOSYS or seccomp).
    "def enosys(*_): raise OSError(38, 'Function not implemented')\nos.pidfd_open = enosys",
    # CONFIG_PROC_CHILDREN=n: tree cleanup could never list the payload.
    "def missing(): raise FileNotFoundError(2, 'No such file or directory')\ng._children = missing",
])
def test_guardian_precondition_failure_refuses_before_spawn(host, tmp_path, monkeypatch, body):
    runner, supervisor = host
    with monkeypatch.context() as patch:
        patch.setattr(guardian, "__file__", fault_guardian(tmp_path, body))
        lease, control = claim(runner, "first")
        result = supervisor.run(command(tmp_path, 'open("ran","w")'), lease, control,
                                resource_key="lane", limits=limits())
    assert result.reason == "guardian_failed"
    assert not (tmp_path / "ran").exists()
    assert record(supervisor)["state"] == "clean"
    lease, control = claim(runner, "second")
    result = supervisor.run(command(tmp_path, 'print("next")'), lease, control,
                            resource_key="lane", limits=limits())
    assert result.stdout == b"next\n"


@pytest.mark.parametrize("state", ["reserved", "active", "quarantined"])
def test_stale_or_pid_reused_metadata_never_signals_an_unowned_pid(host, tmp_path, state, monkeypatch):
    runner, supervisor = host
    run(host, tmp_path, 'print("first")')
    path = supervisor.state_dir / sha("lane") / "current.json"
    stale = record(supervisor)
    stale.update(state=state, guardian={"pid": os.getpid(), "start_ticks": 1},
                 child={"pid": os.getpid(), "start_ticks": 2})
    guardian.write_record(path, stale)

    def forbidden(*_args, **_kwargs):
        pytest.fail("recovery must not signal stored PIDs")

    monkeypatch.setattr(os, "kill", forbidden)
    monkeypatch.setattr(os, "killpg", forbidden)
    monkeypatch.setattr(signal, "pidfd_send_signal", forbidden)
    lease, control = claim(runner, "next")
    with pytest.raises(RecoveryRequired):
        supervisor.run(command(tmp_path, 'print("bad")'), lease, control,
                       resource_key="lane", limits=limits())


def test_spawn_failure_is_clean_but_not_retriable_with_same_lease(host, tmp_path):
    runner, supervisor = host
    lease, control = claim(runner)
    cmd = HostCommand((str(tmp_path / "missing-executable"),), tmp_path)
    result = supervisor.run(cmd, lease, control, resource_key="lane", limits=limits())
    assert result.reason == "spawn_failed"
    assert result.returncode is None
    assert record(supervisor)["state"] == "clean"
    with pytest.raises(DuplicateExecution):
        supervisor.run(cmd, lease, control, resource_key="lane", limits=limits())


def test_descriptor_and_process_cleanup_after_repeated_runs(host, tmp_path):
    before = len(list(Path("/proc/self/fd").iterdir()))
    for index in range(6):
        result, _ = run(host, tmp_path, 'print("ok")', name=f"task-{index}")
        assert result.reason == "completed"
        current = record(host[1])
        assert not Path(f"/proc/{current['guardian']['pid']}").exists()
        assert not Path(f"/proc/{current['child']['pid']}").exists()
    assert len(list(Path("/proc/self/fd").iterdir())) == before


def test_attempt_journal_bound_fails_before_spawn(host, tmp_path):
    run(host, tmp_path, 'print("first")', policy=limits(max_attempts=1))
    with pytest.raises(ProcessSupervisorError, match="journal is full"):
        run(host, tmp_path, 'open("forbidden","w").write("bad")', name="next", policy=limits(max_attempts=1))
    assert not (tmp_path / "forbidden").exists()


@pytest.mark.parametrize("changes", [
    {"timeout_s": float("inf")}, {"timeout_s": float("nan")},
    {"term_grace_s": 0}, {"max_output_bytes": True}, {"max_output_bytes": 100_000_000},
    {"poll_interval_s": 1}, {"heartbeat_timeout_s": 1}, {"max_attempts": 0},
])
def test_invalid_limits(changes):
    with pytest.raises(ValueError):
        ProcessLimits(**changes)


def test_world_writable_or_symlink_state_is_refused(tmp_path):
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(ValueError, match="private"):
        ProcessSupervisor(unsafe)
    link = tmp_path / "link"
    link.symlink_to(unsafe, target_is_directory=True)
    with pytest.raises(OSError):
        ProcessSupervisor(link)


def test_record_reader_accepts_committed_inode_replaced_after_open(tmp_path, monkeypatch):
    path = tmp_path / "current.json"
    replacement = tmp_path / "replacement.json"
    guardian.write_record(path, {"state": "active"})
    guardian.write_record(replacement, {"state": "clean"})
    inode = path.stat().st_ino
    original = os.fstat
    replaced = False

    def replace_before_stat(fd):
        nonlocal replaced
        if not replaced and original(fd).st_ino == inode:
            replaced = True
            os.replace(replacement, path)
        return original(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "fstat", replace_before_stat)
        assert guardian.read_record(path) == {"state": "active"}
    assert replaced
    assert guardian.read_record(path) == {"state": "clean"}
