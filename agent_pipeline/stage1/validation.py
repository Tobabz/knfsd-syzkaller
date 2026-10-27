"""Validation of a Harness Generation patch set (07 §5.2) by one trusted
host command, and the staged execution approvals it leaves.

``CommandValidator`` implements the Controller's ``HarnessValidator``.
``submit`` records the task in SQLite, then runs the host command on a
thread; ``status`` reads the record.  The command is host configuration
(absolute argv, cwd, environment, resource key); the patch set it gets is
data.  It rebuilds the harness from the patch set on the build key's base,
runs the 07 §5.2 checks in a new VM and reports.  The Agent's worktree,
binaries and logs are never inputs.

Command contract (``{input}``, ``{output}`` and ``{resource}`` in argv are
replaced by the two directories and the KVM slot's resource key):

``input/``
    ``validation.json``      task_id and the ``ValidationInput`` fields
    ``patch_set.json``       the ``HarnessPatchSet`` record
    ``patch.diff``           its binary diff (``git apply --binary``)
    ``base_descriptor.json`` the base binding's ``ExecutionHarnessDescriptor``
    ``base_hcap.json``       the base binding's HCAP catalog (with the gap
                             key's vocabulary contract)
                             (the two ``base_`` files only with a base binding)

``output/report.json`` (written by the command)::

    {"result": "passed", "descriptor": "descriptor.json",
     "hcap": "hcap.json",
     "artifacts": [{"identity": "kernel", "type": "...", "path": "bzImage"},
                   ...]}
    {"result": "rejected", "reason": "smoke_unreached", "artifacts": [...]}
    {"result": "inconclusive", "reason": "vm_boot_timeout"}

Paths are file names in ``output/``.  ``rejected`` is the patch set's
fault, with a typed reason (``build_failed``, ``bootstrap_failed``,
``smoke_unreached``, ``neutral_reached``, ``regression``,
``trigger_rule``, ...); ``inconclusive`` is an infrastructure end, run
again as a new task.  On ``passed`` the descriptor's build artifacts must
be listed (or already stored) and the HCAP catalog must load; the
validator then stores the staged ``ExecutionHarnessApproval`` and returns
the staged binding.  A nonzero exit, a timeout or a malformed report is
``inconclusive``, never a verdict.

A task recorded as running by an earlier process is reported
``inconclusive(runner_restart)`` when this one opens the store; a command
session it left behind is killed first.  One process owns the store at a
time (a lock file); one-shot commands use ``DeferredValidator``.
"""

from __future__ import annotations

import fcntl
import os
import re
import signal
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..artifacts import ArtifactStore
from ..contracts import HarnessBinding, Record
from ..controller.generation import ValidationInput, ValidationStatus
from ..data import canonical_json, load_record, parse_json, put_record
from ..hcap import ArtifactHcapChecker
from ..materializer import (ExecutionHarnessApproval,
                            ExecutionHarnessDescriptor,
                            StaticExecutionHarnessAuthority, descriptor_id)
from ..runner.slots import SlotPool, resource
from .engine import CaptureError, _read_regular, _write

INPUT = "{input}"
OUTPUT = "{output}"
RESOURCE = "{resource}"
MAX_REPORT_BYTES = 64 * 1024
MAX_LOG_TAIL_BYTES = 1 << 20
MAX_REASON_CHARS = 200
_TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REASON = re.compile(r"^[a-z0-9_.:-]{1,200}$")


class ValidatorBusy(RuntimeError):
    """Another process owns the validation store."""


class ValidationDeferred(RuntimeError):
    """This process does not run validations; the service loop does."""


# ---------------------------------------------------------------- report


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _Entry(_Model):
    identity: str = Field(min_length=1, max_length=128)
    type: str = Field(min_length=1, max_length=256)
    path: str = Field(min_length=1, max_length=255)


class _Report(_Model):
    result: Literal["passed", "rejected", "inconclusive"]
    reason: str | None = Field(default=None, max_length=MAX_REASON_CHARS)
    descriptor: str | None = None
    hcap: str | None = None
    artifacts: tuple[_Entry, ...] = Field(default=(), max_length=4096)


class ValidationArtifact(Record):
    identity: str
    type: str
    ref: str


class ValidationRecord(Record):
    """The stored evidence of one validation task: what the command
    reported and the files it listed, by digest.  ``evidence_ref`` of the
    task's status."""

    schema_version: Literal["harness-validation.v1"] = \
        "harness-validation.v1"
    task_id: str
    generation_id: str
    patch_set_ref: str
    result: Literal["passed", "rejected", "inconclusive"]
    reason: str | None = None
    returncode: int | None = None
    started_at_ns: int
    completed_at_ns: int
    artifacts: tuple[ValidationArtifact, ...] = ()
    log_ref: str | None = None
    binding: HarnessBinding | None = None
    approval_ref: str | None = None


# ---------------------------------------------------------------- store


class ValidationStore:
    """Validation tasks and the staged approvals of the passed ones.

    Readable by any process (the Materializer's authority reads it);
    written by the one ``CommandValidator`` that owns it."""

    def __init__(self, path: Path | str) -> None:
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), isolation_level=None,
                                   check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA busy_timeout = 30000")
        self._db.execute("PRAGMA journal_mode = WAL")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS validations (
                task_id TEXT PRIMARY KEY,
                input TEXT NOT NULL,
                state TEXT NOT NULL,
                status TEXT NOT NULL,
                session INTEGER,
                started_ticks INTEGER,
                boot_id TEXT,
                descriptor_id TEXT,
                approval_ref TEXT);
            CREATE INDEX IF NOT EXISTS validations_state
                ON validations (state);
            CREATE INDEX IF NOT EXISTS validations_descriptor
                ON validations (descriptor_id);
        """)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _one(self, sql: str, args: tuple):
        with self._lock:
            return self._db.execute(sql, args).fetchone()

    def status(self, task_id: str) -> ValidationStatus:
        row = self._one("SELECT status FROM validations WHERE task_id = ?",
                        (task_id,))
        if row is None:
            return ValidationStatus(state="unknown")
        return ValidationStatus.model_validate_json(row[0])

    def insert(self, task_id: str, task_input: ValidationInput) -> bool:
        """False when the task is already recorded."""
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO validations (task_id, input, state, "
                "status) VALUES (?, ?, 'running', ?)",
                (task_id, task_input.model_dump_json(),
                 ValidationStatus(state="running").model_dump_json()))
            return cur.rowcount == 1

    def input(self, task_id: str) -> ValidationInput:
        row = self._one("SELECT input FROM validations WHERE task_id = ?",
                        (task_id,))
        return ValidationInput.model_validate_json(row[0])

    def started(self, task_id: str, session: int, ticks: int | None,
                boot_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE validations SET session = ?, started_ticks = ?, "
                "boot_id = ? WHERE task_id = ? AND state = 'running'",
                (session, ticks, boot_id, task_id))

    def finish(self, task_id: str, status: ValidationStatus, *,
               descriptor: str | None = None,
               approval_ref: str | None = None) -> None:
        """The task's end; a passed one with its staged approval, in one
        write, so a passed status always has its approval."""
        with self._lock:
            self._db.execute(
                "UPDATE validations SET state = ?, status = ?, "
                "descriptor_id = ?, approval_ref = ?, session = NULL "
                "WHERE task_id = ? AND state = 'running'",
                (status.state, status.model_dump_json(), descriptor,
                 approval_ref, task_id))

    def running(self) -> list[tuple[str, int | None, int | None, str | None]]:
        with self._lock:
            return self._db.execute(
                "SELECT task_id, session, started_ticks, boot_id "
                "FROM validations WHERE state = 'running'").fetchall()

    def approval_refs(self, execution_harness_id: str) -> list[str]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT approval_ref FROM validations WHERE state = "
                "'passed' AND descriptor_id = ? ORDER BY task_id",
                (execution_harness_id,))]


@dataclass(frozen=True)
class StagedExecutionHarnessAuthority:
    """The host's static approvals, and the staged ones validation left
    (07 §5.2).  For a binding, the approval that names its HCAP revision:
    a static one first, then a staged one for the same descriptor."""

    static: StaticExecutionHarnessAuthority
    store: ValidationStore
    artifacts: ArtifactStore

    def resolve(self, binding: HarnessBinding
                ) -> ExecutionHarnessApproval | None:
        base = self.static.resolve(binding)
        if base is not None and \
                binding.hcap_revision in base.approved_hcap_revisions:
            return base
        for ref in self.store.approval_refs(binding.execution_harness_id):
            try:
                approval = load_record(self.artifacts, ref,
                                       ExecutionHarnessApproval)
            except (OSError, ValueError):
                continue
            if binding.hcap_revision in approval.approved_hcap_revisions:
                return approval
        return base


# ---------------------------------------------------------------- sessions


def _boot_id() -> str:
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def _stat(pid: int) -> list[str] | None:
    """Fields of /proc/<pid>/stat after the command name."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return raw[raw.rindex(")") + 2:].split()


def _start_ticks(pid: int) -> int | None:
    fields = _stat(pid)
    return None if fields is None else int(fields[19])


def _session_alive(session: int) -> bool:
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            fields = _stat(int(entry))
            if fields is not None and int(fields[3]) == session:
                return True
    return False


def kill_session(session: int, ticks: int | None, boot_id: str | None
                 ) -> None:
    """Kill a command session an earlier process left.  Only on the same
    boot, and only while its leader is gone or still the recorded one: the
    kernel does not hand out a session id whose members still live."""
    if boot_id != _boot_id():
        return
    leader = _start_ticks(session)
    if leader is not None and leader != ticks:
        return
    if not _session_alive(session):
        return
    try:
        os.killpg(session, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


# ---------------------------------------------------------------- validator


@dataclass(frozen=True)
class CommandValidatorConfig:
    argv: tuple[str, ...]
    cwd: Path
    work_root: Path
    resource_key: str
    env: Mapping[str, str] = field(default_factory=lambda: {"LANG": "C.UTF-8"})
    timeout_s: float = 14_400
    term_grace_s: float = 10.0


class _Inconclusive(Exception):
    pass


class CommandValidator:
    """``HarnessValidator`` over one host command per task."""

    def __init__(self, config: CommandValidatorConfig, store: ValidationStore,
                 artifacts: ArtifactStore, lock_path: Path, *,
                 slots: SlotPool | None = None) -> None:
        if not Path(config.argv[0]).is_absolute():
            raise ValueError("argv[0] must be an absolute path")
        self.config = config
        self.store = store
        self.artifacts = artifacts
        self.slots = slots
        self._lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self._lock_fd)
            raise ValidatorBusy("another process owns the validation "
                                "store") from None
        self._stop = threading.Event()
        self._threads: dict[str, threading.Thread] = {}
        self._sessions: dict[str, int] = {}
        self._mutex = threading.Lock()
        for task_id, session, ticks, boot in store.running():
            if session is not None:
                kill_session(session, ticks, boot)
            store.finish(task_id, ValidationStatus(
                state="inconclusive", reason="runner_restart"))

    def submit(self, task_id: str,
               task_input: ValidationInput) -> ValidationStatus:
        if not _TASK_ID.match(task_id):
            raise ValueError(f"bad validation task id {task_id!r}")
        if self.store.insert(task_id, task_input):
            thread = threading.Thread(
                target=self._execute, args=(task_id, task_input),
                daemon=True, name=f"harness-validation-{task_id}")
            with self._mutex:
                self._threads[task_id] = thread
            thread.start()
        return self.store.status(task_id)

    def status(self, task_id: str) -> ValidationStatus:
        return self.store.status(task_id)

    def wait(self, timeout_s: float | None = None) -> bool:
        """Join the running tasks (tests, close).  False on timeout."""
        deadline = None if timeout_s is None else \
            time.monotonic() + timeout_s
        with self._mutex:
            threads = list(self._threads.values())
        for thread in threads:
            thread.join(None if deadline is None else
                        max(0.0, deadline - time.monotonic()))
        return not any(t.is_alive() for t in threads)

    def close(self, *, timeout_s: float = 30.0) -> None:
        """Stop running commands; their tasks end inconclusive and are run
        again by the next process."""
        self._stop.set()
        with self._mutex:
            sessions = list(self._sessions.values())
        for session in sessions:
            try:
                os.killpg(session, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.wait(timeout_s)
        os.close(self._lock_fd)

    # ------------------------------------------------------------ internals

    def _execute(self, task_id: str, task_input: ValidationInput) -> None:
        started = time.time_ns()
        try:
            status, extra = self._validate(task_id, task_input, started)
        except Exception as exc:          # never leave a task running
            status, extra = ValidationStatus(
                state="inconclusive",
                reason=f"validator_error:{type(exc).__name__}:{exc}"
                [:MAX_REASON_CHARS]), {}
        try:
            self.store.finish(task_id, status, **extra)
        finally:
            with self._mutex:
                self._threads.pop(task_id, None)

    def _prepare(self, task_id: str, task_input: ValidationInput
                 ) -> tuple[Path, Path]:
        run = self.config.work_root / task_id
        inp, out = run / "input", run / "output"
        run.mkdir(parents=True, exist_ok=False)
        inp.mkdir()
        out.mkdir()
        from ..agent_tasks.generation import HarnessPatchSet
        patch_set = HarnessPatchSet.model_validate_json(
            self.artifacts.get(task_input.patch_set_ref))
        if patch_set.generation_id != task_input.generation_id or \
                patch_set.gap != task_input.gap:
            raise _Inconclusive("patch_set_mismatch")
        _write(inp / "validation.json", canonical_json(
            {"task_id": task_id, **task_input.model_dump(mode="json")}))
        _write(inp / "patch_set.json", canonical_json(patch_set))
        _write(inp / "patch.diff", self.artifacts.get(patch_set.patch_ref))
        b = task_input.base_binding
        if b is not None:
            _write(inp / "base_descriptor.json", canonical_json(load_record(
                self.artifacts, b.execution_harness_id,
                ExecutionHarnessDescriptor)))
            _write(inp / "base_hcap.json", self.artifacts.get(b.hcap_revision))
        return inp, out

    def _run(self, task_id: str, argv: tuple[str, ...], log: Path
             ) -> tuple[str, int | None]:
        with open(log, "wb") as sink:
            proc = subprocess.Popen(
                argv, cwd=self.config.cwd, env=dict(self.config.env),
                stdin=subprocess.DEVNULL, stdout=sink, stderr=sink,
                start_new_session=True, close_fds=True)
        with self._mutex:
            self._sessions[task_id] = proc.pid
        self.store.started(task_id, proc.pid, _start_ticks(proc.pid),
                           _boot_id())
        deadline = time.monotonic() + self.config.timeout_s
        reason = "completed"
        try:
            while proc.poll() is None:
                if self._stop.is_set():
                    reason = "stopped"
                elif time.monotonic() >= deadline:
                    reason = "timeout"
                if reason != "completed":
                    self._end(proc)
                    break
                try:
                    proc.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            # Whatever the command left in its session goes with it.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            with self._mutex:
                self._sessions.pop(task_id, None)
        if reason == "completed" and proc.returncode != 0 and \
                self._stop.is_set():
            reason = "stopped"          # close() killed the session
        return reason, proc.returncode

    def _end(self, proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=self.config.term_grace_s)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    def _validate(self, task_id: str, task_input: ValidationInput,
                  started: int) -> tuple[ValidationStatus, dict]:
        def record(result, reason, *, rc=None, artifacts=(), log=None,
                   binding=None, approval=None) -> str:
            return put_record(self.artifacts, ValidationRecord(
                task_id=task_id, generation_id=task_input.generation_id,
                patch_set_ref=task_input.patch_set_ref, result=result,
                reason=reason, returncode=rc, started_at_ns=started,
                completed_at_ns=time.time_ns(), artifacts=tuple(artifacts),
                log_ref=log, binding=binding, approval_ref=approval))

        try:
            inp, out = self._prepare(task_id, task_input)
        except _Inconclusive as exc:
            return ValidationStatus(state="inconclusive", reason=str(exc),
                                    evidence_ref=record("inconclusive",
                                                        str(exc))), {}
        log = out.parent / "process.log"
        with resource(self.slots, self.config.resource_key) as key:
            argv = tuple(a.replace(INPUT, str(inp)).replace(OUTPUT, str(out))
                         .replace(RESOURCE, key) for a in self.config.argv)
            ended, rc = self._run(task_id, argv, log)
        log_ref = self._log_tail(log)
        if ended != "completed" or rc != 0:
            reason = f"command_{ended}" if ended != "completed" else \
                f"command_exit_{rc}"
            return ValidationStatus(
                state="inconclusive", reason=reason,
                evidence_ref=record("inconclusive", reason, rc=rc,
                                    log=log_ref)), {}
        try:
            report, artifacts = self._report(out)
            if report.result != "passed":
                reason = report.reason or report.result
                return ValidationStatus(
                    state=report.result, reason=reason,
                    evidence_ref=record(report.result, reason, rc=rc,
                                        artifacts=artifacts, log=log_ref)), {}
            binding, approval = self._stage(task_input, out, report)
        except (CaptureError, _Inconclusive, ValueError) as exc:
            reason = f"malformed_report:{exc}"[:MAX_REASON_CHARS]
            return ValidationStatus(
                state="inconclusive", reason=reason,
                evidence_ref=record("inconclusive", reason, rc=rc,
                                    log=log_ref)), {}
        approval_ref = put_record(self.artifacts, approval)
        return ValidationStatus(
            state="passed", binding=binding,
            evidence_ref=record("passed", None, rc=rc, artifacts=artifacts,
                                log=log_ref, binding=binding,
                                approval=approval_ref)), {
            "descriptor": binding.execution_harness_id,
            "approval_ref": approval_ref}

    def _log_tail(self, log: Path) -> str | None:
        try:
            with open(log, "rb") as f:
                f.seek(max(0, os.fstat(f.fileno()).st_size
                           - MAX_LOG_TAIL_BYTES))
                return self.artifacts.put(f.read())
        except OSError:
            return None

    def _report(self, out: Path
                ) -> tuple[_Report, list[ValidationArtifact]]:
        report = _Report.model_validate(parse_json(
            _read_regular(out, "report.json", MAX_REPORT_BYTES)))
        if report.result != "passed" and (
                report.reason is None or not _REASON.match(report.reason)):
            raise _Inconclusive(f"{report.result} needs a typed reason")
        artifacts = [ValidationArtifact(
            identity=e.identity, type=e.type, ref=self.artifacts.put(
                _read_regular(out, e.path, self.artifacts.max_artifact_bytes)))
            for e in report.artifacts]
        return report, artifacts

    def _stage(self, task_input: ValidationInput, out: Path, report: _Report
               ) -> tuple[HarnessBinding, ExecutionHarnessApproval]:
        """A passed report: the staged HCAP revision and the approval of
        its build (07 §5.2)."""
        if report.descriptor is None or report.hcap is None:
            raise _Inconclusive("passed needs descriptor and hcap")
        max_bytes = self.artifacts.max_artifact_bytes
        descriptor = ExecutionHarnessDescriptor.model_validate_json(
            _read_regular(out, report.descriptor, max_bytes))
        if descriptor.kernel_commit != task_input.kernel_commit or \
                descriptor.sanitizer != task_input.sanitizer:
            raise _Inconclusive("descriptor_build_key_mismatch")
        missing = [a.name for a in descriptor.build_artifacts
                   if not self.artifacts.has(a.artifact_ref)]
        if missing:
            raise _Inconclusive("build_artifact_missing:" + ",".join(missing))
        revision = self.artifacts.put(
            _read_regular(out, report.hcap, max_bytes))
        try:
            ArtifactHcapChecker(self.artifacts).load_catalog(revision)
        except OSError as exc:
            raise _Inconclusive(f"hcap_unavailable:{exc}") from exc
        execution_harness_id = self.artifacts.put(canonical_json(descriptor))
        if execution_harness_id != descriptor_id(descriptor):
            raise _Inconclusive("descriptor_id_mismatch")
        return HarnessBinding(
            kernel_commit=task_input.kernel_commit,
            sanitizer=task_input.sanitizer,
            execution_harness_id=execution_harness_id,
            hcap_revision=revision), ExecutionHarnessApproval(
                descriptor=descriptor, approved_hcap_revisions=(revision,))


class DeferredValidator:
    """The validator of a one-shot command: it does not run validations,
    so a submit is left to the service loop (``poll`` sends it again)."""

    def __init__(self, store: ValidationStore) -> None:
        self.store = store

    def submit(self, task_id: str,
               task_input: ValidationInput) -> ValidationStatus:
        raise ValidationDeferred(f"{task_id} is left to the service loop")

    def status(self, task_id: str) -> ValidationStatus:
        return self.store.status(task_id)

    def close(self, **kwargs) -> None:
        pass
