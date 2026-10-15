"""Bounded lease-aware Linux child-process supervision on a trusted host.

This is a process primitive, not an ExecutionEngine, evidence producer, VM
fence, or sandbox. A host adapter supplies a fixed argv and globally consistent
resource key. See PROCESS_SUPERVISOR.md for the deployment assumptions.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import threading
import time
from typing import Mapping

from . import _process_guardian as guardian
from .models import WorkLease
from .worker import ExecutionNotStopped, LeaseControl


class ProcessSupervisorError(RuntimeError):
    """A fixed-message host execution failure; contains no command or token."""


class ResourceBusy(ProcessSupervisorError):
    """Another supervisor/guardian still holds this host resource."""


class RecoveryRequired(ProcessSupervisorError):
    """Old ownership cannot be certified clean; no new process was launched."""


class DuplicateExecution(ProcessSupervisorError):
    """This lease was already admitted on this resource, even if it failed."""


class CleanupIncomplete(ProcessSupervisorError, ExecutionNotStopped):
    """Cleanup was not confirmed; a living guardian retains the resource lock.

    As an ``ExecutionNotStopped``, it keeps the Runner from reporting the
    execution (or a pending cancel) as ended before lease expiry.
    """


class ExecutionUncertain(RecoveryRequired, ExecutionNotStopped):
    """The guardian started but ended without confirmed tree cleanup.

    Unlike a refused admission, an execution may have run and may still be
    running: the Runner must not report it as ended before lease expiry.
    """


def _open_channel():
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        return parent, child, selectors.DefaultSelector()
    except BaseException:
        _close(parent, child)
        raise


def _close(*handles) -> None:
    for handle in handles:
        if handle is not None:
            handle.close()


@dataclass(frozen=True)
class ProcessLimits:
    timeout_s: float = 60.0
    term_grace_s: float = 0.5
    kill_grace_s: float = 2.0
    poll_interval_s: float = 0.02
    renew_interval_s: float = 1.0
    heartbeat_timeout_s: float = 5.0
    max_output_bytes: int = 1_048_576
    max_attempts: int = 10_000

    def __post_init__(self) -> None:
        for name in ("timeout_s", "term_grace_s", "kill_grace_s",
                     "poll_interval_s", "renew_interval_s", "heartbeat_timeout_s"):
            value = getattr(self, name)
            if (type(value) not in (int, float) or not math.isfinite(value)
                    or not 0 < value <= 86_400):
                raise ValueError("invalid process time limit")
        if not 0.001 <= self.poll_interval_s <= 0.2:
            raise ValueError("invalid process polling interval")
        if self.heartbeat_timeout_s < 3 * max(self.renew_interval_s, self.poll_interval_s):
            raise ValueError("heartbeat must allow three renewal/poll intervals")
        if type(self.max_output_bytes) is not int or not 1 <= self.max_output_bytes <= 64 * 1024**2:
            raise ValueError("invalid process output limit")
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 1_000_000:
            raise ValueError("invalid process attempt limit")


@dataclass(frozen=True)
class HostCommand:
    """Trusted host configuration; never construct this from model output.

    argv is passed directly to exec, with no shell and no inherited environment.
    Supplying an interpreter/script is an explicit host trust decision.
    """

    argv: tuple[str, ...]
    cwd: Path
    env: Mapping[str, str] = field(default_factory=lambda: {"LANG": "C.UTF-8"})

    def wire(self) -> dict:
        if (not isinstance(self.argv, tuple) or not 1 <= len(self.argv) <= 256
                or any(not isinstance(arg, str) or "\0" in arg for arg in self.argv)
                or not os.path.isabs(self.argv[0])):
            raise ValueError("host command requires a bounded absolute argv")
        cwd = Path(self.cwd)
        if not cwd.is_absolute() or not cwd.is_dir():
            raise ValueError("host command requires an existing absolute cwd")
        env = dict(self.env)
        if len(env) > 256 or any(
            not isinstance(key, str) or not key or "=" in key or "\0" in key
            or not isinstance(value, str) or "\0" in value
            for key, value in env.items()
        ):
            raise ValueError("invalid host environment")
        value = dict(argv=self.argv, cwd=str(cwd), env=env)
        if len(json.dumps(value).encode()) > 48_000:
            raise ValueError("host command is too large")
        return value


@dataclass(frozen=True)
class ProcessResult:
    reason: str
    returncode: int | None
    stdout: bytes
    stderr: bytes
    started_at_ns: int
    completed_at_ns: int
    resource_sha256: str
    task_sha256: str
    generation: int
    token_sha256: str


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _same_owner(left: WorkLease, right: WorkLease) -> bool:
    return left.model_dump(exclude={"expires_at_ns"}) == right.model_dump(exclude={"expires_at_ns"})


class ProcessSupervisor:
    def __init__(self, state_dir: Path | str) -> None:
        if sys.platform != "linux" or not hasattr(os, "pidfd_open"):
            raise ProcessSupervisorError("Linux pidfd supervision is required")
        self.state_dir = Path(state_dir).absolute()
        guardian.private_directory(self.state_dir)

    def run(
        self, command: HostCommand, lease: WorkLease, control: LeaseControl, *,
        resource_key: str, limits: ProcessLimits = ProcessLimits(),
    ) -> ProcessResult:
        """Execute once, renewing ownership and returning only after tree reap.

        A busy resource fails immediately. A dirty record fails closed without
        signalling stored PIDs. Cancellation and lease loss are operational
        outcomes, not Judge results. No raw output is persisted by this class.
        """
        if (not isinstance(resource_key, str) or not 1 <= len(resource_key) <= 256
                or any(ord(char) < 32 for char in resource_key)):
            raise ValueError("invalid host resource key")
        lease = WorkLease.model_validate(lease)
        wire = command.wire()
        # The bearer is never passed to the guardian or payload, even through
        # caller-provided argv/env. Output redaction covers accidental echoes.
        if lease.token in json.dumps(wire) or lease.token in resource_key:
            raise ValueError("lease bearer cannot be part of host configuration")
        resource_hash = _sha(resource_key)
        resource = self.state_dir / resource_hash
        guardian.private_directory(resource)
        fd = guardian.checked_open(resource / "lock", os.O_RDWR | os.O_CREAT)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ResourceBusy("host resource is still owned") from None
            record_path = resource / "current.json"
            if record_path.exists():
                try:
                    previous = guardian.read_record(record_path)
                    if (previous.get("schema_version") != 1
                            or previous.get("resource_sha256") != resource_hash
                            or previous.get("state") != "clean"
                            or previous.get("result", {}).get("type") != "result"):
                        raise ValueError("unclean ownership")
                except (ValueError, OSError, TypeError, AttributeError):
                    raise RecoveryRequired("resource lacks a verified clean ownership record") from None
            if not _same_owner(lease, control.lease):
                raise ProcessSupervisorError("lease control owner mismatch")
            if time.time_ns() >= control.lease.expires_at_ns:
                raise ProcessSupervisorError("lease already expired")
            try:
                if control.stop_requested():
                    raise ProcessSupervisorError("lease stop already requested")
                previous_expiry = control.lease.expires_at_ns
                renewed = control.renew()
                if (not _same_owner(lease, renewed)
                        or not _same_owner(renewed, control.lease)
                        or renewed.expires_at_ns < previous_expiry
                        or time.time_ns() >= renewed.expires_at_ns):
                    raise ProcessSupervisorError("lease renewal owner mismatch")
            except Exception:
                raise ProcessSupervisorError("lease unavailable before execution") from None

            attempt_hash = _sha(f"{_sha(lease.binding.task_id)}:{lease.generation}:{_sha(lease.token)}")
            attempts = resource / "attempts"
            guardian.private_directory(attempts)
            attempt_path = attempts / attempt_hash
            if attempt_path.exists():
                raise DuplicateExecution("lease was already admitted on this resource")
            with os.scandir(attempts) as entries:
                for count, _ in enumerate(entries, 1):
                    if count >= limits.max_attempts:
                        raise ProcessSupervisorError("resource attempt journal is full")
            record = dict(
                schema_version=1, state="reserved", resource_sha256=resource_hash,
                task_sha256=_sha(lease.binding.task_id), generation=lease.generation,
                token_sha256=_sha(lease.token), attempt_sha256=attempt_hash,
                boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            )
            # Allocate the guardian channel before anything is recorded: under
            # descriptor exhaustion this fails with no state change, and a
            # later failure can free these descriptors to record clean.
            try:
                ipc = _open_channel()
            except OSError:
                raise ProcessSupervisorError("could not allocate guardian channel") from None
            try:
                # Keep durable admission tombstones even on spawn failure. Retrying
                # an execution requires a fresh lease, not the same bearer again.
                guardian.write_record(attempt_path, record)
                guardian.write_record(record_path, record)
            except BaseException:
                # Nothing was started: free the channel, then record clean
                # (a failed directory sync can leave `reserved` in place).
                _close(*ipc)
                try:
                    guardian.write_record(record_path, dict(
                        record, state="clean",
                        result=dict(type="result", reason="spawn_failed")))
                except Exception:
                    pass  # Fail closed: a reserved record needs recovery.
                raise
            config = dict(command=wire, limits=asdict(limits),
                          expires_at_ns=renewed.expires_at_ns,
                          attempt_sha256=attempt_hash)
            return self._execute(resource, fd, config, record, lease, control, limits, ipc)
        finally:
            # Never LOCK_UN: the guardian holds the SAME open file description.
            # Closing our copy leaves its lock in force until tree cleanup.
            os.close(fd)

    def _execute(self, resource, lock_fd, config, record, lease, control, limits, ipc):
        parent, child_channel, selector = ipc
        process = None
        output = {"stdout": bytearray(), "stderr": bytearray()}
        total = 0
        stopping = None
        stop_deadline = None
        result = None
        control_eof = False
        started = time.monotonic()
        next_renewal = started

        def send(value):
            try:
                parent.send(json.dumps(value, separators=(",", ":")).encode())
            except OSError:
                # Guardian's lease/heartbeat watchdog remains authoritative.
                pass

        def stop(reason):
            nonlocal stopping, stop_deadline
            if stopping is None:
                stopping = reason
                stop_deadline = (time.monotonic() + limits.term_grace_s
                                 + limits.kill_grace_s + limits.heartbeat_timeout_s + 1)
                send(dict(type="stop", reason=reason))

        try:
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", str(Path(guardian.__file__).resolve()),
                     str(child_channel.fileno()), str(lock_fd), str(resource)],
                    pass_fds=(child_channel.fileno(), lock_fd), close_fds=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, start_new_session=True, env={},
                )
            except OSError:
                # Popen's exec-error protocol has reaped the failed guardian;
                # no guardian/payload can hold the resource after this failure.
                # Free the channel first: under descriptor exhaustion the
                # record write needs a descriptor too.
                _close(parent, child_channel, selector)
                record.update(state="clean", result=dict(type="result", reason="spawn_failed"))
                guardian.write_record(resource / "current.json", record)
                raise ProcessSupervisorError("could not start process guardian") from None
            child_channel.close()
            parent.setblocking(False)
            payload = json.dumps(config, separators=(",", ":")).encode()
            if len(payload) > guardian.MAX_PACKET:
                raise ProcessSupervisorError("guardian configuration exceeds bound")
            # A guardian that already failed has recorded clean itself;
            # its result or EOF below reports that, not this send.
            send(config)
            for stream, name in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            selector.register(parent, selectors.EVENT_READ, "control")
            while True:
                now = time.monotonic()
                if stopping is None and result is None:
                    if time.time_ns() >= control.lease.expires_at_ns:
                        stop("lease_lost")
                    elif now - started >= limits.timeout_s:
                        stop("timed_out")
                    else:
                        try:
                            if control.stop_requested():
                                stop("stop_requested")
                            elif now >= next_renewal:
                                previous_expiry = control.lease.expires_at_ns
                                renewed = control.renew()
                                if (not _same_owner(lease, renewed)
                                        or not _same_owner(renewed, control.lease)
                                        or renewed.expires_at_ns < previous_expiry
                                        or time.time_ns() >= renewed.expires_at_ns):
                                    raise ValueError("invalid renewal")
                                send(dict(type="renew", expires_at_ns=renewed.expires_at_ns))
                                remaining = (renewed.expires_at_ns - time.time_ns()) / 1e9
                                next_renewal = time.monotonic() + min(limits.renew_interval_s, remaining / 3)
                        except Exception:
                            stop("lease_lost")
                for key, _ in selector.select(limits.poll_interval_s):
                    if key.data == "control":
                        message = guardian._receive(parent)
                        if message is None:
                            selector.unregister(parent)
                            control_eof = True
                        elif message.get("type") == "quarantined":
                            raise CleanupIncomplete("guardian retained a quarantined host resource")
                        elif message.get("type") == "result":
                            result = message
                            parent.shutdown(socket.SHUT_WR)
                        else:
                            raise ExecutionUncertain("invalid guardian response")
                    else:
                        chunk = os.read(key.fd, 65_536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                        else:
                            accepted = min(len(chunk), max(0, limits.max_output_bytes - total))
                            output[key.data].extend(chunk[:accepted])
                            total += accepted
                            if accepted < len(chunk):
                                stop("output_limit")
                if process.poll() is not None:
                    if not selector.get_map():
                        break
                    # A broken guardian may leave a descendant holding pipes.
                    if result is None and control_eof:
                        raise ExecutionUncertain("guardian ended without confirmed tree cleanup")
                if stop_deadline is not None and time.monotonic() >= stop_deadline:
                    raise CleanupIncomplete("guardian cleanup deadline exceeded")
                if time.monotonic() - started > (limits.timeout_s + limits.heartbeat_timeout_s
                                               + limits.term_grace_s + limits.kill_grace_s + 3):
                    raise CleanupIncomplete("guardian completion deadline exceeded")
            clean = guardian.read_record(resource / "current.json")
            if result is None and clean.get("state") == "clean":
                # A durable acknowledgement survives loss of the socket's
                # final packet; it is still checked against this exact attempt.
                result = clean.get("result")
            if (process.returncode != 0 or result is None or clean.get("state") != "clean"
                    or clean.get("attempt_sha256") != record["attempt_sha256"]
                    or clean.get("result") != result):
                raise ExecutionUncertain("guardian lacks durable cleanup acknowledgement")
            token = lease.token.encode()
            return ProcessResult(
                reason=stopping or result["reason"], returncode=result["returncode"],
                stdout=bytes(output["stdout"]).replace(token, b"[REDACTED]"),
                stderr=bytes(output["stderr"]).replace(token, b"[REDACTED]"),
                started_at_ns=result["started_at_ns"], completed_at_ns=result["completed_at_ns"],
                resource_sha256=record["resource_sha256"], task_sha256=record["task_sha256"],
                generation=record["generation"], token_sha256=record["token_sha256"],
            )
        finally:
            # EOF independently tells the guardian to clean up, including on
            # KeyboardInterrupt or failures in the calling application.
            _close(child_channel, parent, selector)
            if process is not None:
                for stream in (process.stdout, process.stderr):
                    stream.close()
                try:
                    process.wait(timeout=limits.term_grace_s + limits.kill_grace_s + 1)
                except subprocess.TimeoutExpired:
                    # Do not kill the lock holder: it may own an unkillable
                    # descendant. Its watchdog keeps enforcing quarantine.
                    # Retain/reap the child even if this supervisor is never
                    # called again. One daemon waiter owns each live guardian.
                    threading.Thread(target=process.wait, daemon=True,
                                     name="runner-guardian-reaper").start()
