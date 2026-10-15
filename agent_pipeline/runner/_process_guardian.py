"""Private Linux guardian, executed by absolute path with ``python -I``.

Only stdlib imports: this process must not import application startup hooks.
The inherited flock bridges the spawn/ownership-record window.  PR_SET_CHILD_
SUBREAPER makes every surviving descendant an owned child during cleanup;
signals go through pidfds, never a PID read from an old ownership record.
"""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time


MAX_PACKET = 60_000
MAX_RECORD = 16_384
POLL = 0.02


def private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("supervisor state directory must be private")
    finally:
        os.close(fd)


def checked_open(path: Path, flags: int) -> int:
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    info = os.fstat(fd)
    # A reader can open the previous committed inode just before an atomic
    # record replacement unlinks it. That remains a valid immutable snapshot.
    # Writers and the lock must always refer to a linked, exclusive inode.
    allowed_links = (0, 1) if (flags & os.O_ACCMODE) == os.O_RDONLY else (1,)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink not in allowed_links):
        os.close(fd)
        raise ValueError("unsafe supervisor state file")
    return fd


def sync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_record(path: Path, record: dict) -> None:
    raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_RECORD:
        raise ValueError("supervisor record too large")
    temporary = path.with_name(path.name + ".new")
    fd = checked_open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def read_record(path: Path) -> dict:
    fd = checked_open(path, os.O_RDONLY)
    with os.fdopen(fd, "rb") as stream:
        raw = stream.read(MAX_RECORD + 1)
    if len(raw) > MAX_RECORD:
        raise ValueError("supervisor record too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid supervisor record")
    return value


def process_identity(pid: int) -> dict:
    # comm can contain spaces and ')'; the remaining stat fields cannot.
    raw = Path(f"/proc/{pid}/stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    return {"pid": pid, "start_ticks": int(fields[19])}


def _children() -> list[int]:
    # This guardian has one thread. Limit each pass; a fork-heavy command
    # cannot force unbounded Python memory. A truncated pass is never empty.
    with open(f"/proc/self/task/{os.getpid()}/children", "rb") as stream:
        raw = stream.read(65_536)
    if len(raw) == 65_536:
        raw = raw[:raw.rfind(b" ") + 1]
    return [int(pid) for pid in raw.split()][:4096]


def _signal_child(pid: int, signum: int) -> None:
    # A direct child cannot have its PID reused before *we* reap it. pidfds
    # additionally bind the signal to that exact task, including after exit.
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        return
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        fields = raw[raw.rfind(")") + 2:].split()
        if int(fields[1]) != os.getpid():
            raise RuntimeError("child ownership changed")
        signal.pidfd_send_signal(fd, signum)
    except ProcessLookupError:
        pass
    finally:
        os.close(fd)


def _send(channel: socket.socket, value: dict) -> None:
    try:
        channel.send(json.dumps(value, separators=(",", ":")).encode())
    except (OSError, BlockingIOError):
        # Parent death is expected. Durable clean state, not delivery of an
        # acknowledgement, is what allows the next owner to use this resource.
        pass


def _receive(channel: socket.socket) -> dict | None:
    try:
        raw, _, flags, _ = channel.recvmsg(MAX_PACKET)
    except ConnectionResetError:
        # SOCK_SEQPACKET reports reset on close with unread renewals, including
        # a successful guardian that already delivered its final result.
        return None
    if not raw:
        return None
    if flags & socket.MSG_TRUNC:
        raise ValueError("oversized guardian message")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid guardian message")
    return value


def _prepare(channel: socket.socket) -> dict | None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "subreaper unavailable")
    # Verify the required kernel interfaces before creating any payload
    # process: pidfds, and the children list (CONFIG_PROC_CHILDREN) that
    # tree cleanup polls.
    probe = os.pidfd_open(os.getpid())
    os.close(probe)
    _children()
    channel.settimeout(2.0)
    return _receive(channel)


def _refuse(channel: socket.socket, resource: Path) -> None:
    """Record clean(guardian_failed) for a failure before `active`.

    The payload is spawned only after `active` is durable, and this guardian
    holds the resource lock the parent reserved under, so a `reserved` record
    proves no payload ever ran. Any other record is left untouched.
    """
    try:
        record = read_record(resource / "current.json")
        if record.get("state") != "reserved":
            return
        now = time.time_ns()
        result = dict(type="result", reason="guardian_failed", returncode=None,
                      started_at_ns=now, completed_at_ns=now)
        record.update(state="clean", result=result)
        write_record(resource / "current.json", record)
    except Exception:
        return  # Fail closed: the record stays reserved.
    channel.setblocking(False)
    _finish(channel, result)


def run(channel: socket.socket, lock_fd: int, resource: Path) -> None:
    # The caller already holds this inherited open-file-description lock.
    # Do not unlock it: closing the last copy releases ownership on exit.
    os.fstat(lock_fd)
    try:
        config = _prepare(channel)
    except Exception:
        config = None
    if config is None:
        _refuse(channel, resource)
        return
    channel.setblocking(False)
    record = read_record(resource / "current.json")
    if (record["state"] != "reserved"
            or record["attempt_sha256"] != config["attempt_sha256"]):
        raise ValueError("guardian reservation mismatch")
    record.update(state="active", guardian=process_identity(os.getpid()))
    # Persist BEFORE spawning the payload. If SIGKILL hits the guardian in
    # the spawn-before-child-record window, restart refuses this dirty record.
    write_record(resource / "current.json", record)

    interrupted = False

    def stop(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    limits = config["limits"]
    started_ns = time.time_ns()
    started = time.monotonic()
    expires_ns = config["expires_at_ns"]
    lease_deadline = started + max(0, (expires_ns - started_ns) / 1e9)
    heartbeat_deadline = started + limits["heartbeat_timeout_s"]
    child = None
    reason = "guardian_failed"
    returncode = None
    try:
        if lease_deadline <= started:
            reason = "lease_lost"
        else:
            command = config["command"]
            try:
                child = subprocess.Popen(
                    command["argv"], cwd=command["cwd"], env=command["env"],
                    stdin=subprocess.DEVNULL, close_fds=True,
                    start_new_session=True,
                )
            except OSError:
                reason = "spawn_failed"
            if child is not None:
                record["child"] = process_identity(child.pid)
                write_record(resource / "current.json", record)
                while True:
                    now = time.monotonic()
                    if interrupted:
                        reason = "stop_requested"
                        break
                    if now >= lease_deadline or time.time_ns() >= expires_ns:
                        reason = "lease_lost"
                        break
                    if now >= heartbeat_deadline:
                        reason = "heartbeat_lost"
                        break
                    if now - started >= limits["timeout_s"]:
                        reason = "timed_out"
                        break
                    # Bounded receive work keeps a busy control socket from
                    # starving watchdogs. Only this parent can write to it.
                    for _ in range(16):
                        try:
                            message = _receive(channel)
                        except BlockingIOError:
                            break
                        if message is None:
                            reason = "parent_lost"
                            break
                        if message.get("type") == "stop":
                            reason = message["reason"]
                            break
                        if message.get("type") != "renew":
                            raise ValueError("invalid guardian control")
                        renewed = message["expires_at_ns"]
                        if type(renewed) is not int or renewed < expires_ns:
                            raise ValueError("invalid guardian renewal")
                        # Equal-expiry heartbeats cannot extend the lease by
                        # exploiting a backwards wall-clock adjustment.
                        lease_deadline = min(
                            lease_deadline + (renewed - expires_ns) / 1e9,
                            now + max(0, (renewed - time.time_ns()) / 1e9),
                        )
                        expires_ns = renewed
                        heartbeat_deadline = now + limits["heartbeat_timeout_s"]
                    if reason != "guardian_failed":
                        break
                    exited = os.waitid(os.P_PID, child.pid,
                                       os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if exited is not None:
                        reason = "completed"
                        break
                    time.sleep(POLL)
    except BaseException:
        reason = "guardian_failed"
    finally:
        # Never use Popen.poll/wait before discovering adopted descendants.
        # Even a normally exited leader can leave a live grandchild holding
        # pipes or using the host resource. Stop/reap the ENTIRE owned tree.
        stopping = time.monotonic()
        quarantined = False
        while True:
            try:
                children = _children()
                if not children:
                    break
                signum = (signal.SIGTERM if time.monotonic() - stopping
                          < limits["term_grace_s"] else signal.SIGKILL)
                for pid in children:
                    _signal_child(pid, signum)
                    reaped, status = os.waitpid(pid, os.WNOHANG)
                    if reaped and child is not None and pid == child.pid:
                        returncode = os.waitstatus_to_exitcode(status)
                        child.returncode = returncode
            except BaseException:
                # Inspection/signal failures cannot certify an empty tree.
                pass
            if (not quarantined and time.monotonic() - stopping
                    >= limits["term_grace_s"] + limits["kill_grace_s"]):
                quarantined = True
                record["state"] = "quarantined"
                try:
                    write_record(resource / "current.json", record)
                except OSError:
                    pass
                _send(channel, {"type": "quarantined"})
            # On an unkillable task keep the resource lock, even after the
            # bounded caller returns an error. Never admit a replacement.
            time.sleep(POLL if not quarantined else 0.1)

    result = dict(type="result", reason=reason, returncode=returncode,
                  started_at_ns=started_ns, completed_at_ns=time.time_ns())
    record.update(state="clean", result=result)
    write_record(resource / "current.json", record)
    _finish(channel, result)


def _finish(channel: socket.socket, result: dict) -> None:
    _send(channel, result)
    # Closing a sequenced-packet socket with unread heartbeats can reset the
    # peer and discard its final acknowledgement. Half-close and drain until
    # the parent acknowledges by half-closing, with a bounded grace period.
    try:
        channel.shutdown(socket.SHUT_WR)
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            try:
                if _receive(channel) is None:
                    break
            except BlockingIOError:
                time.sleep(POLL)
    except (OSError, ValueError):
        pass


if __name__ == "__main__":
    # Diagnostics intentionally omit argv/config/environment and bearer data.
    try:
        with socket.socket(fileno=int(sys.argv[1])) as connection:
            run(connection, int(sys.argv[2]), Path(sys.argv[3]))
    except BaseException:
        sys.exit(70)
