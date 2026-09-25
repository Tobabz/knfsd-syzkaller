#!/usr/bin/env python3
"""Deterministic guest workloads for the Frozen Baseline Phase 1 gate.

The cross-client roles are intended to be launched concurrently in separate
client network namespaces.  They coordinate through ``--sync-dir``, which must
name the same host-visible (non-NFS) directory in both namespaces.  The
``--mount`` paths may differ, but must refer to the same lane export.

Examples::

  python3 frozen_phase1_workload.py basic /mnt/lane0-client0 \
      --client client0 --run-id gate-001

  python3 frozen_phase1_workload.py lock-holder \
      /mnt/lane0-client0 /run/frozen-phase1 \
      --client client0 --run-id gate-001
  python3 frozen_phase1_workload.py lock-contender \
      /mnt/lane0-client1 /run/frozen-phase1 \
      --client client1 --run-id gate-001

  python3 frozen_phase1_workload.py rename-reader \
      /mnt/lane0-client0 /run/frozen-phase1 \
      --client client0 --run-id gate-002
  python3 frozen_phase1_workload.py rename-renamer \
      /mnt/lane0-client1 /run/frozen-phase1 \
      --client client1 --run-id gate-002

Every invocation emits exactly one JSON result to stdout.  ``--output`` writes
the same result to a file as well.  A passing rename-reader result always has
``reads_ok == iterations``: the reader opens the file before each synchronized
rename, then races its read of that fd against the other client's rename.
"""

import argparse
import errno
import fcntl
import json
import os
import re
import sys
import time
from pathlib import Path


SCHEMA_VERSION = 1
PAYLOAD_PREFIX = b"frozen-phase1-rename-read\n"
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")


class WorkloadFailure(RuntimeError):
    """An acceptance-relevant workload failure."""


def safe_component(value, label):
    if not SAFE_COMPONENT.fullmatch(value) or value in (".", ".."):
        raise WorkloadFailure(
            "%s must contain only 1-96 letters, digits, '.', '_' or '-'" % label
        )
    return value


def checked_mount(path):
    mount = Path(path).resolve()
    if not mount.is_dir():
        raise WorkloadFailure("mount path is not a directory: %s" % mount)
    return mount


def write_all(fd, data):
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise WorkloadFailure("write made no progress")
        offset += written


def read_all(fd, size=4096):
    chunks = []
    while True:
        chunk = os.read(fd, size)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def lock_exclusive(fd, nonblocking=False):
    operation = fcntl.LOCK_EX
    if nonblocking:
        operation |= fcntl.LOCK_NB
    fcntl.lockf(fd, operation, 0, 0, os.SEEK_SET)


def unlock(fd):
    fcntl.lockf(fd, fcntl.LOCK_UN, 0, 0, os.SEEK_SET)


def unlink_if_present(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def atomic_json_write(path, value):
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = path.parent / (".%s.%d.tmp" % (path.name, os.getpid()))
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        write_all(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.replace(str(temporary), str(path))
    finally:
        unlink_if_present(temporary)


class SyncChannel:
    """Small filesystem-marker protocol shared by cross-client processes."""

    def __init__(self, base, run_id, timeout):
        self.directory = Path(base).resolve() / ("frozen-phase1-" + run_id)
        self.directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise WorkloadFailure("sync path is not a directory: %s" % self.directory)
        self.timeout = timeout

    def publish(self, name, value):
        safe_component(name, "marker name")
        atomic_json_write(self.directory / (name + ".json"), value)

    def wait(self, name, peer_error_names=()):
        safe_component(name, "marker name")
        deadline = time.monotonic() + self.timeout
        marker = self.directory / (name + ".json")
        peer_errors = [
            self.directory / (safe_component(item, "error marker") + ".json")
            for item in peer_error_names
        ]
        while True:
            for error_marker in peer_errors:
                if error_marker.is_file():
                    detail = self._read(error_marker)
                    raise WorkloadFailure(
                        "peer failed (%s): %s"
                        % (error_marker.stem, detail.get("error", "unknown error"))
                    )
            if marker.is_file():
                return self._read(marker)
            if time.monotonic() >= deadline:
                raise WorkloadFailure("timed out waiting for marker %s" % name)
            time.sleep(0.01)

    @staticmethod
    def _read(path):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise WorkloadFailure("invalid sync marker %s: %s" % (path, error))
        if not isinstance(value, dict):
            raise WorkloadFailure("sync marker is not a JSON object: %s" % path)
        return value


def result_base(args, workload, role=None):
    value = {
        "client": args.client,
        "run_id": args.run_id,
        "schema": SCHEMA_VERSION,
        "status": "pass",
        "workload": workload,
    }
    if role is not None:
        value["role"] = role
    return value


def basic_workload(args):
    mount = checked_mount(args.mount)
    run_id = safe_component(args.run_id, "run-id")
    client = safe_component(args.client, "client")
    directory = mount / (".frozen-phase1-basic-%s-%s" % (run_id, client))
    original = directory / "created"
    renamed = directory / "renamed"
    payload = ("frozen-phase1:%s:%s\n" % (run_id, client)).encode()
    fd = None
    operations = []

    # A previous process crash may leave only these two workload-owned paths.
    # Never recursively delete an unexpected directory tree.
    directory.mkdir(mode=0o700, exist_ok=True)
    unlink_if_present(original)
    unlink_if_present(renamed)
    try:
        fd = os.open(
            str(original), os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
        operations.extend(("CREATE", "OPEN"))
        write_all(fd, payload)
        operations.append("WRITE")
        os.fsync(fd)
        operations.append("FSYNC")
        os.lseek(fd, 0, os.SEEK_SET)
        if read_all(fd) != payload:
            raise WorkloadFailure("basic workload read did not match written payload")
        operations.append("READ")
        lock_exclusive(fd)
        operations.append("LOCK")
        unlock(fd)
        operations.append("LOCKU")
        os.close(fd)
        fd = None
        operations.append("CLOSE")

        os.rename(str(original), str(renamed))
        operations.append("RENAME")
        verify_fd = os.open(str(renamed), os.O_RDONLY | os.O_CLOEXEC)
        try:
            if read_all(verify_fd) != payload:
                raise WorkloadFailure("renamed file payload changed")
        finally:
            os.close(verify_fd)
        unlink_if_present(renamed)
        operations.append("REMOVE")
        directory.rmdir()
    finally:
        if fd is not None:
            try:
                unlock(fd)
            except OSError:
                pass
            os.close(fd)
        unlink_if_present(original)
        unlink_if_present(renamed)
        try:
            directory.rmdir()
        except FileNotFoundError:
            pass

    result = result_base(args, "basic")
    result["operations"] = operations
    result["payload_bytes"] = len(payload)
    return result


def lock_path(args):
    mount = checked_mount(args.mount)
    return mount / (".frozen-phase1-cross-lock-%s" % safe_component(args.run_id, "run-id"))


def lock_holder(args, channel):
    path = lock_path(args)
    payload = b"frozen-phase1-cross-lock\n"
    fd = None
    unlink_if_present(path)
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
        write_all(fd, payload)
        os.fsync(fd)
        lock_exclusive(fd)
        channel.publish("lock-holder-ready", {"status": "ready"})
        conflict = channel.wait("lock-contender-conflict", ("lock-contender-error",))
        if conflict.get("blocked") is not True:
            raise WorkloadFailure("contender did not report an advisory-lock conflict")
        unlock(fd)
        channel.publish("lock-holder-released", {"status": "released"})
        acquired = channel.wait("lock-contender-acquired", ("lock-contender-error",))
        if acquired.get("acquired") is not True:
            raise WorkloadFailure("contender did not acquire the released lock")
        os.close(fd)
        fd = None
        unlink_if_present(path)
    finally:
        if fd is not None:
            try:
                unlock(fd)
            except OSError:
                pass
            os.close(fd)
        unlink_if_present(path)

    result = result_base(args, "cross_lock", "holder")
    result["checks"] = {
        "contender_acquired_after_release": True,
        "contender_conflict_observed": True,
        "holder_lock_acquired": True,
        "holder_lock_released": True,
    }
    return result


def lock_contender(args, channel):
    path = lock_path(args)
    channel.wait("lock-holder-ready", ("lock-holder-error",))
    fd = os.open(str(path), os.O_RDWR | os.O_CLOEXEC)
    acquired_unexpectedly = False
    try:
        try:
            lock_exclusive(fd, nonblocking=True)
            acquired_unexpectedly = True
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN):
                raise
        if acquired_unexpectedly:
            unlock(fd)
            raise WorkloadFailure("contender acquired the lock while holder still owned it")
        channel.publish("lock-contender-conflict", {"blocked": True})
        channel.wait("lock-holder-released", ("lock-holder-error",))
        lock_exclusive(fd)
        unlock(fd)
    finally:
        os.close(fd)
    channel.publish("lock-contender-acquired", {"acquired": True})

    result = result_base(args, "cross_lock", "contender")
    result["checks"] = {
        "acquired_after_release": True,
        "nonblocking_conflict_observed": True,
    }
    return result


def race_paths(args):
    mount = checked_mount(args.mount)
    run_id = safe_component(args.run_id, "run-id")
    return (
        mount / (".frozen-phase1-race-%s-left" % run_id),
        mount / (".frozen-phase1-race-%s-right" % run_id),
    )


def iteration_marker(iteration, suffix):
    return "rename-%06d-%s" % (iteration, suffix)


def rename_reader(args, channel):
    source, _destination = race_paths(args)
    channel.wait("rename-race-ready", ("rename-renamer-error",))
    reads_ok = 0
    for iteration in range(args.iterations):
        channel.wait(
            iteration_marker(iteration, "ready"), ("rename-renamer-error",)
        )
        fd = os.open(str(source), os.O_RDONLY | os.O_CLOEXEC)
        try:
            channel.publish(iteration_marker(iteration, "reader-open"), {"open": True})
            channel.wait(iteration_marker(iteration, "go"), ("rename-renamer-error",))
            os.lseek(fd, 0, os.SEEK_SET)
            if read_all(fd) != PAYLOAD_PREFIX:
                raise WorkloadFailure(
                    "reader payload mismatch in iteration %d" % iteration
                )
            reads_ok += 1
        finally:
            os.close(fd)
        channel.publish(iteration_marker(iteration, "reader-done"), {"read": True})

    summary = {"iterations": args.iterations, "reads_ok": reads_ok}
    channel.publish("rename-reader-complete", summary)
    result = result_base(args, "cross_rename_read", "reader")
    result.update(summary)
    return result


def rename_renamer(args, channel):
    source, destination = race_paths(args)
    fd = None
    unlink_if_present(source)
    unlink_if_present(destination)
    renames_forward = 0
    removes = 0
    recreates = 0
    try:
        fd = os.open(
            str(source), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600
        )
        write_all(fd, PAYLOAD_PREFIX)
        os.fsync(fd)
        os.close(fd)
        fd = None
        channel.publish("rename-race-ready", {"status": "ready"})

        for iteration in range(args.iterations):
            channel.publish(iteration_marker(iteration, "ready"), {"ready": True})
            channel.wait(
                iteration_marker(iteration, "reader-open"), ("rename-reader-error",)
            )
            # Publishing GO and immediately renaming lets the peer's read of its
            # already-open NFS fd race this namespace operation without making
            # the expected result depend on scheduler order.
            channel.publish(iteration_marker(iteration, "go"), {"go": True})
            os.rename(str(source), str(destination))
            renames_forward += 1
            destination.unlink()
            removes += 1
            done = channel.wait(
                iteration_marker(iteration, "reader-done"), ("rename-reader-error",)
            )
            if done.get("read") is not True:
                raise WorkloadFailure("reader did not complete iteration %d" % iteration)
            recreate_fd = os.open(
                str(source),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                0o600,
            )
            try:
                write_all(recreate_fd, PAYLOAD_PREFIX)
                os.fsync(recreate_fd)
            finally:
                os.close(recreate_fd)
            recreates += 1

        reader = channel.wait("rename-reader-complete", ("rename-reader-error",))
        if reader.get("iterations") != args.iterations:
            raise WorkloadFailure("reader iteration count differs from renamer")
        if reader.get("reads_ok") != args.iterations:
            raise WorkloadFailure("not every read succeeded across rename")
        unlink_if_present(source)
    finally:
        if fd is not None:
            os.close(fd)
        unlink_if_present(source)
        unlink_if_present(destination)

    result = result_base(args, "cross_rename_read", "renamer")
    result.update(
        {
            "iterations": args.iterations,
            "recreates": recreates,
            "reader_reads_ok": args.iterations,
            "removes": removes,
            "renames_forward": renames_forward,
        }
    )
    return result


def add_identity_arguments(parser, with_sync=False):
    parser.add_argument("mount", help="client's NFS mount path")
    if with_sync:
        parser.add_argument("sync_dir", help="shared host-visible coordination directory")
    else:
        # Optional for callers that use one uniform ROLE MOUNT SYNC_DIR shape.
        parser.add_argument("sync_dir", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--client", required=True, help="stable diagnostic client name")
    parser.add_argument("--run-id", required=True, help="unique coordination/run identifier")
    parser.add_argument("--output", help="also write the final JSON result here")
    if with_sync:
        parser.add_argument(
            "--timeout", type=float, default=30.0, help="peer-marker timeout in seconds"
        )


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    basic = subparsers.add_parser("basic", help="single-client CRUD, fsync and lock test")
    add_identity_arguments(basic)

    for command, help_text in (
        ("lock-holder", "hold a cross-client advisory lock"),
        ("lock-contender", "verify conflict and acquire after release"),
        ("rename-reader", "read an open fd while the peer renames it"),
        ("rename-renamer", "rename a file while the peer reads its open fd"),
    ):
        child = subparsers.add_parser(command, help=help_text)
        add_identity_arguments(child, with_sync=True)
        if command.startswith("rename-"):
            child.add_argument(
                "--iterations", type=int, default=32, help="synchronized race iterations"
            )

    args = parser.parse_args(argv)
    safe_component(args.run_id, "run-id")
    safe_component(args.client, "client")
    if hasattr(args, "timeout") and args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if hasattr(args, "iterations") and args.iterations <= 0:
        parser.error("--iterations must be greater than zero")
    return args


def emit_result(args, result):
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    sys.stdout.write(rendered)
    sys.stdout.flush()
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        atomic_json_write(output, result)


def main(argv=None):
    args = parse_args(argv)
    channel = None
    role = {
        "lock-holder": "holder",
        "lock-contender": "contender",
        "rename-reader": "reader",
        "rename-renamer": "renamer",
    }.get(args.command)
    error_marker = args.command + "-error" if role is not None else None
    workload = "basic"
    try:
        if args.command == "basic":
            result = basic_workload(args)
        else:
            channel = SyncChannel(args.sync_dir, args.run_id, args.timeout)
            if args.command == "lock-holder":
                workload = "cross_lock"
                result = lock_holder(args, channel)
            elif args.command == "lock-contender":
                workload = "cross_lock"
                result = lock_contender(args, channel)
            elif args.command == "rename-reader":
                workload = "cross_rename_read"
                result = rename_reader(args, channel)
            elif args.command == "rename-renamer":
                workload = "cross_rename_read"
                result = rename_renamer(args, channel)
            else:  # argparse prevents this; retain fail-closed behavior.
                raise WorkloadFailure("unknown command: %s" % args.command)
    except Exception as error:  # Emit machine-readable Gate evidence on all failures.
        result = result_base(args, workload, role)
        result.update(
            {
                "error": str(error),
                "error_type": type(error).__name__,
                "status": "fail",
            }
        )
        if channel is not None and error_marker is not None:
            try:
                channel.publish(error_marker, result)
            except Exception as marker_error:
                result["sync_error"] = str(marker_error)
        emit_result(args, result)
        return 1

    emit_result(args, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
