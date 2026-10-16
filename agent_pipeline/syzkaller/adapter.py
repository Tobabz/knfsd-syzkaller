"""Strict prog API adapter with a host-approved, sealed executable snapshot.

The expected identity is authority supplied by the host. A bundle's adjacent
identity.json is a build result, never its own authorization. No source text or
program comments are interpreted here as syscall or provenance claims.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass

from ..admission import (
    SyzkallerBuildManifest, SyzkallerCallTable, SyzkallerTargetIdentity,
)
from ..data import canonical_json, parse_json
from ..materializer import (
    PARSER_CALL_NAME, PARSER_REFUSALS, ParsedProgram, SyzParseFailure,
)

MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
# Linux uapi fcntl.h constants. Some supported Python 3.11 builds do not
# expose the names despite providing memfd_create; the kernel still enforces
# exactly the same seals. No fallback to an unsealed on-disk executable.
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_ALL_SEALS = 0x0001 | 0x0002 | 0x0004 | 0x0008


@dataclass(frozen=True)
class BridgeLimits:
    max_program_bytes: int = 256 * 1024
    max_stdout_bytes: int = 16 * 1024 * 1024
    max_stderr_bytes: int = 64 * 1024
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        for name, maximum in (("max_program_bytes", 256 * 1024),
                              ("max_stdout_bytes", 16 * 1024 * 1024),
                              ("max_stderr_bytes", 64 * 1024)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"invalid {name}")
        if (type(self.timeout_seconds) not in (int, float)
                or not 0 < self.timeout_seconds <= 60):
            raise ValueError("invalid timeout_seconds")


def _read_regular(root: Path, name: str, limit: int) -> bytes:
    """Open every path component with O_NOFOLLOW, then read a bounded fd."""
    parts = name.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise SyzParseFailure("invalid bundle path")
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise SyzParseFailure("bundle file type or size rejected")
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise SyzParseFailure("bundle file size limit exceeded")
            return data
    finally:
        os.close(directory)


def _load(root: Path, name: str, model):
    data = _read_regular(root, name, MAX_METADATA_BYTES)
    parse_json(data)
    value = model.model_validate_json(data)
    if canonical_json(value) != data:
        raise SyzParseFailure(f"noncanonical {name}")
    return value, hashlib.sha256(data).hexdigest()


class PinnedSyzParser:
    """Implements materializer.PinnedSyzParser for one immutable target build.

    Construction verifies the manifest and all files, snapshots the executable
    into a sealed Linux memfd and checks the actual generated call table. Use as
    a context manager or call close(). An existing instance remains bound to its
    snapshot even if files are subsequently replaced. Reopening detects drift.
    """

    def __init__(self, bundle_dir: Path, *, identity: SyzkallerTargetIdentity,
                 limits: BridgeLimits = BridgeLimits()) -> None:
        self._fd: int | None = None
        self.limits = limits
        self.identity = SyzkallerTargetIdentity.model_validate_json(
            canonical_json(identity))
        root = Path(bundle_dir).absolute()
        try:
            manifest, manifest_ref = _load(root, "build-manifest.json",
                                           SyzkallerBuildManifest)
            table, table_ref = _load(root, "call-table.json", SyzkallerCallTable)
            if (manifest_ref != identity.build_manifest_sha256
                    or table_ref != identity.call_table_sha256
                    or manifest.syzkaller_commit != identity.syzkaller_commit
                    or table.syzkaller_commit != identity.syzkaller_commit
                    or manifest.patch_series_sha256 != identity.patch_series_sha256
                    or manifest.target != identity.target
                    or table.target != identity.target
                    or identity.target != "linux/amd64"):
                raise SyzParseFailure("bundle identity mismatch")
            total = 0
            executable = None
            for item in manifest.files:
                data = _read_regular(root, item.path, MAX_BINARY_BYTES)
                total += len(data)
                if total > MAX_BUNDLE_BYTES:
                    raise SyzParseFailure("bundle byte limit exceeded")
                if hashlib.sha256(data).hexdigest() != item.artifact_ref:
                    raise SyzParseFailure(f"build artifact digest mismatch: {item.path}")
                if item.path == "bridge":
                    executable = data
            if executable is None or not executable.startswith(b"\x7fELF"):
                raise SyzParseFailure("missing ELF bridge artifact")
            fd = os.memfd_create("knfsd-syz-bridge", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
            self._fd = fd
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(executable)
                stream.flush()
            os.fchmod(fd, 0o500)
            fcntl.fcntl(fd, _F_ADD_SEALS, _ALL_SEALS)
            self._table = table
            self._call_names = frozenset(table.calls)
            self.export_call_table()
        except (OSError, ValueError, TypeError, RecursionError) as error:
            self.close()
            if isinstance(error, SyzParseFailure):
                raise
            raise SyzParseFailure("invalid pinned bridge bundle") from error

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def __enter__(self) -> PinnedSyzParser:
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _invoke(self, operation: str, program: bytes = b"") -> dict:
        if self._fd is None:
            raise SyzParseFailure("parser is closed")
        output = _run(self._fd, operation, program, self.limits)
        try:
            value = parse_json(output)
            if not isinstance(value, dict):
                raise ValueError("not an object")
            info = value["bridge"]
            if (set(info) != {"schema_version", "syzkaller_commit", "patch_series_sha256", "source_tree", "target"}
                    or info["schema_version"] != "knfsd-syz-bridge.v1"
                    or info["syzkaller_commit"] != self.identity.syzkaller_commit
                    or info["patch_series_sha256"] != self.identity.patch_series_sha256
                    or info["target"] != self.identity.target
                    or not isinstance(info["source_tree"], str)
                    or len(info["source_tree"]) != 40
                    or any(c not in "0123456789abcdef" for c in info["source_tree"])):
                raise ValueError("compiled bridge identity mismatch")
            return value
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            raise SyzParseFailure("invalid bridge response or identity") from error

    def export_call_table(self) -> SyzkallerCallTable:
        value = self._invoke("export")
        if set(value) != {"bridge", "call_table"}:
            raise SyzParseFailure("invalid call table response")
        try:
            table = SyzkallerCallTable.model_validate_json(canonical_json(value["call_table"]))
        except (ValueError, TypeError) as error:
            raise SyzParseFailure("invalid call table response") from error
        if table != self._table:
            raise SyzParseFailure("generated target call table mismatch")
        return table

    def parse(self, program: bytes, *, identity: SyzkallerTargetIdentity) -> ParsedProgram:
        if identity != self.identity:
            raise SyzParseFailure("requested parser identity mismatch")
        if type(program) is not bytes or not 0 < len(program) <= self.limits.max_program_bytes:
            raise SyzParseFailure("program byte limit exceeded")
        try:
            value = self._invoke("parse", program)
        except SyzParseFailure as error:
            # Only a call the pinned table resolves can be disabled or an
            # unverified acquisition, and only an absent one is unresolved.
            if error.reason is not None and (
                    (error.call in self._call_names)
                    != (error.reason != "call_unresolved")):
                raise SyzParseFailure("bridge refused: inconsistent typed refusal") from error
            raise
        try:
            if set(value) != {"bridge", "program"}:
                raise ValueError("invalid parse response")
            payload = value["program"]
            if set(payload) != {"program_sha256", "calls", "usage", "nfs_acquisitions"}:
                raise ValueError("invalid program fields")
            parsed = ParsedProgram.model_validate_json(canonical_json({
                **payload, "identity": self.identity.model_dump(mode="json"),
            }))
            if (parsed.program_sha256 != hashlib.sha256(program).hexdigest()
                    or parsed.usage.program_bytes != len(program)
                    or parsed.usage.call_count != len(parsed.calls)
                    or len(parsed.calls) > 4096
                    or parsed.usage.resource_count > 65536
                    or any(c.availability != "available" or c.call not in self._call_names
                           for c in parsed.calls)):
                raise ValueError("inconsistent parse result")
            return parsed
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            raise SyzParseFailure("invalid parsed program") from error


def _typed_refusal(stderr: bytes) -> SyzParseFailure:
    """Decode the bridge's exit-3 refusal; anything malformed stays untyped."""
    try:
        value = parse_json(stderr)
        if (not isinstance(value, dict)
                or set(value) != {"reason", "call_index", "call"}
                or value["reason"] not in PARSER_REFUSALS
                or type(value["call_index"]) is not int
                or not 0 <= value["call_index"] < 4096
                or type(value["call"]) is not str
                or not PARSER_CALL_NAME.fullmatch(value["call"])):
            raise ValueError("invalid typed refusal")
    except (ValueError, TypeError, RecursionError):
        return SyzParseFailure("bridge refused: invalid typed refusal")
    return SyzParseFailure(
        f"bridge refused: {value['reason']}", reason=value["reason"],
        call=value["call"], call_index=value["call_index"])


def _run(fd: int, operation: str, data: bytes, limits: BridgeLimits) -> bytes:
    """Drain both pipes incrementally; kill/reap on overflow or timeout.

    A timeout (``TimeoutError``) or a signal death (``ChildProcessError``)
    is a host failure, an ``OSError`` the Materializer re-raises; only a
    bridge refusal or an invalid answer is a ``SyzParseFailure``.
    """
    with tempfile.TemporaryFile() as source:
        source.write(data)
        source.seek(0)
        process = subprocess.Popen(
            [f"/proc/self/fd/{fd}", operation], pass_fds=(fd,), stdin=source,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"LANG": "C", "GOMAXPROCS": "2", "GOTRACEBACK": "none"},
            start_new_session=True)
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        deadline = time.monotonic() + limits.timeout_seconds
        try:
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    pipe = getattr(process, name)
                    os.set_blocking(pipe.fileno(), False)
                    selector.register(pipe, selectors.EVENT_READ, name)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("bridge timed out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer = buffers[key.data]
                        bound = getattr(limits, f"max_{key.data}_bytes")
                        if len(buffer) + len(chunk) > bound:
                            raise SyzParseFailure(f"bridge {key.data} byte limit exceeded")
                        buffer.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("bridge timed out")
            process.wait(timeout=remaining)
            if process.returncode < 0:
                # Killed by a signal (OOM, host limits): not a verdict on
                # the program.
                raise ChildProcessError(
                    f"bridge killed by signal {-process.returncode}")
            if process.returncode == 3:
                raise _typed_refusal(bytes(buffers["stderr"]))
            if process.returncode:
                diagnostic = buffers["stderr"].decode("utf-8", errors="replace")[:1024]
                raise SyzParseFailure(f"bridge refused ({process.returncode}): {diagnostic}")
            return bytes(buffers["stdout"])
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("bridge timed out") from error
        finally:
            # Kill the process group even if the leader has exited: a failed
            # helper must not leave inherited pipe writers behind.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            process.stdout.close()
            process.stderr.close()
