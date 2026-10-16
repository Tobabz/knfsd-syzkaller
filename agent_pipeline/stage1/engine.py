"""A Runner ``ExecutionEngine`` that runs one trusted host command per lease.

The command is host configuration (absolute argv, cwd, environment and
resource key); nothing in it comes from a candidate or model output.  For
each lease the engine writes the materialized harness into a fresh
directory, runs the command under ``ProcessSupervisor`` and reads back the
files the command lists.

Command contract (``{input}`` and ``{output}`` in argv are replaced by the
two directories):

``input/``
    ``execution.json``  job_id, task_id, harness_ref, execution_harness_id,
                        lease_generation
    ``harness.json``    the canonical ``ReachabilityHarness`` record
    ``descriptor.json`` the canonical ``ExecutionHarnessDescriptor``
    ``program.syz``     the scenario program bytes
    ``neutral.syz``     the repository neutral control program bytes

``output/capture.json`` (written by the command)::

    {"vm_instance_id": "...", "lane": 0, "generation_id": 1,
     "artifacts": [{"identity": "reachability",
                    "type": "application/vnd.knfsd.reachability+json",
                    "path": "reachability.json"}, ...]}

Paths are relative to ``output/`` and must be regular files there.  The
collection interval is the supervised process's own start and end time;
the command does not report it.  A nonzero exit, a timeout or a malformed
capture fails the run (``capture_failed``), never a verdict.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..artifacts import ArtifactStore
from ..data import canonical_json, load_record, parse_json
from ..evidence import ArtifactInput, EvidenceLimits
from ..materializer import ExecutionHarnessDescriptor, ReachabilityHarness
from ..runner.evidence_backend import ExecutionCapture, HostExecutionFacts
from ..runner.models import WorkLease
from ..runner.process_supervisor import HostCommand, ProcessLimits, ProcessSupervisor
from ..runner.worker import LeaseControl

INPUT = "{input}"
OUTPUT = "{output}"
MAX_CAPTURE_INDEX_BYTES = 64 * 1024


class CaptureError(RuntimeError):
    """The command did not produce a usable capture."""


class _CaptureEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    identity: str
    type: str
    path: str = Field(min_length=1, max_length=255)


class _CaptureIndex(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    vm_instance_id: str
    lane: int
    generation_id: int
    artifacts: tuple[_CaptureEntry, ...] = Field(min_length=1, max_length=256)


@dataclass(frozen=True)
class CommandEngineConfig:
    argv: tuple[str, ...]
    cwd: Path
    work_root: Path
    resource_key: str
    collector_id: str
    env: Mapping[str, str] = field(default_factory=lambda: {"LANG": "C.UTF-8"})
    limits: ProcessLimits = ProcessLimits()


def _read_regular(directory: Path, name: str, max_bytes: int) -> bytes:
    if "/" in name or name in (".", "..") or "\0" in name:
        raise CaptureError(f"capture path must be a file name: {name!r}")
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        raise CaptureError(f"capture file unavailable: {name}") from exc
    finally:
        os.close(dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CaptureError(f"capture file is not regular: {name}")
        if st.st_size > max_bytes:
            raise CaptureError(f"capture file exceeds limit: {name}")
        chunks = []
        total = 0
        while chunk := os.read(fd, 1 << 20):
            total += len(chunk)
            if total > max_bytes:
                raise CaptureError(f"capture file exceeds limit: {name}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


class CommandExecutionEngine:
    def __init__(self, config: CommandEngineConfig, artifacts: ArtifactStore,
                 supervisor: ProcessSupervisor, *,
                 limits: EvidenceLimits = EvidenceLimits()) -> None:
        self.config = config
        self.artifacts = artifacts
        self.supervisor = supervisor
        self.limits = limits

    def _prepare(self, lease: WorkLease) -> tuple[Path, Path]:
        b = lease.binding
        run = self.config.work_root / f"{b.task_id}.g{lease.generation}"
        inp, out = run / "input", run / "output"
        # A new lease generation always gets a new directory.  An existing
        # one belongs to an earlier attempt of this generation; never reuse.
        run.mkdir(parents=True, exist_ok=False)
        inp.mkdir()
        out.mkdir()
        harness = load_record(self.artifacts, b.harness_ref, ReachabilityHarness)
        if harness.execution_harness_id != b.execution_harness_id:
            raise CaptureError("harness does not belong to this execution harness")
        descriptor = load_record(self.artifacts, b.execution_harness_id,
                                 ExecutionHarnessDescriptor)
        _write(inp / "execution.json", canonical_json({
            "job_id": b.job_id, "task_id": b.task_id,
            "harness_ref": b.harness_ref,
            "execution_harness_id": b.execution_harness_id,
            "lease_generation": lease.generation}))
        _write(inp / "harness.json", canonical_json(harness))
        _write(inp / "descriptor.json", canonical_json(descriptor))
        _write(inp / "program.syz", self.artifacts.get(harness.program_ref))
        _write(inp / "neutral.syz",
               self.artifacts.get(harness.neutral_program_ref))
        return inp, out

    def capture(self, lease: WorkLease,
                control: LeaseControl) -> ExecutionCapture:
        inp, out = self._prepare(lease)
        argv = tuple(arg.replace(INPUT, str(inp)).replace(OUTPUT, str(out))
                     for arg in self.config.argv)
        result = self.supervisor.run(
            HostCommand(argv, self.config.cwd, dict(self.config.env)),
            lease, control, resource_key=self.config.resource_key,
            limits=self.config.limits)
        log = out.parent / "process.log"
        _write(log, result.stdout + b"\n--- stderr ---\n" + result.stderr)
        if result.reason != "completed" or result.returncode != 0:
            raise CaptureError(
                f"host command ended {result.reason} rc={result.returncode}")
        raw = _read_regular(out, "capture.json", MAX_CAPTURE_INDEX_BYTES)
        try:
            index = _CaptureIndex.model_validate(parse_json(raw))
        except (ValueError, TypeError) as exc:
            raise CaptureError("malformed capture.json") from exc
        artifacts = []
        total = 0
        for entry in index.artifacts:
            data = _read_regular(out, entry.path, self.limits.max_artifact_bytes)
            total += len(data)
            if total > self.limits.max_bundle_bytes:
                raise CaptureError("capture exceeds the bundle limit")
            artifacts.append(ArtifactInput(identity=entry.identity,
                                           type=entry.type, data=data))
        return ExecutionCapture(
            facts=HostExecutionFacts(
                vm_instance_id=index.vm_instance_id, lane=index.lane,
                generation_id=index.generation_id,
                collector_id=self.config.collector_id,
                collection_started_at_ns=result.started_at_ns,
                collection_completed_at_ns=result.completed_at_ns),
            artifacts=tuple(artifacts))

