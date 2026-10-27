"""Persist a job's Program-based policy before any fuzzing VM starts."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Mapping, Protocol

from agent_pipeline.contracts import JobPolicy, Sanitizer
from agent_pipeline.controller.records import Job
from .program_policy import prepare_program_policy


class JobLookup(Protocol):
    def job(self, job_id: str) -> Job: ...

    def policy(self, policy_id: str) -> JobPolicy: ...


class ProgramPolicyPipeline:
    def __init__(self, jobs: JobLookup, root: Path) -> None:
        self.jobs = jobs
        self.root = Path(root).resolve()

    def prepare(self, job_id: str) -> Path | None:
        job = self.jobs.job(job_id)
        if self.jobs.policy(job.job_policy_id).sanitizer is not Sanitizer.KCSAN:
            return None
        if job.candidate is None:
            raise ValueError("KCSAN job has no accepted candidate")
        if job.binding is not None and \
                job.candidate.kernel_commit != job.binding.kernel_commit:
            raise ValueError("KCSAN candidate and harness kernel do not match")
        payload = prepare_program_policy(job.candidate)
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / f"{job.candidate.candidate_id}_policy.payload"
        self._write_once(path, payload)
        return path

    def manager_config(self, job_id: str,
                       config: Mapping[str, object]) -> dict[str, object]:
        """Select this job's payload file before syz-manager starts."""
        prepared = self.prepare(job_id)
        result = dict(config)
        if prepared is None:
            if "kcsan_policy_file" in result:
                raise ValueError("non-KCSAN job cannot select a KCSAN policy file")
            return result
        selected = result.get("kcsan_policy_file")
        if selected is not None and selected != str(prepared):
            raise ValueError("syz-manager config selects another KCSAN policy file")
        result["kcsan_policy_file"] = str(prepared)
        return result

    @staticmethod
    def _write_once(path: Path, payload: bytes) -> None:
        # The manager reads this directory at startup. Never expose a partial
        # payload or silently replace a different policy for the same candidate.
        if path.exists():
            if path.read_bytes() != payload:
                raise ValueError(f"conflicting KCSAN policy at {path}")
            return
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
            temporary = Path(tmp.name)
            try:
                tmp.write(payload)
                tmp.flush()
                os.fsync(tmp.fileno())
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    if path.read_bytes() != payload:
                        raise ValueError(f"conflicting KCSAN policy at {path}")
            finally:
                temporary.unlink(missing_ok=True)
