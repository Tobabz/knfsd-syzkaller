"""Host configuration of the wired Stage 1 service.

Every value here is a host trust decision: which catalog, which approvals,
which parser identity, which command runs a lease.  None of it may be
derived from candidate or model output.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..admission import SyzkallerTargetIdentity
from ..contracts import JobPolicy, JudgeVersions, Sha256


class _Config(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EngineConfig(_Config):
    """The host command that runs one lease; see ``engine`` for its contract."""

    argv: tuple[str, ...] = Field(min_length=1)
    cwd: Path
    env: dict[str, str] = Field(default_factory=lambda: {"LANG": "C.UTF-8"})
    resource_key: str = Field(min_length=1, max_length=256)
    collector_id: str = "stage1-command-engine"
    timeout_s: float = Field(default=1800, gt=0, le=86_400)
    max_output_bytes: int = Field(default=1_048_576, ge=1)

    @field_validator("argv")
    @classmethod
    def _absolute(cls, argv: tuple[str, ...]) -> tuple[str, ...]:
        if not Path(argv[0]).is_absolute():
            raise ValueError("argv[0] must be an absolute path")
        return argv


class Stage2Config(_Config):
    """The Stage 2 backend: the host command that runs one gate, campaign
    or replay lease (see ``stage2.engine`` for its contract), the replay
    Proxy for the ``--check-rules`` gate, and the judge profiles (CAS
    digests of an ``M1JudgeProfile``, ``Q2JudgeProfile`` and
    ``ReplayJudgeProfile``).  Unset, a compiled rule set waits in
    blocked_operator(stage2_gate_unavailable)."""

    argv: tuple[str, ...] = Field(min_length=1)
    cwd: Path
    env: dict[str, str] = Field(default_factory=lambda: {"LANG": "C.UTF-8"})
    resource_key: str = Field(min_length=1, max_length=256)
    collector_id: str = "stage2-command-engine"
    #: A campaign lease runs for its whole fuzz budget.
    timeout_s: float = Field(default=86_400, gt=0, le=86_400)
    max_output_bytes: int = Field(default=1_048_576, ge=1)
    poll_interval_s: float = Field(default=1.0, gt=0, le=60)
    replay_proxy: Path
    m1_profile_ref: Sha256
    q2_profile_ref: Sha256
    replay_profile_ref: Sha256
    crash_window_bound: int = Field(default=4, ge=1, le=64)

    @field_validator("argv")
    @classmethod
    def _absolute(cls, argv: tuple[str, ...]) -> tuple[str, ...]:
        if not Path(argv[0]).is_absolute():
            raise ValueError("argv[0] must be an absolute path")
        return argv


class Stage1Config(_Config):
    state_dir: Path
    artifact_root: Path
    kernel_repo: Path
    #: ``HarnessCatalog`` digest in the CAS (``ArtifactHarnessRegistry``).
    harness_catalog_ref: Sha256
    #: ``ExecutionHarnessApproval`` record digests in the CAS.
    execution_harness_approvals: tuple[Sha256, ...] = Field(min_length=1)
    syzkaller_bundle: Path
    #: Host-approved parser identity; the bundle's identity.json is not.
    syzkaller_identity: SyzkallerTargetIdentity
    policies: tuple[JobPolicy, ...] = Field(min_length=1)
    #: Fallback Q1 authorities when the bound HCAP pins none.
    judge_versions: JudgeVersions
    vmlinux_artifact_name: str = "kernel"
    instrumentation_artifact_name: str = "instrumentation"
    sealer_id: str = "stage1-host"
    worker_id: str = "stage1-worker"
    lease_duration_s: float = Field(default=120, gt=0)
    agent_workers: int = Field(default=2, ge=1, le=16)
    engine: EngineConfig
    #: The Proxy binary of the promoted semantic build, for the Mutation Rule
    #: Compiler (08 §12).  Unset, a Stage 2 rule set waits in
    #: blocked_operator(stage2_compiler_unavailable).
    nfs_proxy: Path | None = None
    stage2: Stage2Config | None = None

    @classmethod
    def load(cls, path: Path) -> Stage1Config:
        return cls.model_validate_json(Path(path).read_bytes())
