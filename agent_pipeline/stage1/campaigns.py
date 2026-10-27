"""Promotion probe campaigns (07 §5.3) by one trusted host command.

``CommandCampaigner`` implements the Controller's ``ProbeCampaigner`` over
the validation command machinery (``validation.CommandValidator``): the task
is recorded in SQLite, the command runs in its own session on a thread, a
task left running by an earlier process ends ``inconclusive``.  The command
is host configuration; the campaign it gets is data.

Command contract (``{input}``, ``{output}`` and ``{resource}`` in argv are
replaced by the two directories and the KVM slot's resource key):

``input/campaign.json``
    a ``stage1.host.campaign.CampaignConfig``: the host's Stage 1 config
    and collector, the staged binding, the capability, the candidate
    programs to withhold and the seed.

``output/campaign.json`` (written by the command, exit 0)::

    {"result": "evidence", "reason": "criteria_met",
     "evidence": "evidence.json", ...}
    {"result": "refused", "reason": "criteria_not_met", "detail": "..."}
    {"result": "inconclusive", "reason": "vm_boot_failed", "detail": "..."}

On ``evidence`` the ``PromotionProbeEvidence`` must load, name the task's
capability and binding, list every withheld program and run none of them;
it is stored in the CAS and its digest is the status's ``evidence_ref``.
A nonzero exit, a timeout or a malformed report is ``inconclusive``.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field

from ..contracts import Record
from ..controller.promotion import CampaignInput, CampaignStatus
from ..data import canonical_json, parse_json, put_record
from ..promotion import PromotionProbeEvidence
from ..runner.slots import resource
from .engine import CaptureError, _read_regular, _write
from .validation import (INPUT, MAX_REASON_CHARS, OUTPUT, RESOURCE,
                         CommandValidator, ValidationStore)

MAX_REPORT_BYTES = 64 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_RUNS_BYTES = 16 * 1024 * 1024
_REASON = re.compile(r"^[a-z0-9_.:-]{1,200}$")


class CampaignStore(ValidationStore):
    """Campaign tasks, beside the validations in the same file or not."""

    TABLE = "campaigns"
    INPUT = CampaignInput
    STATUS = CampaignStatus


class _Report(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    result: Literal["evidence", "refused", "inconclusive"]
    reason: str = Field(min_length=1, max_length=MAX_REASON_CHARS)
    detail: str = Field(default="", max_length=4000)
    evidence: str | None = None


class CampaignRecord(Record):
    """The stored record of one campaign task: what the command reported,
    its run log, and the evidence it wrote.  ``record_ref`` of the task's
    status."""

    schema_version: Literal["promotion-campaign.v1"] = \
        "promotion-campaign.v1"
    task_id: str
    promotion_id: str
    capability_id: str
    result: Literal["evidence", "refused", "inconclusive"]
    reason: str
    detail: str = ""
    returncode: int | None = None
    started_at_ns: int
    completed_at_ns: int
    evidence_ref: str | None = None
    runs_ref: str | None = None
    log_ref: str | None = None


@dataclass(frozen=True)
class CommandCampaignerConfig:
    argv: tuple[str, ...]
    cwd: Path
    work_root: Path
    resource_key: str
    #: What ``campaign.json`` names: the host's Stage 1 config file and
    #: collector config (None: the Stage 1 state directory's).
    stage1: Path
    collector: Path | None = None
    env: Mapping[str, str] = field(default_factory=lambda: {"LANG": "C.UTF-8"})
    timeout_s: float = 14_400
    term_grace_s: float = 10.0
    #: CampaignConfig fields the host sets (selection, run counts).
    campaign: Mapping[str, object] = field(default_factory=dict)


class _Inconclusive(Exception):
    pass


class CommandCampaigner(CommandValidator):
    """``ProbeCampaigner`` over one host command per task."""

    KIND = "campaign"

    def _config(self, task_input: CampaignInput) -> bytes:
        from .host.campaign import CampaignConfig
        c = self.config
        return canonical_json(CampaignConfig(
            stage1=c.stage1, collector=c.collector,
            execution_harness_id=task_input.binding.execution_harness_id,
            hcap_revision=task_input.binding.hcap_revision,
            capability_id=task_input.capability_id,
            withheld_program_sha256s=task_input.withheld_program_sha256s,
            seed=task_input.seed, **dict(c.campaign)).model_dump(mode="json"))

    def _validate(self, task_id: str, task_input: CampaignInput,
                  started: int) -> tuple[CampaignStatus, dict]:
        def end(result, reason, *, detail="", rc=None, log=None,
                evidence=None, runs=None, programs=()) -> CampaignStatus:
            record = put_record(self.artifacts, CampaignRecord(
                task_id=task_id, promotion_id=task_input.promotion_id,
                capability_id=task_input.capability_id, result=result,
                reason=reason, detail=detail, returncode=rc,
                started_at_ns=started, completed_at_ns=time.time_ns(),
                evidence_ref=evidence, runs_ref=runs, log_ref=log))
            return CampaignStatus(state=result, reason=reason,
                                  evidence_ref=evidence, record_ref=record,
                                  program_sha256s=tuple(programs))

        run = self.config.work_root / task_id
        inp, out = run / "input", run / "output"
        run.mkdir(parents=True, exist_ok=False)
        inp.mkdir()
        out.mkdir()
        _write(inp / "campaign.json", self._config(task_input))
        log = run / "process.log"
        with resource(self.slots, self.config.resource_key) as key:
            argv = tuple(a.replace(INPUT, str(inp)).replace(OUTPUT, str(out))
                         .replace(RESOURCE, key) for a in self.config.argv)
            ended, rc = self._run(task_id, argv, log)
        log_ref = self._log_tail(log)
        if ended != "completed" or rc != 0:
            reason = f"command_{ended}" if ended != "completed" else \
                f"command_exit_{rc}"
            return end("inconclusive", reason, rc=rc, log=log_ref), {}
        try:
            report = _Report.model_validate(parse_json(
                _read_regular(out, "campaign.json", MAX_REPORT_BYTES)))
            if not _REASON.match(report.reason):
                raise _Inconclusive("untyped reason")
            runs = self._runs(out)
            if report.result != "evidence":
                return end(report.result, report.reason,
                           detail=report.detail, rc=rc, log=log_ref,
                           runs=runs), {}
            evidence, programs = self._evidence(out, report, task_input)
        except (CaptureError, _Inconclusive, ValueError) as exc:
            reason = f"malformed_report:{exc}"[:MAX_REASON_CHARS]
            return end("inconclusive", reason, rc=rc, log=log_ref), {}
        return end("evidence", report.reason, rc=rc, log=log_ref,
                   evidence=evidence, runs=runs, programs=programs), {}

    def _runs(self, out: Path) -> str | None:
        if not (out / "runs.json").is_file():
            return None
        return self.artifacts.put(_read_regular(out, "runs.json",
                                                MAX_RUNS_BYTES))

    def _evidence(self, out: Path, report: _Report,
                  task_input: CampaignInput) -> tuple[str, list[str]]:
        if report.evidence is None:
            raise _Inconclusive("evidence needs its file")
        data = _read_regular(out, report.evidence, MAX_EVIDENCE_BYTES)
        evidence = PromotionProbeEvidence.model_validate_json(data)
        if evidence.capability_id != task_input.capability_id or \
                evidence.execution_harness_id != \
                task_input.binding.execution_harness_id:
            raise _Inconclusive("evidence_binding_mismatch")
        withheld = set(task_input.withheld_program_sha256s)
        if not withheld <= set(evidence.withheld_program_sha256s):
            raise _Inconclusive("evidence_withheld_mismatch")
        # The model refuses evidence that ran a program it withheld.
        programs = sorted(set(evidence.minimal.program_sha256s) |
                          set(evidence.generated.program_sha256s))
        return self.artifacts.put(data), programs
