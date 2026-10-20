"""What a sealed Stage 2 bundle holds, and the host facts that come with it.

One Runner task of a Stage 2 step seals one or more bundles (09 §4, §8):
a gate one per repetition, a campaign one per fuzz VM instance span, a
replay one.  Every bundle carries a ``stage2-host`` artifact the engine
writes from host knowledge (the command's own report and what the engine
did itself, such as the replay plan and compatibility gate).  Its values
are host authority, like the capture's VM instance and lane; the guest
cannot write them.  Everything else is evidence the judges check.

Artifact identities and types, by step:

gate
    ``reachability`` and ``coverage*``  the Stage 1 Q1 observation of the
                                        scenario run with the rules installed
    ``neutral-coverage``                the neutral run's published PCs
                                        (``NEUTRAL_COVERAGE_TYPE``), for the
                                        ambient flag only
    ``execprog.scenario``,              syz-execprog output of each run; its
    ``execprog.neutral``                ``nfs proxy barrier`` lines place the
                                        program generations
    ``journal/<segment>``               the lane's host journal segments
campaign
    ``q2-evidence``, console, reports   ``sealed_q2`` evidence
    ``crash-log``                       syz-manager's crash log, when a VM
                                        crashed (its last executing programs)
    ``generation-coverage/<lane>.<g>``  published PCs per program generation
    ``journal/<segment>``               the VM's host journal segments
replay
    ``execprog.replay``                 syz-execprog output of the window
    ``journal/<segment>``               the separate replay journal
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..journal_sink import SEGMENT_SUFFIX
from ..q2 import ConsoleLogCompleteness, Q2CollectionWindow, VmTermination
from ..semantic_delta import SealedJournal
from ..semantic_replay import InvalidReason, Termination

HOST_FACTS_ID = "stage2-host"
HOST_FACTS_TYPE = "application/vnd.knfsd.stage2-host+json"
JOURNAL_PREFIX = "journal/"
JOURNAL_TYPE = "application/vnd.knfsd.nfsp-journal-segment"
EXECPROG_TYPE = "text/vnd.knfsd.execprog-output"
SCENARIO_EXECPROG_ID = "execprog.scenario"
NEUTRAL_EXECPROG_ID = "execprog.neutral"
REPLAY_EXECPROG_ID = "execprog.replay"
#: A PublishedCoverage of the neutral run.  Not COVERAGE_TYPE: the Q1
#: judge requires every coverage artifact of that type in the observation.
NEUTRAL_COVERAGE_ID = "neutral-coverage"
NEUTRAL_COVERAGE_TYPE = "application/vnd.knfsd.remote-kcov-neutral+json"
GENERATION_COVERAGE_PREFIX = "generation-coverage/"
GENERATION_COVERAGE_TYPE = "application/vnd.knfsd.remote-kcov-generation+json"
CRASH_LOG_ID = "crash-log"
CRASH_LOG_TYPE = "text/vnd.knfsd.syz-crash-log"

JournalName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")]


class _Record(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", strict=True,
                              revalidate_instances="always")


def journal_identity(segment_name: str) -> str:
    return JOURNAL_PREFIX + segment_name


def is_journal_segment(name: str, journal_name: str) -> bool:
    stem = name.removesuffix(SEGMENT_SUFFIX)
    head, _, number = stem.rpartition(".")
    return name.endswith(SEGMENT_SUFFIX) and head == journal_name and \
        len(number) == 4 and number.isdigit()


class GateHostFacts(_Record):
    """What the gate command reports for one repetition."""

    journal_name: JournalName


class CampaignHostFacts(_Record):
    """What the campaign command reports for one fuzz VM instance span.

    The Q2 fields are the host collector's (01 §8.2): it captured the
    console and listed every syz-manager report, saw how the VM ended and
    stamped the collection window.  ``executions`` is syz-manager's count
    of programs run in the span."""

    journal_name: JournalName
    executions: int = Field(ge=0)
    console_log_identity: str | None
    console_log_completeness: ConsoleLogCompleteness
    manager_crash_report_identities: tuple[str, ...] = ()
    vm_termination: VmTermination
    collection_window: Q2CollectionWindow


class ReplayHostFacts(_Record):
    """What the replay command reports: how the replay VM ended."""

    journal_name: JournalName
    replay_end: Termination
    fixture_failed: bool = False


class Compatibility(_Record):
    """``nfs-proxy --check-rules`` on the recorded rule set (05 §39)."""

    ok: bool
    reason: InvalidReason | None = None
    line: str = Field(max_length=512)


class Stage2HostFacts(_Record):
    """The sealed ``stage2-host`` artifact: one of the step reports above,
    and for a replay what the engine established before it ran: the
    production side's end and the compatibility gate, or why no replay
    could be planned (then nothing ran)."""

    schema_version: Literal["stage2-host-facts.v1"] = "stage2-host-facts.v1"
    step: Literal["gate", "campaign", "replay"]
    gate: GateHostFacts | None = None
    campaign: CampaignHostFacts | None = None
    replay: ReplayHostFacts | None = None
    production_end: Termination | None = None
    compatibility: Compatibility | None = None
    plan_error: str | None = Field(default=None, max_length=512)

    @model_validator(mode="after")
    def _one_report(self) -> Stage2HostFacts:
        reports = {"gate": self.gate, "campaign": self.campaign,
                   "replay": self.replay}
        for step, report in reports.items():
            if step != self.step and report is not None:
                raise ValueError(f"{step} report on a {self.step} bundle")
        if self.step != "replay":
            if reports[self.step] is None:
                raise ValueError(f"{self.step} bundle without its report")
            if self.production_end or self.compatibility or self.plan_error:
                raise ValueError("replay facts on a non-replay bundle")
        elif self.plan_error is None:
            if self.replay is None or self.compatibility is None or \
                    self.production_end is None:
                raise ValueError("a planned replay needs its report, "
                                 "production end and compatibility")
        elif self.replay is not None:
            raise ValueError("an unplanned replay ran nothing")
        return self


#: How the collector saw a campaign VM end, as the replay comparator's
#: production side termination (03-nfs-proxy/05 §29).
PRODUCTION_END: dict[str, Termination] = {
    "guest_crashed": Termination.GUEST_CRASH,
    "runner_stopped": Termination.VM_TEARDOWN,
    "lost": Termination.UNKNOWN,
    "unknown": Termination.UNKNOWN,
}


def unpack_journal(bundle, journal_name: str, directory: Path) -> SealedJournal:
    """The sealed journal segments of ``bundle``, opened read only.

    Only ``journal/<name>.NNNN.njnl`` artifacts of ``JOURNAL_TYPE`` are
    written; anything else of that type refuses the bundle."""
    directory.mkdir(parents=True)
    count = 0
    for item in bundle.artifacts:
        if item.descriptor.type != JOURNAL_TYPE:
            continue
        name = item.descriptor.identity.removeprefix("journal/")
        if item.descriptor.identity != journal_identity(name) or \
                not is_journal_segment(name, journal_name):
            raise ValueError(f"unexpected journal artifact {name!r}")
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o644)
        try:
            os.write(fd, item.data)
        finally:
            os.close(fd)
        count += 1
    if not count:
        raise ValueError("the bundle has no journal segments")
    return SealedJournal(directory, journal_name)


def open_journal(bundle, journal_name: str) -> tuple[SealedJournal,
                                                     tempfile.TemporaryDirectory]:
    """``unpack_journal`` into a temporary directory the caller cleans up."""
    tmp = tempfile.TemporaryDirectory(prefix="stage2-journal-")
    try:
        return unpack_journal(bundle, journal_name,
                              Path(tmp.name) / "journal"), tmp
    except BaseException:
        tmp.cleanup()
        raise
