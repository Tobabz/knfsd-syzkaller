"""Interfaces of the deterministic components and outside systems the
Controller calls. Artifact-backed HCAP, Q1 and Materializer implementations
live in hcap, sealed_q1 and materializer. Durable execution services remain a
separate Runner boundary.

The machine calls HcapChecker, Materializer and Q1Judge inside a transition,
so each must be a pure function of its arguments (09 rationale 1): replaying
a job calls them again and must get the same answer.
"""

from __future__ import annotations

from typing import Protocol

from .contracts import (CampaignSegment, CompileRejected, CompiledRuleSet,
                        GateRun, HarnessBinding, HcapCheck, JudgeVersions,
                        GapRef, ReplayOutcome,
                        MaterializationHcapAuthority, MaterializeRejected,
                        Materialized, Q1Result, Sanitizer)


class HcapChecker(Protocol):
    def check_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        """04 §1.1: capabilities exist, usable_by has agent_stage1, the plan
        names this hcap_revision."""

    def revalidate_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        """Check a stored plan against a newly selected HCAP catalog.

        The plan keeps the revision under which the Agent produced it; all
        capability, status, scope and interface declarations are checked
        against ``hcap_revision``.
        """

    def judge_versions(self, hcap_revision: str) -> JudgeVersions | None:
        """Return the Q1 authorities pinned by this HCAP, when present."""

    def knows_capability(self, hcap_revision: str,
                         missing_capability_id: str) -> bool:
        """Is the id in this revision's controlled vocabulary (07 §3)?"""


class Materializer(Protocol):
    def materialize(self, plan_ref: str, binding: HarnessBinding, *,
                    hcap_authority: MaterializationHcapAuthority | None = None
                    ) -> Materialized | MaterializeRejected:
        """05 §11.  Omitted authority requires an exact plan revision."""

    def harness_authority_current(self, harness_ref: str,
                                  binding: HarnessBinding) -> bool:
        """Would `binding`'s HCAP revision give this harness the same
        call admission profile and neutral control catalog refs?  False
        for any record or approval problem; OSError propagates."""


class Q1Judge(Protocol):
    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        """Does trusted host provenance bind the bundle to this Runner task?

        The Controller calls this before first consuming a bundle. Checking
        only a bundle against its own receipt cannot prevent cross-task reuse.
        This lookup, like judge(), must remain reproducible during replay.
        Raise if host provenance is not available yet, so the Controller can
        retry without committing a mismatch that would later change meaning.
        """

    def judge(self, bundle_ref: str, plan_ref: str, candidate_id: str,
              versions: JudgeVersions) -> Q1Result:
        """06 §8-§10 over one sealed bundle (01 §11.1)."""

    def has_required_evidence(self, bundle_ref: str,
                              versions: JudgeVersions) -> bool:
        """Can `versions` judge this bundle without running again
        (01 §11.2)?"""


class MutationRuleCompiler(Protocol):
    def compile(self, rule_set_ref: str, harness_ref: str,
                binding: HarnessBinding) -> CompiledRuleSet | CompileRejected:
        """08 §12, 03-nfs-proxy/04 §19: validate the MutationRuleSet against
        the ProtocolSchema and the promoted semantic registry of
        ``binding.hcap_revision``, bind its traffic scope to the harness's
        Stage 1 route and lower it.  Pure, like the other components: the
        Controller calls it again on replay.  It infers nothing from prose
        and computes no live offset, original bytes or ordinal."""


class Stage2Judge(Protocol):
    """The Controller-side judges of Stage 2 execution evidence (01 §11.1):
    Q1 and M1 for the gate, Q2 and M1 for a campaign segment, the replay
    comparator.  Each reads one sealed bundle and is a pure function of
    its arguments, like the other components; the Controller calls it
    again on replay."""

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        """Does trusted host provenance bind the bundle to this Runner
        task?  As Q1Judge.matches_execution: raise while provenance is not
        available yet."""

    def judge_gate(self, bundle_ref: str, *, plan_ref: str,
                   candidate_id: str, compiled: CompiledRuleSet,
                   versions: JudgeVersions) -> GateRun:
        """01 §3: Q1 of the scenario run with the rule set installed, rule
        and intent M1, and the ambient control flags."""

    def judge_campaign(self, bundle_ref: str, *, candidate_id: str,
                       compiled: CompiledRuleSet) -> CampaignSegment:
        """01 §8.2 Q2 of the segment, M1 over its CrashContextWindow and
        the reached-generation hypothesis counts (01 §3, §12)."""

    def judge_replay(self, bundle_ref: str, *, crash_bundle_ref: str,
                     compiled: CompiledRuleSet) -> ReplayOutcome:
        """03-nfs-proxy/05 §29 over the replay of the crash bundle's
        CrashContextWindow with the recorded rule set."""


class HarnessRegistry(Protocol):
    def lookup(self, kernel_commit: str, sanitizer: Sanitizer
               ) -> HarnessBinding | None:
        """The validated harness build and its hcap_revision (01 §11.2)."""


class IssueTracker(Protocol):
    def open_or_link(self, gap: GapRef, job_id: str) -> str:
        """Create the HarnessGapIssue for `gap`, or link the job to the open
        one with the same key (07 §2, §3).  Returns its reference."""


class InMemoryRegistry:
    def __init__(self) -> None:
        self.bindings: dict[tuple[str, Sanitizer], HarnessBinding] = {}

    def put(self, binding: HarnessBinding) -> None:
        self.bindings[(binding.kernel_commit, binding.sanitizer)] = binding

    def remove(self, kernel_commit: str, sanitizer: Sanitizer) -> None:
        self.bindings.pop((kernel_commit, sanitizer), None)

    def lookup(self, kernel_commit: str, sanitizer: Sanitizer
               ) -> HarnessBinding | None:
        return self.bindings.get((kernel_commit, sanitizer))


class InMemoryIssues:
    """One issue per gap key (07 §3)."""

    def __init__(self) -> None:
        self.issues: dict[GapRef, str] = {}       # the open issue per gap
        self.links: dict[GapRef, list[str]] = {}
        self.opened = 0

    def open_or_link(self, gap: GapRef, job_id: str) -> str:
        if gap not in self.issues:
            self.opened += 1
            self.issues[gap] = f"gap-{self.opened}"
            self.links[gap] = []
        if job_id not in self.links[gap]:
            self.links[gap].append(job_id)
        return self.issues[gap]

    def resolve(self, gap: GapRef) -> None:
        """Close the gap's issue; the gap next time opens a new one."""
        self.issues.pop(gap)
        self.links.pop(gap)
