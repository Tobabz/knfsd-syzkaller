"""Interfaces of the deterministic components and outside systems the
Controller calls.  The real HCAP checker, Harness Materializer and Q1 Judge
come with their own PRs; tests use fakes.

The machine calls HcapChecker, Materializer and Q1Judge inside a transition,
so each must be a pure function of its arguments (09 rationale 1): replaying
a job calls them again and must get the same answer.
"""

from __future__ import annotations

from typing import Protocol

from .contracts import (HarnessBinding, HcapCheck, JudgeVersions, GapRef,
                        MaterializeRejected, Materialized, Q1Result, Sanitizer)


class HcapChecker(Protocol):
    def check_plan(self, plan_ref: str, hcap_revision: str) -> HcapCheck:
        """04 §1.1: capabilities exist, usable_by has agent_stage1, the plan
        names this hcap_revision."""

    def knows_capability(self, hcap_revision: str,
                         missing_capability_id: str) -> bool:
        """Is the id in this revision's controlled vocabulary (07 §3)?"""


class Materializer(Protocol):
    def materialize(self, plan_ref: str, binding: HarnessBinding
                    ) -> Materialized | MaterializeRejected:
        """05 §11."""


class Q1Judge(Protocol):
    def judge(self, bundle_ref: str, plan_ref: str, candidate_id: str,
              versions: JudgeVersions) -> Q1Result:
        """06 §8-§10 over one sealed bundle (01 §11.1)."""

    def has_required_evidence(self, bundle_ref: str,
                              versions: JudgeVersions) -> bool:
        """Can `versions` judge this bundle without running again
        (01 §11.2)?"""


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
