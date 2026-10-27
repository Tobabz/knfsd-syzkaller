"""Promotion of a staged harness (07 §5.3, 09 §3.2).

A Harness Generation that passed gives its gap key's jobs a staged binding.
Promotion is separate from those jobs and never changes their state: the
Controller fixes the probes (the contract's ``boundary_functions``, inside
the campaign), withholds the candidates' programs, runs a probe campaign
per capability the staged HCAP added or changed for the gap, and keeps the
``PromotionProbeEvidence`` for a person to review.

- ``collecting``: the jobs on the staged binding are planning; their plan
  programs are the candidate programs a campaign must not run.  The
  campaigns start once no live job there is still without a plan and at
  least one program is known.
- ``campaigning``: one campaign Runner task per capability.  An
  ``inconclusive`` one runs again, up to the generation's
  ``runtime_retry_limit``; then the promotion is ``failed``.
- ``review``: every campaign wrote evidence.  ``not_met``: a campaign was
  refused, or a candidate program known later ran in a campaign.  The
  staged binding stays; the jobs go on (07 §5.3).  An operator may run the
  campaigns again (``retry``).
- ``approved``: a person approved the evidence.  The promotion itself is
  the host's (the capabilities and their evidence in the host spec, a new
  harness catalog); ``promoted`` once the registry's binding for the build
  key carries each capability with its campaign evidence.  The gap's issue
  is then resolved, and the registry change moves the jobs (09 §5).
- ``rejected``: a person rejected it.  The jobs leave the staged binding
  (09 §5 binding change) and meet the gap again; the generation then ends
  them ``promotion_rejected`` until an operator retries generation.

The reducers are pure; PromotionDriver commits each step, then sends the
campaign tasks the step names, as GenerationDriver does.
"""

from __future__ import annotations

import enum
from typing import Callable, Literal, Protocol

from pydantic import Field

from ..contracts import GapRef, HarnessBinding, Record, Sanitizer
from .generation import HarnessGeneration


class PromotionState(str, enum.Enum):
    COLLECTING = "collecting"
    CAMPAIGNING = "campaigning"
    REVIEW = "review"
    APPROVED = "approved"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    NOT_MET = "not_met"
    FAILED = "failed"


#: States poll() and recover() look at.
OPEN = frozenset({PromotionState.COLLECTING, PromotionState.CAMPAIGNING,
                  PromotionState.REVIEW, PromotionState.APPROVED})
#: Ends ``on_end`` hears of.
ENDS = frozenset({PromotionState.PROMOTED, PromotionState.REJECTED,
                  PromotionState.NOT_MET, PromotionState.FAILED})


class CampaignInput(Record):
    """One probe campaign Runner task: a capability of the staged binding,
    and the candidate programs it must not run."""

    promotion_id: str
    generation_id: str
    capability_id: str
    binding: HarnessBinding
    withheld_program_sha256s: tuple[str, ...]
    seed: int = 0


class CampaignStatus(Record):
    """status(task_id) of a campaign task.  ``evidence`` names the stored
    ``PromotionProbeEvidence`` and the programs the campaign ran;
    ``refused`` the typed reason; ``inconclusive`` an infrastructure end
    that is run again.  ``record_ref`` is the task's stored record."""

    state: Literal["unknown", "running", "evidence", "refused",
                   "inconclusive"]
    reason: str | None = None
    evidence_ref: str | None = None
    record_ref: str | None = None
    program_sha256s: tuple[str, ...] = ()


class ProbeCampaigner(Protocol):
    def submit(self, task_id: str,
               task_input: CampaignInput) -> CampaignStatus:
        """Record task_id durably, then start.  Idempotent for task_id."""

    def status(self, task_id: str) -> CampaignStatus: ...


class CapabilityCampaign(Record):
    """The campaign of one capability.  ``attempt`` numbers its Runner
    tasks over every round; ``tries`` counts the current round's."""

    capability_id: str
    attempt: int = 1
    tries: int = 1
    result: Literal["evidence", "refused"] | None = None
    reason: str | None = None
    evidence_ref: str | None = None
    record_ref: str | None = None
    program_sha256s: tuple[str, ...] = ()


class PromotionReview(Record):
    decision: Literal["approved", "rejected"]
    decision_id: str = Field(min_length=1, max_length=128)
    note: str = Field(default="", max_length=2000)
    #: The evidence the decision saw.
    evidence_refs: tuple[str, ...] = ()
    at: str


class HarnessPromotion(Record):
    promotion_id: str
    generation_id: str
    gap: GapRef
    kernel_commit: str
    sanitizer: Sanitizer
    base_binding: HarnessBinding | None
    staged_binding: HarnessBinding
    runtime_retry_limit: int = Field(ge=1)
    state: PromotionState = PromotionState.COLLECTING
    capabilities: tuple[CapabilityCampaign, ...] = ()
    #: Every candidate program seen on the staged binding.
    candidate_program_sha256s: tuple[str, ...] = ()
    #: What the current round's campaigns were told to withhold.
    withheld_program_sha256s: tuple[str, ...] = ()
    review: PromotionReview | None = None
    reason: str | None = None
    issue_resolved: bool = False
    seq: int = 0

    def task_id(self, index: int) -> str:
        return f"{self.promotion_id}.c{index}.r" \
            f"{self.capabilities[index].attempt}"

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        return tuple(c.evidence_ref for c in self.capabilities
                     if c.evidence_ref is not None)


class PromotionTransition(Record):
    promotion_id: str
    seq: int
    from_state: PromotionState | None
    to_state: PromotionState
    event: dict
    at: str
    promotion: HarnessPromotion


class PromotionInputs(Protocol):
    """What the Controller reads from the CAS for a promotion."""

    def capabilities(self, g: HarnessGeneration) -> tuple[str, ...]:
        """The capabilities the staged HCAP added or changed that fill the
        generation's gap."""

    def programs(self, plan_ref: str) -> tuple[str, ...]:
        """The program digests of a job's plan."""

    def carries(self, binding: HarnessBinding, capability_id: str,
                evidence_ref: str) -> bool:
        """Does the binding's HCAP have the capability with this
        evidence?"""


def promotion_id_of(generation_id: str) -> str:
    return f"{generation_id}.p"


def new_promotion(g: HarnessGeneration,
                  capability_ids: tuple[str, ...]) -> HarnessPromotion:
    p = HarnessPromotion(
        promotion_id=promotion_id_of(g.generation_id),
        generation_id=g.generation_id, gap=g.gap,
        kernel_commit=g.kernel_commit, sanitizer=g.sanitizer,
        base_binding=g.base_binding, staged_binding=g.staged_binding,
        runtime_retry_limit=g.runtime_retry_limit,
        capabilities=tuple(CapabilityCampaign(capability_id=c)
                           for c in sorted(set(capability_ids))))
    if not p.capabilities:
        return p.model_copy(update={"state": PromotionState.FAILED,
                                    "reason": "no_capability_fills_gap"})
    return p


# ---------------------------------------------------------------- reducer


def _ran(p: HarnessPromotion, programs: set[str]) -> str | None:
    """The first capability whose campaign ran one of `programs`."""
    for c in p.capabilities:
        if programs & set(c.program_sha256s):
            return c.capability_id
    return None


def on_programs(p: HarnessPromotion, programs: set[str],
                waiting: bool) -> HarnessPromotion | None:
    """The candidate programs on the staged binding now, and whether a
    live job there still has no plan."""
    known = set(p.candidate_program_sha256s)
    seen = tuple(sorted(known | programs))
    if p.state is PromotionState.COLLECTING:
        if not waiting and seen:
            return p.model_copy(update={
                "state": PromotionState.CAMPAIGNING,
                "candidate_program_sha256s": seen,
                "withheld_program_sha256s": seen})
        if seen == p.candidate_program_sha256s:
            return None
        return p.model_copy(update={"candidate_program_sha256s": seen})
    if p.state not in OPEN or seen == p.candidate_program_sha256s:
        return None
    p = p.model_copy(update={"candidate_program_sha256s": seen})
    ran = _ran(p, set(seen) - known)
    if ran is not None:
        return p.model_copy(update={
            "state": PromotionState.NOT_MET,
            "reason": f"candidate_program_ran:{ran}"})
    return p


def on_campaign(p: HarnessPromotion, task_id: str,
                st: CampaignStatus) -> HarnessPromotion | None:
    """A final campaign status."""
    if p.state is not PromotionState.CAMPAIGNING or \
            st.state in ("unknown", "running"):
        return None
    index = next((i for i in range(len(p.capabilities))
                  if p.task_id(i) == task_id), None)
    if index is None or p.capabilities[index].result is not None:
        return None
    c = p.capabilities[index]
    if st.state == "inconclusive":
        if c.tries - 1 >= p.runtime_retry_limit:
            return p.model_copy(update={
                "state": PromotionState.FAILED,
                "reason": f"runtime_retry_exhausted:{c.capability_id}:"
                          f"{st.reason or ''}"})
        c = c.model_copy(update={"attempt": c.attempt + 1,
                                 "tries": c.tries + 1})
    else:
        result, reason = st.state, st.reason
        if result == "evidence" and (
                st.evidence_ref is None or
                set(st.program_sha256s) & set(p.candidate_program_sha256s)):
            result, reason = "refused", "candidate_program_ran" \
                if st.evidence_ref else "evidence_missing"
        c = c.model_copy(update={
            "result": result, "reason": reason or result,
            "evidence_ref": st.evidence_ref if result == "evidence"
            else None,
            "record_ref": st.record_ref,
            "program_sha256s": st.program_sha256s})
    caps = p.capabilities[:index] + (c,) + p.capabilities[index + 1:]
    p = p.model_copy(update={"capabilities": caps})
    if any(x.result is None for x in caps):
        return p
    refused = next((x for x in caps if x.result == "refused"), None)
    if refused is not None:
        return p.model_copy(update={
            "state": PromotionState.NOT_MET,
            "reason": f"{refused.capability_id}:{refused.reason}"})
    return p.model_copy(update={"state": PromotionState.REVIEW})


def approve(p: HarnessPromotion, decision_id: str, note: str,
            at: str) -> HarnessPromotion | None:
    if p.state is not PromotionState.REVIEW:
        return None
    return p.model_copy(update={
        "state": PromotionState.APPROVED,
        "review": PromotionReview(decision="approved",
                                  decision_id=decision_id, note=note,
                                  evidence_refs=p.evidence_refs, at=at)})


def reject(p: HarnessPromotion, decision_id: str, note: str,
           at: str) -> HarnessPromotion | None:
    if p.state in (PromotionState.PROMOTED, PromotionState.REJECTED):
        return None
    return p.model_copy(update={
        "state": PromotionState.REJECTED, "reason": "review_rejected",
        "review": PromotionReview(decision="rejected",
                                  decision_id=decision_id, note=note,
                                  evidence_refs=p.evidence_refs, at=at)})


def retry(p: HarnessPromotion) -> HarnessPromotion | None:
    """An operator runs the campaigns again (new tasks, a new seed) after
    they were not met or failed."""
    if p.state not in (PromotionState.NOT_MET, PromotionState.FAILED) or \
            not p.capabilities:
        return None
    caps = tuple(c.model_copy(update={
        "attempt": c.attempt + 1, "tries": 1, "result": None, "reason": None,
        "evidence_ref": None, "record_ref": None, "program_sha256s": ()})
        for c in p.capabilities)
    seen = p.candidate_program_sha256s
    return p.model_copy(update={
        "state": PromotionState.CAMPAIGNING if seen
        else PromotionState.COLLECTING,
        "capabilities": caps, "withheld_program_sha256s": seen,
        "reason": None})


def on_registry(p: HarnessPromotion, carried: bool
                ) -> HarnessPromotion | None:
    if p.state is not PromotionState.APPROVED or not carried:
        return None
    return p.model_copy(update={"state": PromotionState.PROMOTED})


def issue_resolved(p: HarnessPromotion) -> HarnessPromotion | None:
    if p.state is not PromotionState.PROMOTED or p.issue_resolved:
        return None
    return p.model_copy(update={"issue_resolved": True})


# ---------------------------------------------------------------- driver


class PromotionDriver:
    """Commits promotion steps and sends their campaign tasks.  ``on_end``
    is called with a promotion that reached an end, after its commit."""

    def __init__(self, store, campaigner: ProbeCampaigner, *,
                 clock: Callable[[], str],
                 on_end: Callable[[HarnessPromotion], None]) -> None:
        self.store = store
        self.campaigner = campaigner
        self.clock = clock
        self.on_end = on_end

    def create(self, p: HarnessPromotion) -> HarnessPromotion:
        """Store `p` unless its generation has a promotion already; returns
        the stored one."""
        stored = self.store.create_promotion(p, PromotionTransition(
            promotion_id=p.promotion_id, seq=p.seq, from_state=None,
            to_state=p.state, event={"type": "created"}, at=self.clock(),
            promotion=p))
        if stored == p and p.state in ENDS:
            self.on_end(p)
        return stored

    def programs(self, promotion_id: str, programs: set[str],
                 waiting: bool) -> None:
        self.step(promotion_id, lambda p: on_programs(p, programs, waiting),
                  {"type": "programs", "programs": sorted(programs),
                   "waiting": waiting})

    def dispatch(self, promotion_id: str) -> None:
        """Submit each campaign without a result.  Idempotent by task_id."""
        p = self.store.promotion(promotion_id)
        if p.state is not PromotionState.CAMPAIGNING:
            return
        for i, c in enumerate(p.capabilities):
            if c.result is None:
                task_id = p.task_id(i)
                self._take(promotion_id, task_id, self.campaigner.submit(
                    task_id, self._input(p, i)))

    def poll(self, promotion_id: str) -> None:
        p = self.store.promotion(promotion_id)
        if p.state is not PromotionState.CAMPAIGNING:
            return
        for i, c in enumerate(p.capabilities):
            if c.result is None:
                task_id = p.task_id(i)
                st = self.campaigner.status(task_id)
                if st.state == "unknown":
                    self.dispatch(promotion_id)
                    return
                self._take(promotion_id, task_id, st)

    def step(self, promotion_id: str, reduce, event: dict, *,
             send: bool = True) -> bool:
        p = self.store.promotion(promotion_id)
        new = reduce(p)
        if new is None:
            return False
        new = new.model_copy(update={"seq": p.seq + 1})
        self.store.commit_promotion(p.seq, new, PromotionTransition(
            promotion_id=promotion_id, seq=new.seq, from_state=p.state,
            to_state=new.state, event=event, at=self.clock(),
            promotion=new))
        if new.state in ENDS and new.state is not p.state:
            self.on_end(new)
        elif new.state is PromotionState.CAMPAIGNING and send:
            self.dispatch(promotion_id)
        return True

    def _take(self, promotion_id: str, task_id: str,
              st: CampaignStatus) -> None:
        self.step(promotion_id, lambda p: on_campaign(p, task_id, st), {
            "type": "campaign_finished", "task_id": task_id,
            "status": st.model_dump(mode="json")})

    @staticmethod
    def _input(p: HarnessPromotion, index: int) -> CampaignInput:
        c = p.capabilities[index]
        return CampaignInput(
            promotion_id=p.promotion_id, generation_id=p.generation_id,
            capability_id=c.capability_id, binding=p.staged_binding,
            withheld_program_sha256s=p.withheld_program_sha256s,
            seed=c.attempt)


# ---------------------------------------------------------------- inputs


class ArtifactPromotionInputs:
    """PromotionInputs over the CAS."""

    def __init__(self, artifacts) -> None:
        from ..hcap import ArtifactHcapChecker
        self.artifacts = artifacts
        self.hcap = ArtifactHcapChecker(artifacts)

    def capabilities(self, g: HarnessGeneration) -> tuple[str, ...]:
        staged = self.hcap.load_catalog(g.staged_binding.hcap_revision)
        base = {} if g.base_binding is None else {
            c.id: c for c in self.hcap.load_catalog(
                g.base_binding.hcap_revision).capabilities}
        return tuple(sorted(
            c.id for c in staged.capabilities
            if c.fills_gap == g.gap.missing_capability_id and
            base.get(c.id) != c))

    def programs(self, plan_ref: str) -> tuple[str, ...]:
        from ..data import load_record
        from ..hcap import ReachabilityPlan
        plan = load_record(self.artifacts, plan_ref, ReachabilityPlan)
        return (plan.program_proposal.artifact_ref,)

    def carries(self, binding: HarnessBinding, capability_id: str,
                evidence_ref: str) -> bool:
        try:
            catalog = self.hcap.load_catalog(binding.hcap_revision)
        except (OSError, ValueError):
            return False
        return any(c.id == capability_id and evidence_ref in c.evidence_refs
                   for c in catalog.capabilities)
