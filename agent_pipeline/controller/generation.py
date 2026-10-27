"""Harness Generation of a gap key (09 §3.2, 07 §5).

A generation belongs to a gap key and a build key (kernel commit and
sanitizer), not to a job: every job that waits on the key takes its result
(09 §3.2).  It runs a Harness Generation Agent Task, then a Runner
validation of the Agent's patch set, until a validation passes (a staged
binding), the Agent answers infeasible, the budget is spent, or the Agent
or the validation fails past its limit.

The reducer functions are pure; GenerationDriver commits each step in the
store, then sends what the step names (an Agent request, a validation
submit), as the job service does (09 §8).  A job hears of the end through
its own GenerationEnded event.
"""

from __future__ import annotations

import enum
from typing import Annotated, Callable, Literal, Protocol, Union

from pydantic import Field, TypeAdapter

from ..contracts import (AgentModelPolicy, GapRef, HarnessBinding, Record,
                         Sanitizer, Sha256, VulnerabilityCandidate)


class GenerationState(str, enum.Enum):
    GENERATING = "generating"           # an Agent attempt runs
    VALIDATING = "validating"           # its patch set is validated
    PASSED = "passed"
    INFEASIBLE = "infeasible"
    EXHAUSTED = "exhausted"
    FAILED = "failed"


ACTIVE = frozenset({GenerationState.GENERATING, GenerationState.VALIDATING})


# ---------------------------------------------------------------- outputs


class ExtensionOutput(Record):
    """The Agent wrote a patch set; the Runner's validation decides."""

    variant: Literal["extension"] = "extension"
    patch_set_ref: Sha256


class InfeasibleOutput(Record):
    variant: Literal["infeasible"] = "infeasible"
    reason: str = Field(min_length=1, max_length=2000)


GenerationOutput = Annotated[Union[ExtensionOutput, InfeasibleOutput],
                             Field(discriminator="variant")]
GENERATION_OUTPUT = TypeAdapter(GenerationOutput)


# ---------------------------------------------------------------- records


class GenerationAttempt(Record):
    """One generation attempt: an Agent task, then the validation of its
    patch set.  ``agent_try`` is the Agent execution of the task now
    current (a restart or a retried failure is a new try);
    ``validation_try`` numbers the validation Runner tasks, 0 before
    the first."""

    number: int = Field(ge=1)
    agent_task_id: str
    agent_try: int = 1
    agent_failures: int = 0
    #: The current try was handed to the generator.
    sent: bool = False
    patch_set_ref: str | None = None
    validation_try: int = 0
    rejection: str | None = None
    evidence_ref: str | None = None

    @property
    def validation_task_id(self) -> str | None:
        if not self.validation_try:
            return None
        return f"{self.agent_task_id}.v{self.validation_try}"


class HarnessGeneration(Record):
    """09 §3.2.  ``base_binding`` is the registry's binding for the build
    key when the generation started (None: no build for the commit).  The
    limits are the starting job's policy, fixed for the generation."""

    generation_id: str
    gap: GapRef
    kernel_commit: str
    sanitizer: Sanitizer
    base_binding: HarnessBinding | None
    origin_job: str
    candidate: VulnerabilityCandidate
    analysis_ref: str | None = None
    proposal_ref: str | None = None
    model_policy: AgentModelPolicy
    budget: int = Field(ge=1)
    agent_retry_limit: int = Field(ge=1)
    runtime_retry_limit: int = Field(ge=1)
    state: GenerationState = GenerationState.GENERATING
    attempts: tuple[GenerationAttempt, ...]
    staged_binding: HarnessBinding | None = None
    reason: str | None = None
    seq: int = 0

    @property
    def current(self) -> GenerationAttempt:
        return self.attempts[-1]


class GenerationTransition(Record):
    """Append-only, like a job's (09 §8)."""

    generation_id: str
    seq: int
    from_state: GenerationState | None
    to_state: GenerationState
    event: dict
    at: str
    generation: HarnessGeneration


class PriorAttempt(Record):
    patch_set_ref: str
    rejection: str
    evidence_ref: str | None = None


class GenerationRequest(Record):
    """What the Harness Generation Agent Task receives (09 §3.2).
    Artifacts are passed by digest."""

    generation_id: str
    task_id: str
    attempt: int
    gap: GapRef
    model_policy: AgentModelPolicy
    candidate: VulnerabilityCandidate
    analysis_ref: str | None = None
    proposal_ref: str | None = None
    base_binding: HarnessBinding | None = None
    previous: tuple[PriorAttempt, ...] = ()


class ValidationInput(Record):
    """One validation Runner task (07 §5.2): the patch set, rebuilt on the
    build key's base."""

    generation_id: str
    gap: GapRef
    kernel_commit: str
    sanitizer: Sanitizer
    base_binding: HarnessBinding | None
    patch_set_ref: str


class ValidationStatus(Record):
    """status(task_id) of a validation task.  ``passed`` names the staged
    binding; ``rejected`` the typed reason and its sealed bundle;
    ``inconclusive`` an infrastructure end that is run again."""

    state: Literal["unknown", "running", "passed", "rejected",
                   "inconclusive"]
    binding: HarnessBinding | None = None
    reason: str | None = None
    evidence_ref: str | None = None


class HarnessGenerator(Protocol):
    def start(self, request: GenerationRequest) -> None:
        """Run the Agent task; its result comes back through the
        Controller's on_generation_result / on_generation_failure."""


class HarnessValidator(Protocol):
    def submit(self, task_id: str,
               task_input: ValidationInput) -> ValidationStatus:
        """Record task_id durably, then start.  Idempotent for task_id."""

    def status(self, task_id: str) -> ValidationStatus: ...


def generation_of(task_id: str) -> str:
    return task_id.rsplit(".a", 1)[0]


# ---------------------------------------------------------------- reducer


def _with_current(g: HarnessGeneration, **update) -> HarnessGeneration:
    return g.model_copy(update={"attempts": g.attempts[:-1] + (
        g.current.model_copy(update=update),)})


def on_output(g: HarnessGeneration, task_id: str, attempt: int,
              output) -> HarnessGeneration | None:
    """The Agent's answer.  Only the current try counts."""
    a = g.current
    if g.state is not GenerationState.GENERATING or \
            a.agent_task_id != task_id or a.agent_try != attempt:
        return None
    if output.variant == "infeasible":
        return g.model_copy(update={"state": GenerationState.INFEASIBLE,
                                    "reason": output.reason})
    return _with_current(g, patch_set_ref=output.patch_set_ref,
                         validation_try=1).model_copy(
        update={"state": GenerationState.VALIDATING})


def on_failure(g: HarnessGeneration, task_id: str, attempt: int,
               failure: str) -> HarnessGeneration | None:
    """An Agent failure: the same task again, up to agent_retry_limit."""
    a = g.current
    if g.state is not GenerationState.GENERATING or \
            a.agent_task_id != task_id or a.agent_try != attempt:
        return None
    if a.agent_failures >= g.agent_retry_limit:
        return g.model_copy(update={"state": GenerationState.FAILED,
                                    "reason": f"agent_failure:{failure}"})
    return _with_current(g, agent_failures=a.agent_failures + 1,
                         agent_try=a.agent_try + 1, sent=False)


def restart(g: HarnessGeneration) -> HarnessGeneration | None:
    """Whether the generator took the current try is unknown (a failed
    start, a restarted Controller): send a new try.  A late answer of the
    old one is not taken.  Not an Agent failure."""
    if g.state is not GenerationState.GENERATING:
        return None
    return _with_current(g, agent_try=g.current.agent_try + 1, sent=False)


def mark_sent(g: HarnessGeneration) -> HarnessGeneration:
    return _with_current(g, sent=True)


def on_validation(g: HarnessGeneration, task_id: str,
                  st: ValidationStatus) -> HarnessGeneration | None:
    """A final validation status (09 §3.2 table)."""
    a = g.current
    if g.state is not GenerationState.VALIDATING or \
            a.validation_task_id != task_id or \
            st.state in ("unknown", "running"):
        return None
    if st.state == "passed":
        if st.binding is None or st.binding.kernel_commit != \
                g.kernel_commit or st.binding.sanitizer is not g.sanitizer:
            return g.model_copy(update={
                "state": GenerationState.FAILED,
                "reason": "validation_binding_mismatch"})
        return g.model_copy(update={"state": GenerationState.PASSED,
                                    "staged_binding": st.binding})
    if st.state == "inconclusive":
        if a.validation_try - 1 >= g.runtime_retry_limit:
            return g.model_copy(update={
                "state": GenerationState.FAILED,
                "reason": f"runtime_retry_exhausted:{st.reason or ''}"})
        return _with_current(g, validation_try=a.validation_try + 1)
    g = _with_current(g, rejection=st.reason or "rejected",
                      evidence_ref=st.evidence_ref)
    if a.number >= g.budget:
        return g.model_copy(update={"state": GenerationState.EXHAUSTED,
                                    "reason": "generation_exhausted"})
    n = a.number + 1
    return g.model_copy(update={
        "state": GenerationState.GENERATING,
        "attempts": g.attempts + (GenerationAttempt(
            number=n, agent_task_id=f"{g.generation_id}.a{n}"),)})


# ---------------------------------------------------------------- driver


class GenerationDriver:
    """Commits generation steps and sends their tasks.  ``on_end`` is
    called with a generation that has ended, after its commit."""

    def __init__(self, store, generator: HarnessGenerator,
                 validator: HarnessValidator, *,
                 clock: Callable[[], str],
                 on_end: Callable[[HarnessGeneration], None]) -> None:
        self.store = store
        self.generator = generator
        self.validator = validator
        self.clock = clock
        self.on_end = on_end

    def create(self, g: HarnessGeneration,
               after: str | None) -> HarnessGeneration:
        """Store `g` unless the key's latest generation is no longer
        `after`; returns the key's latest generation either way."""
        return self.store.create_generation(g, GenerationTransition(
            generation_id=g.generation_id, seq=g.seq, from_state=None,
            to_state=g.state, event={"type": "started"}, at=self.clock(),
            generation=g), after)

    def on_result(self, task_id: str, attempt: int, output) -> None:
        self._step(generation_of(task_id), lambda g: on_output(
            g, task_id, attempt, output), {
                "type": "agent_succeeded", "task_id": task_id,
                "attempt": attempt, "output": output.model_dump(mode="json")})

    def on_failure(self, task_id: str, attempt: int, failure: str) -> None:
        self._step(generation_of(task_id), lambda g: on_failure(
            g, task_id, attempt, failure), {
                "type": "agent_failed", "task_id": task_id,
                "attempt": attempt, "failure": failure})

    def dispatch(self, generation_id: str) -> None:
        """Send what the generation waits for.  Idempotent: an Agent try is
        sent once; a validation submit is idempotent by task_id."""
        g = self.store.generation(generation_id)
        if g.state is GenerationState.GENERATING and not g.current.sent:
            self.generator.start(self._request(g))
            self._step(generation_id, lambda x: mark_sent(x) if
                       x.state is GenerationState.GENERATING and
                       x.current.agent_try == g.current.agent_try and
                       x.current.number == g.current.number and
                       not x.current.sent else None,
                       {"type": "agent_sent",
                        "task_id": g.current.agent_task_id,
                        "attempt": g.current.agent_try}, send=False)
        elif g.state is GenerationState.VALIDATING:
            task_id = g.current.validation_task_id
            self._take(generation_id, task_id, self.validator.submit(
                task_id, self._validation_input(g)))

    def poll(self, generation_id: str) -> None:
        """A try the generator may not have (a failed start) is sent again
        as a new try; a validation task is asked for its status."""
        g = self.store.generation(generation_id)
        if g.state is GenerationState.GENERATING and not g.current.sent:
            self._step(generation_id, restart, {"type": "agent_restarted"})
        elif g.state is GenerationState.VALIDATING:
            task_id = g.current.validation_task_id
            st = self.validator.status(task_id)
            if st.state == "unknown":
                self.dispatch(generation_id)
            else:
                self._take(generation_id, task_id, st)

    def recover(self, generation_id: str) -> None:
        """09 §8: an Agent task of a previous Controller is sent again as a
        new try; a validation task is re-attached by task_id."""
        g = self.store.generation(generation_id)
        if g.state is GenerationState.GENERATING:
            self._step(generation_id, restart, {"type": "agent_restarted"})
        elif g.state is GenerationState.VALIDATING:
            self.dispatch(generation_id)

    # ------------------------------------------------------------ internals

    def _take(self, generation_id: str, task_id: str,
              st: ValidationStatus) -> None:
        self._step(generation_id, lambda g: on_validation(g, task_id, st), {
            "type": "validation_finished", "task_id": task_id,
            "status": st.model_dump(mode="json")})

    def _step(self, generation_id: str, reduce, event: dict, *,
              send: bool = True) -> None:
        g = self.store.generation(generation_id)
        new = reduce(g)
        if new is None:
            return
        new = new.model_copy(update={"seq": g.seq + 1})
        self.store.commit_generation(g.seq, new, GenerationTransition(
            generation_id=generation_id, seq=new.seq, from_state=g.state,
            to_state=new.state, event=event, at=self.clock(),
            generation=new))
        if new.state not in ACTIVE:
            self.on_end(new)
        elif send:
            self.dispatch(generation_id)

    @staticmethod
    def _request(g: HarnessGeneration) -> GenerationRequest:
        a = g.current
        return GenerationRequest(
            generation_id=g.generation_id, task_id=a.agent_task_id,
            attempt=a.agent_try, gap=g.gap, model_policy=g.model_policy,
            candidate=g.candidate, analysis_ref=g.analysis_ref,
            proposal_ref=g.proposal_ref, base_binding=g.base_binding,
            previous=tuple(PriorAttempt(patch_set_ref=p.patch_set_ref,
                                        rejection=p.rejection,
                                        evidence_ref=p.evidence_ref)
                           for p in g.attempts[:-1]
                           if p.patch_set_ref and p.rejection))

    @staticmethod
    def _validation_input(g: HarnessGeneration) -> ValidationInput:
        return ValidationInput(
            generation_id=g.generation_id, gap=g.gap,
            kernel_commit=g.kernel_commit, sanitizer=g.sanitizer,
            base_binding=g.base_binding,
            patch_set_ref=g.current.patch_set_ref)
