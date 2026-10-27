"""Promotion criteria for capabilities (#100, 07 §5.3, 04 §3.3).

A capability reaches the shared HCAP only when it is general, not fitted to
the candidate it was made for.  The same criteria judge a capability a
person wrote and one Harness Generation produced:

* its ``CapabilityContract`` declares the entry points and the public kernel
  functions they reach, and a capability that fills a gap declares the
  vocabulary's contract for that gap (``gap_contract_refusals``);
* the promotion probes are the contract's boundary functions, fixed by the
  Controller; whoever made the capability cannot choose them;
* ``PromotionProbeEvidence`` shows the probes reached by minimal programs
  built from the contract and by distinct syzkaller-generated programs that
  call an entry point, and missed by a neutral control, none of them a
  program the Controller withheld (the candidate's);
* the entry points' syz call arguments carry no literal the contract does
  not fix (``argument_generality_refusals``), a static check on the pinned
  target's argument shapes.

Regression and the trigger rule (07 §5.2, 04 §3.2) are separate gates.
A promoted semantic mutation subset (Stage 2) is judged by the M7 gate
instead (``semantic_promotion.promote``, 07 §5.3 item 7).
"""

from __future__ import annotations

import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from typing_extensions import Self

from .contracts import Sha256
from .data import canonical_json
from .hcap import (Capability, CapabilityContract, ExecutionLayout,
                   HcapCatalog, Identifier)
from .q1 import KernelIdentity

#: Placeholders until the repository owner sets them (#100).
MIN_MINIMAL_RUNS = 3
MIN_MINIMAL_HIT_RATIO = 1.0
MIN_GENERATED_RUNS = 32
MIN_GENERATED_PROGRAMS = 16
MIN_GENERATED_HIT_RATIO = 0.25
MIN_NEUTRAL_RUNS = 3


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def contract_sha256(contract: CapabilityContract) -> str:
    return hashlib.sha256(canonical_json(contract)).hexdigest()


# --- argument generality -------------------------------------------------

class ArgumentLeaf(_Model):
    """One scalar position of a syz call's arguments.

    ``literal`` is true when the pinned description admits a single value
    there (a constant, a one-value range, a one-value string), so every
    program carries the same literal: ``value`` for a number, ``text`` for
    a string.  ``recursive`` marks where a type recurs and the walk stopped;
    what lies below is unknown.  ``types`` names the syzlang struct and
    union types enclosing the position, outermost first.
    """

    path: str = Field(min_length=1)
    literal: bool
    value: int | None = None
    text: str | None = None
    recursive: bool = False
    types: tuple[str, ...] = ()


class CallShape(_Model):
    call: str = Field(min_length=1)
    leaves: tuple[ArgumentLeaf, ...] = ()


class CallShapes(_Model):
    """The pinned target's argument shapes for some calls (the parser
    bridge's ``describe``)."""

    schema_version: Literal["syz-call-shapes.v1"] = "syz-call-shapes.v1"
    syzkaller_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    target: Literal["linux/amd64"] = "linux/amd64"
    calls: tuple[CallShape, ...]

    def get(self, call: str) -> CallShape | None:
        return next((c for c in self.calls if c.call == call), None)


def argument_generality_refusals(contract: CapabilityContract,
                                 shapes: CallShapes) -> list[str]:
    """Literals in the entry points' arguments that the contract does not
    fix, recursions it does not cover with a fixed type, and fixed
    arguments that are no literal (a stale contract)."""
    fixed = {(f.call, f.path): (f.value, f.text)
             for f in contract.fixed_arguments}
    fixed_types = set(contract.fixed_types)
    refusals = []
    used = set()
    for call in contract.syz_calls():
        shape = shapes.get(call)
        if shape is None:
            refusals.append(f"call_shape_missing:{call}")
            continue
        for leaf in shape.leaves:
            # A template type matches by its full or its base name.
            enclosing = {*leaf.types, *(t.split("[", 1)[0] for t in leaf.types)}
            if fixed_types & enclosing:
                continue
            if leaf.recursive:
                refusals.append(f"recursive_argument:{call}:{leaf.path}")
                continue
            if not leaf.literal:
                continue
            if fixed.get((call, leaf.path)) == (leaf.value, leaf.text):
                used.add((call, leaf.path))
                continue
            refusals.append(f"literal_argument:{call}:{leaf.path}")
    for key in sorted(set(fixed) - used):
        if shapes.get(key[0]) is not None:
            refusals.append(f"fixed_argument_not_literal:{key[0]}:{key[1]}")
    return refusals


# --- probe campaign evidence --------------------------------------------

class ProbeRunSet(_Model):
    """Runs of one program kind and the promotion probes they reached."""

    program_sha256s: tuple[Sha256, ...] = Field(min_length=1)
    runs: int = Field(ge=0)
    #: Runs that reached at least one probe.
    runs_hitting: int = Field(ge=0)
    #: Probes some run reached.
    probes_hit: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> Self:
        if len(set(self.program_sha256s)) != len(self.program_sha256s):
            raise ValueError("duplicate program")
        if len(self.program_sha256s) > self.runs:
            raise ValueError("more programs than runs")
        if self.runs_hitting > self.runs:
            raise ValueError("more hitting runs than runs")
        if len(set(self.probes_hit)) != len(self.probes_hit):
            raise ValueError("duplicate probe")
        if bool(self.probes_hit) != bool(self.runs_hitting):
            raise ValueError("probes hit without a hitting run, or the reverse")
        return self

    def ratio(self) -> float:
        return self.runs_hitting / self.runs if self.runs else 0.0


class PromotionProbeEvidence(_Model):
    """A probe campaign that never ran the candidate's program (#100).

    ``minimal`` runs programs built from the contract, ``generated`` runs
    distinct syzkaller-generated and mutated programs that each call an
    entry point, and ``neutral`` runs programs of the same fixture that use
    none.  ``withheld_program_sha256s`` are the programs the Controller kept
    out of the campaign: the candidate's.  A capability that fills a gap
    needs them, since a candidate raised the gap (``promotion_refusals``).
    """

    schema_version: Literal["promotion-probe-evidence.v1"]
    capability_id: Identifier
    contract_sha256: Sha256
    observed_at: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
    execution_harness_id: Sha256
    mapping_identity: KernelIdentity
    guest_lane_script_sha256: Sha256
    layout: ExecutionLayout
    accelerator: Literal["kvm", "tcg"]
    exec_slowdown: int = Field(ge=1)
    #: The Controller's probes: the contract's boundary functions.
    probes: tuple[Identifier, ...] = Field(min_length=1)
    #: Digest of each public probe mapping, keyed by probe name.
    probe_mapping_sha256: dict[str, Sha256]
    minimal: ProbeRunSet
    generated: ProbeRunSet
    neutral: ProbeRunSet
    withheld_program_sha256s: tuple[Sha256, ...] = ()
    #: Generated programs dropped because they called no entry point.
    generated_without_entry_call: int = Field(ge=0)
    crash_signature_count: int = Field(ge=0)
    shareable_result_contains_target_metadata_or_addresses: bool

    @model_validator(mode="after")
    def _campaign(self) -> Self:
        if self.execution_harness_id != self.mapping_identity.execution_harness_id:
            raise ValueError("mapping and campaign harness identities differ")
        probes = set(self.probes)
        if len(probes) != len(self.probes):
            raise ValueError("duplicate probe")
        if set(self.probe_mapping_sha256) != probes:
            raise ValueError("probe mappings differ from the probes")
        for name, runs, ratio in (
                ("minimal", MIN_MINIMAL_RUNS, MIN_MINIMAL_HIT_RATIO),
                ("generated", MIN_GENERATED_RUNS, MIN_GENERATED_HIT_RATIO)):
            run_set = getattr(self, name)
            if run_set.runs < runs:
                raise ValueError(f"fewer than {runs} {name} runs")
            if run_set.ratio() < ratio:
                raise ValueError(f"{name} runs reached the probes in fewer "
                                 f"than {ratio:.0%} of runs")
            if set(run_set.probes_hit) != probes:
                raise ValueError(f"{name} runs missed a probe")
        if len(self.generated.program_sha256s) < MIN_GENERATED_PROGRAMS:
            raise ValueError(f"fewer than {MIN_GENERATED_PROGRAMS} distinct "
                             "generated programs")
        ran = {*self.minimal.program_sha256s, *self.generated.program_sha256s,
               *self.neutral.program_sha256s}
        if ran & set(self.withheld_program_sha256s):
            raise ValueError("the campaign ran a withheld program")
        if self.neutral.runs < MIN_NEUTRAL_RUNS:
            raise ValueError(f"fewer than {MIN_NEUTRAL_RUNS} neutral runs")
        if self.neutral.runs_hitting:
            raise ValueError("a neutral control run reached a probe")
        if self.generated_without_entry_call:
            raise ValueError("generated runs include programs that call no "
                             "entry point")
        if self.crash_signature_count:
            raise ValueError("probe campaign contains a crash")
        if self.shareable_result_contains_target_metadata_or_addresses:
            raise ValueError("shareable campaign evidence contains private "
                             "target data")
        return self


def promotion_refusals(capability: Capability,
                       evidence: list[PromotionProbeEvidence]) -> list[str]:
    """Why ``capability`` cannot be promoted on ``evidence``; empty when
    some evidence promotes it.  The evidence models already enforce the
    campaign thresholds."""
    contract = capability.contract
    if contract is None:
        return ["contract_missing"]
    own = [e for e in evidence if e.capability_id == capability.id]
    if not own:
        return ["promotion_evidence_missing"]
    digest = contract_sha256(contract)
    refusals: list[str] = []
    for item in own:
        problems = []
        if item.contract_sha256 != digest:
            problems.append("promotion_evidence_contract_mismatch")
        if set(item.probes) != set(contract.boundary_functions):
            problems.append("probes_not_contract_boundary")
        if contract.time_dependent and item.accelerator != "kvm":
            problems.append("time_dependent_needs_kvm")
        if capability.fills_gap is not None and \
                not item.withheld_program_sha256s:
            # A gap is raised by a candidate; its program must be named.
            problems.append("candidate_programs_not_withheld")
        if not problems:
            return []
        refusals.extend(p for p in problems if p not in refusals)
    return refusals


def gap_contract_refusals(catalog: HcapCatalog, missing_capability_id: str,
                          capability: Capability) -> list[str]:
    """A capability filling a gap declares the vocabulary's contract for it,
    never one derived from the candidate that raised the gap."""
    gap = next((g for g in catalog.gap_contracts
                if g.missing_capability_id == missing_capability_id), None)
    if gap is None:
        return [f"gap_contract_missing:{missing_capability_id}"]
    if capability.contract != gap.contract:
        return [f"contract_differs_from_gap:{missing_capability_id}"]
    return []
