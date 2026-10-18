"""Q1 host authority for the wired Stage 1 service.

After a Runner task seals, the service publishes its Q1 authority through
``RunnerQ1ReceiptBridge`` and installs a new Judge snapshot.  Every field of
the published ``Q1HostContext`` comes from host records: the Controller
transition that dispatched the task, the Runner's accepted completion, the
sealing receipt, the execution harness descriptor and an operator-registered
verified target mapping.  Nothing is read from guest evidence.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..artifacts import ArtifactStore, validate_digest
from ..contracts import JudgeVersions, Q1Result, VulnerabilityCandidate
from ..controller.records import Job, TaskKind
from ..controller.store import Store
from ..data import load_record, put_record
from ..materializer import ExecutionHarnessDescriptor, ReachabilityHarness
from ..q1 import CandidateTarget, ExecutionCorrelation, KernelIdentity, TargetPcMapping
from ..runner.evidence_backend import RunnerEvidenceReceiptStore
from ..runner.q1_receipts import (Q1AuthorityPending, Q1HostContext,
                                  Q1ReceiptRejected, RunnerQ1ReceiptBridge)
from ..runner.service import DurableRunner
from ..sealed_q1 import ArtifactQ1Judge


class PublishedQ1Judge:
    """``components.Q1Judge`` over the latest installed bridge snapshot.

    Publications are append-only and immutable, so a newer snapshot never
    changes the answer for a bundle an older one knew.  An unknown bundle
    still raises, which leaves the Controller transition uncommitted until
    its authority is published.
    """

    def __init__(self, snapshot: ArtifactQ1Judge) -> None:
        self.snapshot = snapshot

    def install(self, snapshot: ArtifactQ1Judge) -> None:
        self.snapshot = snapshot

    def matches_execution(self, bundle_ref: str, *, job_id: str,
                          task_id: str) -> bool:
        return self.snapshot.matches_execution(bundle_ref, job_id=job_id,
                                               task_id=task_id)

    def judge(self, bundle_ref: str, plan_ref: str, candidate_id: str,
              versions: JudgeVersions) -> Q1Result:
        return self.snapshot.judge(bundle_ref, plan_ref, candidate_id, versions)

    def has_required_evidence(self, bundle_ref: str,
                              versions: JudgeVersions) -> bool:
        return self.snapshot.has_required_evidence(bundle_ref, versions)


def candidate_target(candidate: VulnerabilityCandidate) -> CandidateTarget:
    return CandidateTarget(candidate_id=candidate.candidate_id,
                           kernel_commit=candidate.kernel_commit,
                           **candidate.location.model_dump(mode="json"))


@dataclass(frozen=True)
class DescriptorKernelIdentity:
    """Mapping identity derived from the approved descriptor alone.

    This slice supports only guests booted with ``nokaslr``: the relocation
    is then zero by construction and needs no runtime measurement.  Any
    other command line returns ``None`` (publication stays pending).
    """

    vmlinux_artifact_name: str
    instrumentation_artifact_name: str

    def identity(self, descriptor: ExecutionHarnessDescriptor,
                 execution_harness_id: str) -> KernelIdentity | None:
        if "nokaslr" not in descriptor.guest_kernel_command_line.split():
            return None
        builds = {a.name: a.artifact_ref for a in descriptor.build_artifacts}
        vmlinux = builds.get(self.vmlinux_artifact_name)
        instrumentation = builds.get(self.instrumentation_artifact_name)
        if vmlinux is None or instrumentation is None:
            return None
        return KernelIdentity(
            execution_harness_id=execution_harness_id,
            kernel_commit=descriptor.kernel_commit,
            instrumentation_sha256=instrumentation, vmlinux_sha256=vmlinux,
            kaslr_enabled=False, kaslr_offset=0)


class MappingCatalog:
    """Operator-registered verified target mappings.

    ``add`` stores a ``TargetPcMapping`` in the CAS and records its digest
    as an empty file under ``index_dir``.  Registering a mapping is a host
    trust decision: the operator vouches that ``target_pcs`` were derived
    from this exact vmlinux for this exact target.
    """

    def __init__(self, artifacts: ArtifactStore, index_dir: Path) -> None:
        self.artifacts = artifacts
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)

    def add(self, mapping: TargetPcMapping) -> str:
        mapping = TargetPcMapping.model_validate(mapping)
        if not mapping.verified:
            raise ValueError("only a verified mapping can be registered")
        ref = put_record(self.artifacts, mapping)
        path = self.index_dir / ref
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o644)
        os.fsync(fd)
        os.close(fd)
        return ref

    def refs(self) -> tuple[str, ...]:
        found = []
        for entry in sorted(os.listdir(self.index_dir)):
            try:
                found.append(validate_digest(entry))
            except ValueError:
                continue
        return tuple(found)

    def lookup(self, target: CandidateTarget,
               identity: KernelIdentity) -> str | None:
        """The first verified mapping for exactly this target and build."""
        for ref in self.refs():
            try:
                mapping = load_record(self.artifacts, ref, TargetPcMapping)
            except (OSError, ValueError):
                continue
            if mapping.verified and mapping.target == target and \
                    mapping.identity == identity:
                return ref
        return None


@dataclass(frozen=True)
class Publication:
    job_id: str
    task_id: str
    outcome: str        # published | pending | rejected
    detail: str = ""


class Q1AuthorityPublisher:
    """Publish Q1 authority for every sealed, pending Stage 1 Runner task."""

    def __init__(self, store: Store, runner: DurableRunner,
                 receipts: RunnerEvidenceReceiptStore,
                 bridge: RunnerQ1ReceiptBridge, artifacts: ArtifactStore,
                 identities: DescriptorKernelIdentity,
                 mappings: MappingCatalog, judge: PublishedQ1Judge) -> None:
        self.store = store
        self.runner = runner
        self.receipts = receipts
        self.bridge = bridge
        self.artifacts = artifacts
        self.identities = identities
        self.mappings = mappings
        self.judge = judge

    def publish_ready(self) -> list[Publication]:
        results = []
        published = False
        for job in list(self.store.jobs()):
            p = job.pending_task
            if p is None or p.kind is not TaskKind.RUNNER or \
                    p.runner_input is not None:
                continue            # Stage 2 has its own authority
            completion = self.runner.receipt(p.task_id)
            if completion is None or completion.final_state != "sealed":
                continue
            try:
                self.bridge.publication(completion.bundle_ref)
                continue                    # already published
            except KeyError:
                pass
            try:
                context = self.context(job, p.task_id)
                self.bridge.publish(context)
            except Q1AuthorityPending as exc:
                results.append(Publication(job.job_id, p.task_id, "pending",
                                           str(exc)))
            except (Q1ReceiptRejected, ValueError, OSError) as exc:
                results.append(Publication(job.job_id, p.task_id, "rejected",
                                           f"{type(exc).__name__}: {exc}"))
            else:
                published = True
                results.append(Publication(job.job_id, p.task_id, "published"))
        if published:
            self.judge.install(self.bridge.snapshot())
        return results

    def _dispatch_snapshot(self, job_id: str, task_id: str) -> Job:
        """The job as stored by the transition that minted this task.

        The bridge requires the records used for this dispatch, not a
        possibly newer current binding.
        """
        for t in self.store.transitions(job_id):
            p = t.job.pending_task
            if p is not None and p.kind is TaskKind.RUNNER and \
                    p.task_id == task_id:
                return t.job
        raise Q1ReceiptRejected(f"no dispatch transition for {task_id}")

    def context(self, job: Job, task_id: str) -> Q1HostContext:
        dispatched = self._dispatch_snapshot(job.job_id, task_id)
        harness = dispatched.harness
        binding = dispatched.binding
        if harness is None or binding is None or \
                dispatched.candidate is None or dispatched.plan_ref is None:
            raise Q1ReceiptRejected(f"incomplete dispatch record for {task_id}")
        completion = self.runner.receipt(task_id)
        if completion is None or completion.bundle_ref is None:
            raise Q1AuthorityPending("Runner has not sealed this task")
        try:
            receipt = self.receipts.get(completion.bundle_ref)
        except KeyError as exc:
            raise Q1AuthorityPending("sealing receipt is not available") from exc
        descriptor = load_record(self.artifacts, binding.execution_harness_id,
                                 ExecutionHarnessDescriptor)
        identity = self.identities.identity(descriptor,
                                            binding.execution_harness_id)
        if identity is None:
            raise Q1AuthorityPending(
                "no host kernel identity: the descriptor must boot with "
                "nokaslr and name the vmlinux and instrumentation artifacts")
        mapping_ref = self.mappings.lookup(candidate_target(dispatched.candidate), identity)
        if mapping_ref is None:
            raise Q1AuthorityPending("no verified target mapping is registered")
        record = load_record(self.artifacts, harness.harness_ref,
                             ReachabilityHarness)
        return Q1HostContext(
            candidate=dispatched.candidate, plan_ref=dispatched.plan_ref,
            binding=binding, materialized=harness,
            lease_generation=completion.generation, identity=identity,
            correlation=ExecutionCorrelation.model_validate(
                receipt.correlation.model_dump()),
            trace_mode=record.runtime_selection.trace_mode,
            mapping_ref=mapping_ref,
            vmlinux_artifact_name=self.identities.vmlinux_artifact_name,
            instrumentation_artifact_name=(
                self.identities.instrumentation_artifact_name))
