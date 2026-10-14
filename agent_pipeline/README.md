# agent_pipeline

The Agent pipeline Controller, Stage 1. It owns the candidate job: intake,
harness binding, the job state machine, and the record of every transition.
The design is [09-job-state-graph.md](../docs/design/02-llm-agent/09-job-state-graph.md).
Its contracts come from `docs/design/02-llm-agent/01`–`07`.

```sh
uv sync --locked
uv run pytest -W error   # Controller, intake, and artifact-backed components
```

| Module | What |
|---|---|
| `contracts.py` | Pydantic forms of the data contracts (candidate, JobPolicy, binding, Q1Result, Agent output variants) |
| `intake.py` | candidate intake validation (02 §3) over git plumbing. `Controller.register()` stores a candidate once per target; `start_job()` starts another job for it (e.g. another sanitizer) |
| `components.py` | interfaces of the HCAP checker, Materializer, Q1 Judge, harness registry, issue tracker |
| `artifacts.py` | bounded SHA-256 storage; verifies reads and existing objects, publishes without replacing objects |
| `data.py` | canonical typed JSON records; rejects duplicate keys, non-finite numbers and noncanonical stored bytes |
| `hcap.py` | versioned HCAP/ReachabilityPlan schemas, capability/status/scope checks and pinned dependency verification |
| `registry.py` | immutable catalog reader for host-approved harness bindings, HCAP revisions and approval evidence |
| `evidence.py` | seals supplied bytes into a manifest; verifies byte integrity, limits, types and host correlation |
| `q1.py` | pure Q1 decision kernel over verified normalized inputs, a trusted profile/boundary and an external target-PC mapping |
| `sealed_q1.py` | Controller Q1 adapter; loads sealed bytes and binds the plan, target, execution, mapping and complete coverage PC union |
| `controller/machine.py` | the state machine: `handle(job, event)`, no I/O |
| `controller/store.py` | SQLite: one transaction per transition |
| `controller/service.py` | events in, tasks out after commit; `poll()` and `recover()` send a failed or unanswered call again (each failure is recorded per job in `effect_failures`, and the other jobs go on); `replay()` |
| `controller/tasks.py` | the Runner and Agent executor task contracts (09 §8) |

## Using the artifact-backed components

These are injectable library components, not a runnable pipeline service.
Persist typed records with `data.put_record(store, record)` and retain the
returned digest; `load_record` checks the stored bytes against both that
digest and the requested schema. The catalog digest is its HCAP revision.
It is not a self-referential field inside the catalog.

The host selects an approved `HarnessCatalog` digest for
`ArtifactHarnessRegistry`. Each registration pins a binding, its HCAP catalog
and nonempty approval-evidence references. The registry checks their integrity;
it does not establish that the evidence proves a runtime validation claim.
`ArtifactHcapChecker` checks a plan against the selected HCAP revision, including
exact scope labels and explicit acknowledgement of unvalidated uses. It does
not parse syz programs or decide call admission.

The Runner-facing `EvidenceStore.seal` accepts already collected bytes and
host-derived correlation/collection metadata. It publishes the manifest last.
`verify` requires an independently trusted `expected_correlation`; deriving it
from the manifest being verified would defeat the check. Payloads are opaque
at this storage boundary, so each consumer must validate its typed payloads.

`ArtifactQ1Judge` takes an immutable snapshot of `TrustedQ1Execution` receipts
keyed by bundle digest. A trusted host integration must supply the executed
plan, intake-accepted candidate, full execution identity projection, generation
correlation, trace mode and externally verified mapping reference. Never build
these receipts from guest claims. Create a new adapter snapshot when receipts
are added, without replacing or removing historical receipts needed for replay.
Before consuming a Runner
result, the Controller calls `matches_execution` with its job and pending task;
a valid bundle from another job or an earlier task is not usable for this run.
Custom Q1 adapters must implement this check as well as `judge` and
`has_required_evidence`. `JudgeVersions` contains the CAS digests of the host-selected
`Q1AdmissibilityProfile` and `RemoteKcovSupportBoundary`.

The bundle contains one `reachability` observation with type
`application/vnd.knfsd.reachability+json` and, for a published aggregate,
`PublishedCoverage` payloads with type `application/vnd.knfsd.remote-kcov+json`.
Every coverage payload must be referenced, match the trusted generation and
contribute to the observation's PC union. Guest target-hit booleans are ignored.
Unknown receipts raise `UnknownExecution`; invalid evidence for a known receipt
returns `INCONCLUSIVE(evidence)`. Missing mapping is not a target miss.
When a host receipt has not arrived, the Controller preserves the pending task
and records an effect failure; a later poll can consume that same task after
the receipt arrives, without committing a transient mismatch into replay.
`assess` returns the full deterministic `Q1Decision` for the caller to persist;
`judge` returns the Controller's smaller `Q1Result`. Neither method writes
artifacts or queries a VM during a Controller transition.

Content addressing establishes byte integrity, not provenance. The artifact
root and its provisioning, catalog/profile selection, receipt registry, mapping
approval and transfer from a real Runner all remain trusted host responsibilities.
Do not promote capabilities based on fixture records or this test suite.

## Verification and remaining integration

Tests cover corrupt/missing artifacts, noncanonical records, conflicting
correlation and versions, HCAP scope restrictions, Q1 precedence and loss
policies. Controller integration tests use the real HCAP checker and sealed Q1
adapter, including event replay; they still use fake Agent, Materializer and
Runner execution. All coverage and mappings in those tests are synthetic.

Not here yet: Agent Tasks (PydanticAI, decision record decision 2), the real
Harness Materializer (pinned syz parsing, call admission and neutral-control
selection), a persistent Runner/executor service, raw KCOV/counter collection
and normalization, automatic DWARF/runtime-PC mapping, approved production HCAP
and judge data, and Stage 2. No VM/LLM run or end-to-end runtime validation is
claimed; `JobPolicy.run_stage2` remains false-only. The nfs-proxy implementation
and its M3 work are independent of these components.
