# agent_pipeline

The Agent pipeline Stage 1 Controller, its deterministic host components, and
independent M1/Q2 decision kernels. The Controller owns the candidate job:
intake, harness binding, the job state machine, and the record of every
transition.
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
| `admission.py` | exact syzkaller build/call-table identity, closed-world call admission and repository-owned neutral-control authority |
| `materializer.py` | deterministic Harness Materializer core; validates pinned parser output, admission, runtime/fixture selection, seeds and neutral controls before publishing a review manifest |
| `syzkaller/` | pinned Linux/amd64 `prog.Strict` parser and generated call-table exporter over a verified executable snapshot |
| `registry.py` | immutable catalog reader for host-approved harness bindings, HCAP revisions and approval evidence |
| `evidence.py` | seals supplied bytes into a manifest; verifies byte integrity, limits, types and host correlation |
| `q1.py` | pure Q1 decision kernel over verified normalized inputs, a trusted profile/boundary and an external target-PC mapping |
| `sealed_q1.py` | Controller Q1 adapter; loads sealed bytes and binds the plan, target, execution, mapping and complete coverage PC union |
| `m1.py` | pure rule/intent/hypothesis M1 kernel over a verified generation-journal projection; application and delivery remain separate |
| `q2.py` | pure Q2 sanitizer/crash decision kernel and versioned Q2 profile/result contracts |
| `sealed_q2.py` | Controller-side Q2 adapter; binds raw reports and console capture to a trusted host receipt and complete artifact inventory |
| `agent_tasks/analysis.py` | bounded structured `CandidateAnalysis` output contract (03 §5–§10) |
| `agent_tasks/planning.py` | structured planning variants and host-side conversion of bounded inline program text to a content-addressed `ReachabilityPlan` |
| `agent_tasks/tools.py` | the complete Agent tool allowlist: pinned kernel read/search, caller/callee index lookup and pinned HCAP lookup; paths and outputs are bounded |
| `agent_tasks/source_index.py` | immutable Git-object implementation of the source-index protocol; full commit OIDs, trusted roots and process/output/time bounds are enforced |
| `agent_tasks/runtime.py` | injectable structured-output runtime protocol; task policy selects provider/model and output-repair allowance |
| `agent_tasks/pydantic_ai_runtime.py` | optional PydanticAI driver with typed output, the pinned toolbox, bounded requests and output repairs, and response-derived model identity |
| `agent_tasks/executor.py` | `AgentExecutor` adapter for Candidate Analysis and Reachability Planning; records the runtime's actual `provider:model` id through existing Controller callbacks |
| `runner/` | restart-safe SQLite leases/completion, evidence sealing, accepted-receipt Q1 publication and lease-aware Linux process supervision |
| `journal_framing.py` | bounded M5 journal frame recovery and canonical ACK codec; persistence and event admission remain separate |
| `semantic_delta.py` | M6 semantic Delta reader: opens a sealed host journal read only, re-admits every frame with the sink's rules, reports torn tails, refuses corruption, and projects one generation for the replay comparator |
| `semantic_replay.py` | pure M6 replay comparator: per-position batch-signature multisets, JudgeProfile(Replay) v1 refusal classes, refusal-evidence completeness and the 05 §29 verdict order |
| `replay_runner.py` | M6/S1c Runner side: CrashContextWindow from a syz-manager crash log, join to the production journal, recorded rule set and `--check-rules` gate, replay inputs for `syz-execprog`, judge input |
| `controller/machine.py` | the state machine: `handle(job, event)`, no I/O |
| `controller/store.py` | SQLite: one transaction per transition |
| `controller/service.py` | events in, tasks out after commit; `poll()` and `recover()` send a failed or unanswered call again (each failure is recorded per job in `effect_failures`, and the other jobs go on); `replay()` |
| `controller/tasks.py` | the Runner and Agent executor task contracts (09 §8) |
| `stage1/` | the wired service: Controller + `QueuedAgentExecutor` + durable Runner worker + host-command execution engine + Q1 authority publication, and its CLI. See [`stage1/README.md`](stage1/README.md) |

## Using the artifact-backed components

These are injectable library components. `stage1/` assembles them into a
runnable Stage 1 service.
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

`ArtifactHarnessMaterializer` repeats that declarative HCAP check at its own
trust boundary, then requires exact build, call-table, admission and neutral
catalog identities. Both proposed programs and repository seeds pass the same
strict parser and call-admission path. The injected
`syzkaller.PinnedSyzParser` verifies the exact `SyzkallerTargetIdentity`, build
artifacts and generated target call table before parsing through syzkaller's
`prog.Strict`. Build its bundle with the procedure in
[`tools/syzkaller/README.md`](../tools/syzkaller/README.md). The host must approve
the expected identity independently; a bundle's own identity file is not
approval evidence.

The parser derives profile acquisitions from exact typed
`syz_open_nfs_lane_profile` variants and fd origins from unmodified direct
references to those results. Closing or potentially rebinding descriptors
invalidates the corresponding provenance. Legacy lane calls, derived fd/path
provenance and runtime availability are outside this extraction scope.
Unverified constraints remain refusals; parsing or building does not promote
an experimental HCAP capability to validated status.

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

The durable Runner stores task input and lease generations in SQLite. Its
evidence backend derives job/task/harness correlation from the active lease,
accepts only bounded bytes and limited host facts from an injected execution
engine, seals through `EvidenceStore`, verifies the result, and persists a
canonical `RunnerEvidenceReceipt`. A CAS manifest is consumable only when the
Runner accepted the same digest as its final `sealed` result and that receipt
is present and valid. A manifest left by late lease loss or receipt failure is
an orphan, not Judge input.

`RunnerQ1ReceiptBridge` checks an accepted completion and sealing receipt against
the trusted dispatch, candidate, kernel identity and target mapping. It records
immutable publication history and builds an `ArtifactQ1Judge` snapshot. Missing
authority defers publication so the Controller can retry without recording a
transient verdict. See [`Q1_RECEIPTS.md`](runner/Q1_RECEIPTS.md).

`ProcessSupervisor` executes a trusted host command with bounded output, runtime,
lease renewal and cancellation. A Linux guardian retains the resource lock until
its owned process tree is reaped; uncertain restart state blocks replacement.
This primitive must still be wired into a concrete execution engine with a
consistent resource identity. See [`PROCESS_SUPERVISOR.md`](runner/PROCESS_SUPERVISOR.md).

The standalone M1 kernel consumes a host-verified projection of a generation
journal. It treats a durable `EXPOSURE_INTENT` as application evidence,
requires both barriers plus a clean terminal summary for `NOT_APPLIED`, and
keeps forwarding completion as a separate delivery result. A sealed-evidence
adapter and the M5 journal producer are still required before this kernel can
judge production runs.
`journal_framing` fixes the versioned frame header and ACK shape, detects complete
corrupt frames, and reports an incomplete final append without modifying input.
It does not persist records, validate event semantics or send acknowledgements.

`ArtifactQ2Judge` follows the same split without depending on Stage 2
Controller integration. Its `TrustedQ2Execution` receipt is the authority for
execution correlation, the report inventory, console completeness, VM
termination and collection-window markers. The sealed `SealedQ2Evidence`
index is cross-checked against that receipt; it cannot stamp those facts. The
adapter verifies every console/report byte before the pure `q2.evaluate`
kernel classifies reports under the selected `Q2JudgeProfile`. Missing storage
or a late receipt raises instead of creating a verdict, while malformed,
miscorrelated or hash-invalid present evidence produces
`INCONCLUSIVE(invalid_evidence)`.

Content addressing establishes byte integrity, not provenance. The artifact
root and its provisioning, catalog/profile selection, receipt registry, mapping
approval and transfer from a real Runner all remain trusted host responsibilities.
Do not promote capabilities based on fixture records or this test suite.

## Verification and remaining integration

Tests cover corrupt/missing artifacts, noncanonical records, conflicting
correlation and versions, HCAP scope restrictions, Q1 precedence and loss
policies. Controller integration tests use the real HCAP checker and sealed Q1
adapter, including event replay; they still use fake Agent, Materializer and
Runner execution. `test_stage1_service.py` runs the wired service end to end
with the real Controller, Agent executor, Materializer, durable Runner,
process supervisor, sealing backend and Q1 bridge; only model responses, the
parser and the host command's capture are synthetic. All coverage and
mappings in those tests are synthetic.

Candidate Analysis and Reachability Planning can use the concrete
`PydanticAIRuntime`. The lock pins `pydantic-ai-slim==2.55.0`; the dev group
includes the runtime and OpenAI transport so the default test command checks
them. For a deployment without dev dependencies, install `agent-runtime` for
an injected PydanticAI model, or `agent-openai` for the default OpenAI Responses
driver:

```sh
uv sync --locked --no-dev --extra agent-openai
```

Construct `PydanticAIRuntime()` and pass it to `Stage1AgentExecutor`. The host
supplies credentials through the OpenAI SDK's configuration. The default
driver disables SDK retries and server-side response storage; output repairs
are bounded by the task policy, while Controller task retries remain separate.
Each run has its own Agent and tool bindings. Tests use PydanticAI models and
an HTTP mock without sending live provider requests. Importing the base
`agent_tasks` package does not require this optional driver. See
[`PYDANTIC_AI_RUNTIME.md`](agent_tasks/PYDANTIC_AI_RUNTIME.md) for factory,
deadline and response-identity requirements.

`stage1/host/` has the VM lane collector, the host record generator and
target-PC mapping for a real run, tested without a guest; its runbook is
[`stage1/host/README.md`](stage1/host/README.md). The HCAP and judge data
it generates from the template are operator statements, not approved
production data.

Also not here yet: broader NFS resource-provenance extraction,
Runner-receipt integration for Q2 and Stage 2 Controller/Runner
integration. The standalone M1 and Q2 gates use synthetic fixtures only; no
VM/LLM run or end-to-end runtime validation is claimed. `JobPolicy.run_stage2`
remains false-only. The nfs-proxy semantic runtime remains a separate component
until its Runner and durable journal paths are wired.
