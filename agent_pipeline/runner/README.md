# Durable Runner orchestration

`DurableRunner` implements the Controller's `Runner` task protocol with a
SQLite queue. It stores canonical task input, lifecycle and cancellation
facts, exclusive lease attempts, and a canonical completion receipt before it
acknowledges each transition. `RunnerWorker` only adapts an injected backend;
the queue and worker do not boot VMs, collect evidence or emit Q1/Q2 verdicts.
The optional process supervisor can run a trusted host command; an execution
engine must connect it to VM/capture infrastructure.

The Controller's `task_id` is the unique stage execution identifier because
the current `RunnerInput` has no separate stage field. A completion receipt
binds that task id to its job, harness artifact, execution harness, accepted
lease generation, and final bundle or unsealed reason.

## Lease expiry and cancellation (09 §8)

`RunnerWorker` renews its lease from a heartbeat thread, every third of the
lease duration by default, while the backend runs. A lease that still expires
(the worker or host died) is never claimed again: the task ends
`ended_unsealed(runner_restart)`, and the Controller decides whether to run
it again under its `runtime_retry` budget.

`cancel()` on a leased task only records the request and answers `running`.
The worker sees it through `stop_requested()`, and its `complete()` settles
the task as `ended_unsealed(cancelled)`. If the worker never completes, lease
expiry settles it the same way. So a final cancel status means the execution
stopped, and the Controller sends the job's next Runner task only then.

A backend that cannot confirm its execution stopped (for example, process
cleanup that could not be proven) raises `ExecutionNotStopped` instead of
returning a result. `EvidenceSealingBackend` passes it through. The worker then
neither completes nor renews: the task ends at lease expiry, after the
backend's own lease deadline. Until cleanup is done, the backend's resource
fence (for `ProcessSupervisor`, the resource lock) refuses the next execution;
repeated refusals spend `runtime_retry` and reach `blocked_operator`.

## Backend fencing requirement

The generation and bearer token in `WorkLease` must also fence the concrete
backend execution. A production backend must propagate both values into its
process/VM ownership record, reject stale heartbeats and writes, and require
the current generation/token before publishing a sealed bundle. It must poll
`LeaseControl.stop_requested()` and stop on cancellation or lost ownership.

SQLite lease expiry prevents an old worker's result from being accepted by
`DurableRunner`, but it cannot terminate a noncooperative process or undo
side effects it performs outside this database. A backend that does not apply
the same fence can briefly overlap with a retry the Controller starts after
expiry and is not safe for production use.

The raw token is a bearer credential. It is retained in SQLite and returned in
`WorkLease`; audit views expose only its SHA-256 digest.

This first slice stores one final bundle reference. Streaming campaign bundles
remain future work.

## Evidence backend boundary

`EvidenceSealingBackend` accepts an injected `ExecutionEngine`. The engine can
return immutable artifact bytes and host facts for the VM instance, lane,
generation and collection interval. It cannot choose the task, job, harness,
sealer identity or a verdict. The adapter derives those identities from the
active `WorkLease`, rejects conflicting guest-reported correlation, checks all
limits before storage, and calls `EvidenceStore.seal` only after preflight.

After sealing, the adapter verifies the stored bytes and persists a canonical
`RunnerEvidenceReceipt` keyed by the manifest digest. The receipt records
capture provenance and artifact inventory; it makes no Q1/Q2 assertion.
Concrete VM lifecycle, KCOV collection, proxy journal capture and campaign
streaming are still outside this package.

A CAS manifest is consumable downstream only when the durable Runner has an
accepted `sealed` completion naming that digest and the receipt store returns
the matching valid `RunnerEvidenceReceipt`. A late lease loss or receipt-store
failure can leave an unreferenced manifest after `EvidenceStore.seal` succeeds.
That manifest is an orphan, not evidence that a Controller or Judge may use.

## Accepted completion to Q1

[`RunnerQ1ReceiptBridge`](Q1_RECEIPTS.md) enforces that consumption rule and
cross-checks explicit host authority against the dispatch/materialization,
candidate target, kernel identity and mapping. Its append-only publication
history produces immutable `ArtifactQ1Judge` snapshots for Controller retries
and replay. It does not infer host authority from guest bytes.

## Host process supervision

[`ProcessSupervisor`](PROCESS_SUPERVISOR.md) provides lease-aware Linux command
execution with bounded output, timeouts, renewal and cancellation. Its guardian
holds a shared resource lock through descendant cleanup. After an uncertain
crash, dirty ownership state refuses replacement without signalling old PIDs.
This is a host process primitive; the execution engine must select the actual
resource identity and account for VM or external effects outside the process tree.
