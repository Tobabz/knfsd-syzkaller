# Durable Runner orchestration

`DurableRunner` implements the Controller's `Runner` task protocol with a
SQLite queue. It stores canonical task input, lifecycle and cancellation
facts, exclusive lease attempts, and a canonical completion receipt before it
acknowledges each transition. `RunnerWorker` only adapts an injected backend;
this package does not boot VMs, run programs, collect or fabricate evidence,
or emit Q1/Q2 verdicts.

The Controller's `task_id` is the unique stage execution identifier because
the current `RunnerInput` has no separate stage field. A completion receipt
binds that task id to its job, harness artifact, execution harness, accepted
lease generation, and final bundle or unsealed reason.

## Backend fencing requirement

The generation and bearer token in `WorkLease` must also fence the concrete
backend execution. A production backend must propagate both values into its
process/VM ownership record, reject stale heartbeats and writes, and require
the current generation/token before publishing a sealed bundle. It must poll
`LeaseControl.stop_requested()` and stop on cancellation or lost ownership.

SQLite expiry and reclaim prevent an old worker's result from being accepted
by `DurableRunner`, but they cannot terminate a noncooperative process or undo
side effects it performs outside this database. A backend that does not apply
the same fence can briefly overlap with a replacement after expiry and is not
safe for production use.

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
Concrete VM lifecycle, KCOV collection, proxy journal capture, backend process
fencing and campaign streaming are still outside this package.

A CAS manifest is consumable downstream only when the durable Runner has an
accepted `sealed` completion naming that digest and the receipt store returns
the matching valid `RunnerEvidenceReceipt`. A late lease loss or receipt-store
failure can leave an unreferenced manifest after `EvidenceStore.seal` succeeds.
That manifest is an orphan, not evidence that a Controller or Judge may use.
