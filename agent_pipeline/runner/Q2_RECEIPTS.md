# Runner → Q2 receipt publication

`q2_receipts.RunnerQ2ReceiptBridge` publishes explicit host authority for a
sealed completion accepted by `DurableRunner`. It produces an immutable
`ArtifactQ2Judge` registry snapshot and records the digests of the accepted
completion and sealing receipt. The existing Q2 Judge issues the verdict.

```python
from agent_pipeline.runner.q2_receipts import RunnerQ2ReceiptBridge

bridge = RunnerQ2ReceiptBridge(
    "runner-q2.sqlite", runner=runner, receipts=sealing_receipts,
    artifacts=artifacts, evidence=evidence,
)
execution = bridge.publish(host_context)  # independently supplied Q2HostContext
judge = bridge.snapshot()
result = judge.judge(execution.bundle_ref, q2_profile_ref)
lineage = bridge.publication(execution.bundle_ref)
```

## Prerequisites and host inputs

This standalone bridge uses the existing `DurableRunner.receipt`,
`RunnerEvidenceReceiptStore.get`, `EvidenceStore.verify`, `TrustedQ2Execution`
and `ArtifactQ2Judge` APIs. No Stage 2 dispatch/controller, live VM collector,
M5 schema/admission, or shared Runner protocol changes are required. The
Runner's task ID identifies the execution; its current input has no stage tag.
The caller must select an actual Q2 task from trusted dispatch records.

`Q2HostContext` requires independent host facts:

| Field | Source and validation |
| --- | --- |
| `binding` | The `TaskBinding` used for this dispatch: task, job, harness artifact and execution harness. It must equal the accepted completion and sealing receipt binding. A later job binding cannot replace it. |
| `lease_generation` | Accepted Runner lease generation, also checked against the sealing receipt. It is distinct from the correlation's coverage/generation ID. |
| `correlation` | Host execution position: task, job, execution harness, VM instance, lane and generation ID. It must match the binding, sealing receipt and verified manifest. |
| `collection` | Host collector identity and capture interval, exactly matching the sealing receipt and manifest. Completion must not predate sealing. |
| `artifacts` | Complete host inventory of `ReceiptInventory` entries, including ancillary artifacts, sorted uniquely by identity. Identity, type, digest, size and reported correlation must match the sealing receipt and verified manifest. All artifact bytes are verified. |
| `console_log_identity`, `manager_crash_report_identities` | Collector-assigned console and report roles. Typed console/report entries must exactly match these identities. Reports retain host collection order; that order need not match sorted inventory order. |
| `console_log_completeness`, `vm_termination`, `collection_window` | Explicit host observations of console capture, termination and window markers. These are never inferred from guest payloads, collection timestamps, the existence of a sealed bundle, or a Runner completion. |

The host context and databases are trust inputs. Byte hashing, model
construction and canonical serialization do not authenticate the caller,
prove that collection occurred, or establish runtime build identity. The
bridge does not validate a future Stage 2 plan, manufacture host facts, or
implement collection. A sealing receipt alone, including a valid receipt from
a lost lease, is insufficient: the matching sealed result must first be
accepted by the durable Runner.

## Guest evidence and Q2 decisions

Publication does not parse `SealedQ2Evidence`. An otherwise authorized capture
can have a malformed, missing, noncanonical, or wrongly correlated Q2 index.
The Judge receives the host receipt and classifies those guest evidence errors
as `INCONCLUSIVE(invalid_evidence)`. Guest completeness, termination, report
lists and window claims cannot replace the host values. A missing index must
be reflected in the actual complete host inventory; it is not missing host
authority. The existing capture contract still requires at least one artifact.

Publication accepts open, absent, and end-only host window markers. Existing
Q2 precedence remains unchanged: a classified report with start-only or no
markers is `OBSERVED`; an end-only window is
`INCONCLUSIVE(invalid_evidence)`, even with a classified report. Without a
report, an open or absent window is inconclusive. Publication similarly does
not require a complete console or a successful termination.

## History, restart and bounds

The publication database uses SQLite WAL/FULL transactions. Its API only
inserts history. Both bundle and task identities are unique; identical
publication is idempotent, while changed context, report order, receipt lineage
or bundle binding is rejected. Retries revalidate the real source receipts and
bytes before comparing the retained publication.

`publication()` and `snapshot()` use only retained history; they need no live
Runner, sealing receipt database, collector, or CAS reads, including after
restart. A Judge later needs the retained CAS/profile to assess evidence.
Each snapshot uses one SQLite SELECT and a detached immutable registry. Later
publications and caller mutations cannot change an earlier snapshot.

Host/publication records are limited to 1 MiB, history snapshots to 4,096
executions and 16 MiB of serialized publication records. Host inventory has at
most 256 entries. All history read paths, including idempotent publication,
bound row bodies in SQL before allocation/decoding; metadata columns are also
bounded. Casting bodies to BLOB before truncation keeps the limit in bytes
even if damaged storage contains TEXT. Snapshot iteration bounds both record
count and aggregate bytes. Supplied `EvidenceStore` and CAS limits apply to
the evidence. A limit failure retains all existing history.

Canonical bytes, hashes, row keys and execution/context projection are checked
on reads. Retain the publication database alongside the corresponding Runner
history, receipt database and CAS. Replacing/deleting history or coherently
rewriting it and its hashes as a trusted database writer cannot be detected
cryptographically; the bridge provides no signature or external rollback log.

## Errors and retry

- Missing accepted completion or sealing receipt raises `Q2AuthorityPending`,
  a subclass of `UnknownQ2Execution`. Retain the old snapshot and retry later.
- Artifact I/O failures, including absent bytes, raise `Q2EvidenceUnavailable`.
  A direct `OSError` wrapped by the receipt store is also availability failure.
- Wrapped SQLite `BUSY`, `LOCKED`, `IOERR`, `FULL`, `NOMEM` and `CANTOPEN` codes
  are availability failures. Extended codes use their primary low byte. Only
  the direct cause and its actual `sqlite_errorcode` are examined; no message
  matching or recursive cause traversal is used. `CORRUPT`, `NOTADB`, unknown
  codes and `ProgrammingError` are not converted to availability errors.
- Direct Runner/history SQLite failures propagate as database errors. Other
  receipt-store errors retain that API's `RunnerEvidenceReceiptError` type.
- Stable authority conflicts, malformed host context, damaged history and
  invalid manifest/artifact bytes raise validation/integrity errors. They do
  not create authority or a verdict. Once authority is published, the existing
  Judge retains its own transient-I/O versus `invalid_evidence` distinction.

No failure path overwrites a publication or manufactures a successful Q2
result. Fix stable conflicts at their source; retry unavailable storage without
recording a semantic verdict.

The owned tests use bounded synthetic captures with the actual Runner,
EvidenceSealingBackend, receipt store, EvidenceStore and Q2 Judge. They cover
orphan/stale/wrong-task rejection, forged guest indexes, host inventory and
metadata conflicts, window precedence, storage faults, actual SQLite lock
contention, corrupted and oversized history, concurrent publication, restart,
idempotence and detached snapshots. They do not establish VM collection,
Stage 2 orchestration, M5 integration or production execution readiness.

Direct imports from `agent_pipeline.runner.q2_receipts` are sufficient; no
package-level exports are required.
