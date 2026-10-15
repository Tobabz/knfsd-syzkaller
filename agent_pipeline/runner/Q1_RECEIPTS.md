# Runner → Q1 receipt integration

`q1_receipts.RunnerQ1ReceiptBridge` connects a completion accepted by the real
`DurableRunner` to an immutable `ArtifactQ1Judge` authority snapshot. The bridge
does not issue a verdict. The Judge reads sealed observation/coverage bytes and
evaluates them using the selected Q1 profile and support boundary.

```python
bridge = RunnerQ1ReceiptBridge(
    "runner-q1.sqlite", runner=runner, receipts=sealing_receipts,
    artifacts=artifacts, evidence=evidence,
)
execution = bridge.publish(host_context)  # Q1HostContext, from the trusted host
judge = bridge.snapshot()                # install in the next Controller Env
lineage = bridge.publication(execution.bundle_ref)
```

`Q1HostContext` requires these independently trusted inputs:

| Input | Source and checks |
| --- | --- |
| `candidate` | Intake-accepted Controller candidate; exact ID, commit and resolved target must match the plan and executed build. |
| `plan_ref`, `binding`, `materialized` | The records used for this task's dispatch. Harness, review, plan, descriptor, parsed program identities, HCAP binding and runtime selection are cross-checked. A current job binding may belong to a later dispatch and must not replace these records. |
| `lease_generation`, `correlation` | Host lease and execution position. Task/job/harness, lease generation, VM, lane and coverage generation must match the accepted completion and sealing receipt. Lease generation and coverage generation are distinct. |
| `identity`, `trace_mode` | Boot/build identity, measured runtime relocation, and trace configuration verified by the host execution engine. Trace configuration must match the materialized plan. |
| `vmlinux_artifact_name`, `instrumentation_artifact_name` | Distinct descriptor artifact names identifying the mapping-relevant build digests. Names are explicit because the existing descriptor contract does not prescribe them. |
| `mapping_ref` | Independently validated mapper output for this exact candidate and kernel identity. `None`, absent bytes or `verified=False` defer publication. A verified empty mapping remains judgeable as an inconclusive mapping result. |

The caller must obtain these inputs from trusted Controller/host/mapper records.
Constructing `Q1HostContext`, hashing guest JSON, or storing it in the CAS does
not authenticate its claims. The bridge cannot prove boot identity, perform
intake, verify DWARF mappings, or identify the writer of a host database. It never
derives authoritative fields from guest observations or manifest claims.

`publish` reads `runner.receipt(task_id)` and requires a sealed final result.
It then loads the corresponding `RunnerEvidenceReceiptStore` entry, checks every
task/input/job/harness/lease/bundle binding, verifies the sealed manifest and all
artifact bytes, and compares the complete inventory and collection/sealing
metadata. An orphaned backend receipt is insufficient. An expired lease ends the
task unsealed, so its sealed result is never published. Runner and sealer
timestamps come from different clocks and are not compared; ordering comes from
Runner acceptance under the lease generation.

Publication uses a SQLite FULL/WAL transaction and stores the validated context,
`TrustedQ1Execution`, and digests of both source receipts. Publication is
idempotent for identical records. A task or bundle cannot be assigned another
context, mapping or identity, including after restart. Caller changes to the
source context and later publications do not mutate an earlier Judge snapshot.
The history database is append-only through this API and must be retained with
the Controller history and CAS; replacing it with an empty or unrelated database
discards authority needed for replay. Snapshots contain all retained entries.

Host records are bounded to 1 MiB. Each history/snapshot accepts at most 4,096
executions and 16 MiB of publication records. Reaching a limit raises without
discarding entries. Provision a separate history for a separate Controller
history; do not prune consumed receipts to make space. Evidence uses the supplied
`EvidenceStore` limits. Ordinary CAS limits still apply.

When completion, a sealing receipt, or a referenced host artifact has not arrived,
`publish` raises `Q1AuthorityPending`, a subclass of `UnknownExecution`. I/O
failures also propagate. No publication or verdict is manufactured. Keep the old
snapshot, retry publication when authority arrives, and install a newly obtained
snapshot. The existing Controller leaves a Runner-finished transition uncommitted
when its Judge lacks authority; a later snapshot allows retry. Stable mismatches,
tampering and publication conflicts raise validation errors and must be repaired
at their source, never converted into a successful receipt.

Only successful publication belongs in the Judge registry. Guest payload errors
remain the Judge's responsibility: a guest success boolean cannot produce a hit,
and malformed or inconsistent observation bytes produce an evidence failure.

Tests use real intake, Materializer, DurableRunner, EvidenceSealingBackend,
ArtifactQ1Judge and Controller replay with synthetic source/parser/capture/mapping
fixtures. They do not claim VM execution, real KCOV collection, live model calls,
Q2 or Stage 2 validation. Existing Runner and Controller protocols are unchanged.
