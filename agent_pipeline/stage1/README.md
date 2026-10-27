# Stage 1 service

`agent_pipeline.stage1` wires the existing Stage 1 components into one
process: the Controller and its Store, Agent Tasks on `QueuedAgentExecutor`,
the durable Runner with a worker thread, evidence sealing, and Q1 authority
publication. Nothing here adds a decision rule; every verdict still comes
from `ArtifactQ1Judge` through the Controller state machine.

```
submit ─► Controller ─► QueuedAgentExecutor ─► (worker) Stage1AgentExecutor
             ▲   │            │ deliver()                   │
             │   │            └────────── results ◄─────────┘
             │   └─► DurableRunner ◄── RunnerWorker thread
             │            │               └─► EvidenceSealingBackend
             │            │                     └─► CommandExecutionEngine
             │            │                          └─► host command (VM)
             │            ▼
             └── PublishedQ1Judge ◄── Q1AuthorityPublisher ◄── sealed receipts
```

Each `Stage1Service.step()` delivers finished Agent results on the
Controller thread, publishes Q1 authority for Runner tasks that sealed, and
calls `Controller.poll()`. If a task seals between the publish and the poll,
that poll records one `pending_task` effect failure (no Judge authority yet)
and the next step consumes the verdict.

## Running it

```sh
uv sync --locked --no-dev --extra agent-openai
python -m agent_pipeline.stage1 --config stage1.json add-mapping mapping.json
python -m agent_pipeline.stage1 --config stage1.json submit \
    --commit <kernel commit> --path fs/nfsd/nfs4proc.c --symbol nfsd4_open \
    --policy kasan-default
python -m agent_pipeline.stage1 --config stage1.json run --job <job id>
```

`run` stops when the job reaches `s1_reached`, needs a person
(`s1_approval`, `blocked_operator`, a harness gap) or ends. Answer an
approval with `approve JOB TASK REVIEW_MANIFEST_SHA256 DECISION_ID`, then
`run` again; `replay JOB` re-checks the stored transitions.

`seed JOB --policy kcsan-default` starts a new job for JOB's candidate
under another policy (another sanitizer, #81 R5) from JOB's plan: no
Analysis or Planning, the plan is re-validated against the new binding's
HCAP and materialized, and Q1 must reach again on that harness. Register
the target-PC mapping of the new harness's vmlinux first (`target-pcs`
takes the job's own harness).

Only `run` calls a model. Every other command is one-shot: an Agent Task
it creates (`submit`, `deny`, `operator resume`, a resolved issue) is
recorded with its attempt left `sending`, and `run`, or a `run` already
going in another process, sends it on its next poll. On exit, `run` waits
for a running lease so its completion or cleanup report is stored, and
stores Agent results that finish while it closes.

A job blocked on a harness gap is linked to a local issue (`issues`).
After fixing the gap, record it with `resolve-issue gap-N resolved`
(or `deferred`, `reopened`, `wont_fix`); the change is stored and passed
to the linked jobs by that command and by any running service. A job takes
a change only while its current wait is linked to that issue, and the
Controller Store records the last change each job took in the same
transaction as the transition, so a change delivered twice, by two
processes at once, or after a later one is ignored.

`stage1.json` is a `config.Stage1Config`. Every value is host authority:

| Field | What |
|---|---|
| `state_dir` | SQLite stores (`controller`, `runner`, `receipts`, `q1-publications`, `issues`), `mappings/`, `runs/`, `processes/` |
| `artifact_root` | the CAS holding every record below |
| `kernel_repo` | Git checkout for intake and the Agent's read-only tools |
| `harness_catalog_ref` | `HarnessCatalog` digest (`ArtifactHarnessRegistry`) |
| `execution_harness_approvals` | `ExecutionHarnessApproval` digests |
| `syzkaller_bundle`, `syzkaller_identity` | parser bundle from `tools/syzkaller/build.py` and its host-approved identity |
| `policies` | `JobPolicy` records; model provider and model per Agent Task |
| `judge_versions` | fallback `Q1AdmissibilityProfile` / `RemoteKcovSupportBoundary` digests |
| `vmlinux_artifact_name`, `instrumentation_artifact_name` | descriptor build-artifact names used for the kernel identity |
| `engine` | the host command, its cwd, environment, resource key and timeout |
| `generation` | optional Harness Generation (07 §5): the Agent's sandbox (`repo`, `worktree_root`, `base_ref`, `launcher`, `env`, `allowed_paths`, `workers`) and the `validation` command; see below |

Keep `state_dir` and `artifact_root` together: Controller history, Runner
receipts and Q1 publications are needed for replay.

## Host command contract

`CommandExecutionEngine` runs `engine.argv` once per Runner lease under
`ProcessSupervisor`, with `{input}` and `{output}` replaced by fresh
directories under `state_dir/runs/<task>.g<generation>/`.

`input/` holds `execution.json` (job, task, harness and lease generation),
`harness.json` (`ReachabilityHarness`), `descriptor.json`
(`ExecutionHarnessDescriptor`), `program.syz` and `neutral.syz`.

The command writes `output/capture.json`:

```json
{"vm_instance_id": "vm-1", "lane": 0, "generation_id": 1,
 "artifacts": [
   {"identity": "reachability",
    "type": "application/vnd.knfsd.reachability+json",
    "path": "reachability.json"},
   {"identity": "coverage",
    "type": "application/vnd.knfsd.remote-kcov+json",
    "path": "coverage.json"}]}
```

`reachability.json` is a canonical `q1.RemoteKcovObservation` and each
coverage file a canonical `sealed_q1.PublishedCoverage` for the same
correlation. A run with a kernel crash also lists a `crash-report`
artifact (`application/vnd.knfsd.crash-report+json`, a canonical
`crash.CrashReport`); the crash is not a runtime error, and the Controller
keeps it as a crash finding on the job (see the Q1 section of [`../README.md`](../README.md)). Paths are plain file names
in `output/`. The collection interval is the supervised process's own start
and end; stdout and stderr are kept in `process.log`. A nonzero exit,
timeout or malformed capture ends the task `capture_failed`, which the
Controller treats as a runtime failure, not a verdict.

## Harness Generation

With `generation` set, a job whose policy has a `harness_generation_budget`
goes from a harness gap to `harness_generating` instead of stopping
(`docs/design/02-llm-agent/09-job-state-graph.md` §3.2). `run` runs the
generation Agent on its own workers (`QueuedGenerationExecutor`) and each
patch set it answers through `CommandValidator`, which runs
`generation.validation.argv` once per validation task with `{input}`,
`{output}` and `{resource}` replaced (the contract is in
`validation.py`). The command rebuilds the harness from `input/patch.diff`
on the base binding, runs the 07 §5.2 checks in a VM and writes
`output/report.json`: `passed` with the new `descriptor.json` and staged
`hcap.json`, `rejected` with a typed reason, or `inconclusive`. A pass
stores a staged `ExecutionHarnessApproval`; the Materializer's authority
takes it beside the static `execution_harness_approvals`, and the waiting
jobs continue on the staged binding. Tasks and approvals are in
`state_dir/validations.sqlite`; command runs in `validation-runs/`.

Only `run` validates (it holds `validation.lock`); other commands read the
statuses and leave submits to `run`. A validation running when `run` stops
ends `inconclusive`, and the Controller runs it again as a new task after
restart. With `slots`, a validation takes a KVM slot from the same pool as
the Runner workers; without, it runs on its own `resource_key`, so the host
needs room for both.

## Q1 authority

`Q1AuthorityPublisher` builds each `Q1HostContext` from host records only:

- candidate, plan, binding and materialization from the Controller
  transition that dispatched the task;
- lease generation from the Runner's accepted completion, and the
  execution position from the sealing receipt;
- the kernel identity from the approved descriptor. This slice requires
  `nokaslr` on the guest command line, so the relocation is zero;
- the target mapping from `add-mapping`. Registering a mapping is the
  operator's statement that its PCs come from this exact vmlinux.

When any of these is missing the publication stays pending and the job
stays in `s1_running`; it continues once the record arrives.

## Real run (follow-up)

The VM lane collector, the record generator and target-PC mapping are in
[`host/`](host/README.md), with the runbook for the KVM host. They are
tested without a guest; the first real run is recorded here so its
completion is checkable:

- **Owner:** to be assigned when the run starts.
- **Target:** the `main` commit that merges the collector, with the parser
  bundle rebuilt from that commit by `tools/syzkaller/build.py`.
- **Done when** one candidate goes, on that commit, through the real model
  (PydanticAI) → syzkaller parser → VM lane collector → evidence sealing →
  Q1 publication → `s1_reached`, and after restarting the service
  `replay JOB` matches.
- **Evidence:** the run's `state_dir` and `artifact_root` (Controller
  transitions, Runner receipts, Q1 publication, `runs/*/process.log`),
  archived with the command lines used and linked from the collector PR.

## Not here yet

The service runs on one host with one Runner worker and one resource key.
Measured KASLR relocation (the collector requires `nokaslr`) and external
issue filing remain separate work. Stage 2 runs in the same service when
`stage2` is configured; see `agent_pipeline/stage2/README.md`.
