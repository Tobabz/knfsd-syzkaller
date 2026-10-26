# Stage 2 backend

`agent_pipeline.stage2` runs the Stage 2 Runner steps (gate, campaign,
replay) on host VMs and judges what they seal. It adds no decision rule:
the verdicts come from the existing kernels (`q1`/`sealed_q1`, `m1`,
`q2`/`sealed_q2`, `replay_runner` and `semantic_replay`), and the
Controller's 09 §4 rows route on them.

```
Controller ─► DurableRunner ◄── RunnerWorker ─► StepRoutingBackend
   ▲                ▲                              ├─ step None ─► EvidenceSealingBackend (Stage 1)
   │                │ append_bundle (per segment)  └─ step set ──► StreamingSealingBackend
   │                └──────────────────────────────────────────────── Stage2CommandEngine
   │                                                                     └─► host command (VMs)
   └── PublishedStage2Judge ◄── Stage2AuthorityPublisher ◄── bundles, receipts, dispatch records
```

- `engine.Stage2CommandEngine` runs one trusted host command per lease and
  seals every segment the command finishes **while it runs**: each becomes
  its own bundle, added to the task with `DurableRunner.append_bundle`, so
  a campaign's bundles reach the Controller before the campaign ends. A gate
  seals one bundle per repetition, a replay one.
- `evidence` names the artifacts a bundle holds and the `stage2-host` facts
  the engine writes into it from host knowledge (the command's report, the
  replay plan, the `--check-rules` answer). The command cannot write them.
- `authority.Stage2AuthorityPublisher` publishes one `Stage2Execution` per
  bundle, append-only, from host records only: the dispatch transition, the
  Runner's bundle record, the sealing receipt (which carries the full
  `RunnerInput`), the execution harness descriptor, an operator-registered
  verified target mapping and the configured judge profiles. A gate's Q1
  authority passes the same materialization checks as a Stage 1 run.
- `judge.ArtifactStage2Judge` is `components.Stage2Judge` over a snapshot
  of that authority. A bundle without published authority raises (the
  Controller retries); malformed or miscorrelated evidence is INCONCLUSIVE
  (rules and hypotheses), Q2 by its own table, or `evidence_rejected`
  (replay).

What each step's verdict reads:

| step | verdict |
|---|---|
| gate | Q1 of the scenario run (`ArtifactQ1Judge`); rule and intent M1 over the program generations its `nfs proxy barrier` lines name, joined to the journal; ambient flags from the neutral run (target PCs in its coverage, rules APPLIED in it), recorded only |
| campaign | Q2 of the segment (`ArtifactQ2Judge`); for Q2 OBSERVED, M1 over the crash's CrashContextWindow from syz-manager's crash log; per program generation whose published coverage hits a target PC, its hypothesis M1 for the campaign tally |
| replay | `replay_runner.judge_input` over the crash bundle's production journal and the replay journal, then `semantic_replay.evaluate` |

## Host command contract

The command is host configuration (`Stage1Config.stage2.argv`); `{input}`
and `{output}` in argv are replaced with the lease's directories.

`input/` holds `execution.json` (job, task, step, harness, lease
generation, `compiled_ref`, `rule_set_id`, `gate_repetitions`,
`campaign_id`, `crash_bundle_ref`), `harness.json`, `descriptor.json`,
`hcap.json`, `admission.json`,
`program.syz`, `neutral.syz`, `rules.nfsprul1` (install these bytes) and
`compiled.json`. A replay also has `replay/`: `rules.bin` (the bytes the
crash's journal recorded), `programs.log` (the window, in order, for
`syz-execprog -procs=1 -repeat=1`) and `plan.json`.

The command writes one directory per segment, `output/segments/NNNNNN/`
numbered from 0, as `segments/.NNNNNN.tmp` renamed when complete. Its
`capture.json` is

```json
{"vm_instance_id": "...", "lane": 0, "generation_id": 1,
 "host": { ...the step's report... },
 "artifacts": [{"identity": "...", "type": "...", "path": "..."}]}
```

| step | `host` (`evidence`) | artifacts |
|---|---|---|
| gate | `GateHostFacts`: `journal_name` | `reachability` and `coverage` (the Stage 1 Q1 observation, scenario run with rules); `neutral-coverage` (`NEUTRAL_COVERAGE_TYPE`); `execprog.scenario`, `execprog.neutral` (syz-execprog output); `journal/<name>.NNNN.njnl` |
| campaign | `CampaignHostFacts`: `journal_name`, `executions`, the Q2 collector facts (console identity and completeness, every syz-manager report identity, `vm_termination`, `collection_window`) | `q2-evidence`, console, reports (`sealed_q2`); `crash-log` when the VM crashed; `generation-coverage/<lane>.<generation>` per program generation; `journal/...` |
| replay | `ReplayHostFacts`: `journal_name`, `replay_end`, `fixture_failed` | `execprog.replay`; `journal/...` of the separate replay journal |

A gate must finish `gate_repetitions` segments, a replay one, a campaign at
least one; fewer, a nonzero exit or a malformed segment ends the lease
`capture_failed` (a runtime failure the Controller reruns, never a verdict)
and keeps the segments already sealed. For a replay the engine plans before
anything runs; when no plan is possible (no crash log, no window entry in
the journal) nothing runs and one segment records why, so the replay is
judged REPLAY_INVALID instead of retried.

## Configuration

`Stage1Config.stage2` (unset: a compiled rule set waits in
`blocked_operator(stage2_gate_unavailable)`):

```json
"stage2": {
  "argv": ["/opt/knfsd/venv/bin/python", "-m",
           "agent_pipeline.stage2.host", "step", "--manager",
           "/var/lib/knfsd/stage2/manager.json", "--collector",
           "/var/lib/knfsd/stage1/collector.json",
           "--campaign-executions", "128",
           "{input}", "{output}"],
  "cwd": "/var/lib/knfsd/stage2",
  "resource_key": "host-a/kvm",
  "replay_proxy": "/opt/knfsd/bin/nfs-proxy",
  "m1_profile_ref": "<M1JudgeProfile digest>",
  "q2_profile_ref": "<Q2JudgeProfile digest>",
  "replay_profile_ref": "<ReplayJudgeProfile digest>",
  "crash_window_bound": 4
}
```

Use the Stage 1 command's `resource_key` when both use the same VMs. The
profiles are records in the CAS (`data.put_record`). `crash_window_bound`
must not exceed syzkaller's `experimental.nfs_proxy_window`.
The step command limits one syz-manager invocation to 128 completed programs
by default so its generation artifacts fit the 255-artifact segment bound.
The Controller starts further campaign tasks until policy routes the job.
`--exec-slowdown` is the bounded syz-execprog slowdown for direct gate and
replay guests. Left out, it is the collector's `exec_slowdown`: 1 under KVM,
10 under TCG. Override it only when the durable host journal's measured
fsync latency requires a larger executor timeout; record any override in the
trusted Stage 2 argv. It does not alter syz-manager campaign timeouts;
syz-manager raises its own slowdown when its QEMU arguments contain
`-accel tcg`.

`JobPolicy.campaign_mode` is `none` by default: a reached job waits in
`s1_reached(evidence_only)` and an operator starts Stage 2
(`operator JOB start_stage2`). A policy may set `campaign_mode: mutate`, or
the legacy `run_stage2: true`, to start it on Q1 `REACHED`. The campaign thresholds and `fuzz_budget_executions` are
placeholders until the repository owner sets them.

## Manager config

`python -m agent_pipeline.stage1.host generate SPEC` writes the manager
config when the host spec has a `stage2` section (#81 D17):

```json
"stage2": {"nfs_proxy_window": 6}
```

It writes `state_dir/stage2-manager.json`, or `stage2-manager-<sanitizer>.json`
for each variant, from the same descriptor the Stage 1 collector runs: its
`bzImage`, `vmlinux`, image, syzkaller binaries, SSH key, QEMU, CPUs and
memory, a frozen copy of the pinned lane script as `workdir_template`, the
approved command line with the selection's `koov.*` arguments and
`koov.nfs_target=1`, the 9P lane share, and one journal channel per guest
lane. `enable_syscalls` is every admitted call and every call the runtime
selection enables; a given list must include all of them and name only
calls the syzkaller build has. `runtime_selection` picks the selection the
manager boots and may be left out when the spec has one. `generated.json`
records each manager's SHA-256 under `stage2_manager`. Generation does not
set `Stage1Config.stage2` or `nfs_proxy`, which need the promoted Proxy and
the judge profiles; pass the manager to the `step` and `preflight` commands.

### Validated layouts (#99)

Every capability carries a `validated_layout` (`procs` and the proc lanes
its evidence ran on); a capability without one is validated on Stage 1's
layout, `procs: 1` on lane 0. Stage 1 plans run there, so a plan that uses a
capability whose layout does not cover lane 0 is refused
(`layout_not_validated:<id>`). A layout wider than Stage 1's must come from
typed capability evidence whose `layout` equals the declared one.

`procs` defaults to the layout of the runtime selection's capability
(HCAP-04). A larger `procs` is refused, calls whose admitting capabilities
do not cover `procs` are left out of `enable_syscalls` (a given list naming
one is refused), and `remote_cover` must be covered. `preflight` repeats the
check on the manager it is given against each approved harness's catalog
and call admission profile.

### Lane topology evidence

HCAP-01, HCAP-03 and HCAP-04 widen together from one bounded syz-manager
campaign:

```sh
python -m agent_pipeline.stage2.topology \
    --manager state/stage2-manager.json \
    --collector state/collector.json \
    --descriptor state/descriptor.json \
    --output state/topology --procs 4
```

The campaign runs the manager with `procs` lanes, `reproduce: false`, the
neutral program's calls and an empty Proxy rule set, and stops when every
lane has at least `--executions` (default 8) executions or at `--timeout`.
Per lane it requires that every spooled execution is attributed to that
lane, was acknowledged by the lane's Proxy, reports a healthy lane, and that
each generation it ran opened on that lane's journal channel with no event
from another lane. It writes `result.json` and, when every lane passes,
`hcap04-kvm.json`. Promotable evidence is bound to the repository's fixed
`v41-client-io-topology.prog` digest; the command does not accept another
corpus. The corpus is a shortened NFSv4.1 live-bind program: its first call
opens the per-proc lane and its generated EXCHANGE_ID request drives the
server path, so target-mode call coverage is attributable on every lane.
Add `hcap04-kvm.json` to `capability_evidence` for HCAP-01, HCAP-03 and
HCAP-04 and set their `validated_layout` to
`{"procs": 4, "lanes": [0, 1, 2, 3]}`. The Stage 2 default is `procs=4`.

`lane.sh status` runs inside the guest and is not reachable from a manager
VM, so the per-execution health fields of the spool record stand in for it.

## KVM preflight

Before starting a real Stage 2 job, run the read-only readiness check:

```sh
python -m agent_pipeline.stage2.host preflight \
  --stage1 stage1-state/stage1.json \
  --collector stage1-state/collector.json \
  --manager stage2-manager.json
```

The check does not boot a VM or change pipeline state. It verifies the
collector's accelerator (`/dev/kvm` opens with the expected API when the
collector runs under KVM; nothing when it runs under TCG), QEMU/SSH/SCP, the configured host command and its input/output
placeholders, every pinned harness file, the three judge profiles, each
binding's approved HCAP and promoted semantic subset, and that the Compiler
and replay Proxy report the promoted build. The required syz-manager config
must be an explicit Stage 2 command argument. Its kernel, image, lane script
and syzkaller binaries must match the approved harness pins; its SSH key and
QEMU must match the collector. It also requires remote coverage, program
snapshot mode disabled, a crash-context window at least as large as
`crash_window_bound`, one target-mode VM whose QEMU arguments select the
collector's accelerator, the exact approved base kernel
command line plus `koov.*` fixture arguments that boot one of the
descriptor's runtime selections (its `koov.nfs_version` or
`koov.nfs_fixture`, its `koov.nfs_trace`; the Stage 1-only `nlm-knfsd`
fixture is refused), and one journal channel per active proc. With several
sanitizer variants the manager is checked against the harnesses whose
`bzimage` and `kernel` it boots, so one manager runs one variant. The report records the manager config's SHA-256. Regenerate
older Stage 1 harness configs so their descriptor also pins `syz-manager`; a
Stage 2 preflight intentionally rejects descriptors that pin only the
executor binaries.

Preflight also requires the outer Stage 2 supervisor timeout to cover the
slowdown-scaled gate and replay watchdogs and the configured campaign
timeout. Each step enforces one evidence-finalization reserve around journal
channel shutdown, journal and artifact reads, fsyncs and atomic publication.
The final directory rename is the irreversible publication commit point; a
timeout can leave an unpublished dot-directory for lease cleanup, or race with
a completed rename. In the latter case the command still fails but the engine
keeps the atomically complete final segment. This keeps a storage stall
distinguishable from valid sealed evidence before the outer supervisor cleanup
reserve begins.

Warnings identify an operator-start policy, repository placeholder campaign
thresholds or separate Stage 1/Stage 2 resource keys. Any failed check exits
2; `--json` emits the versioned
`stage2-kvm-preflight.v1` report for archiving with a run.

## Real KVM runner

`python -m agent_pipeline.stage2.host step` implements the host contract.
Gate and replay use fresh direct-QEMU guests with the approved fixture. A
campaign creates a private syz-manager workdir and one-program seed corpus.
Syzkaller patches 0025--0026 force and durably export remote KCOV for every
target-mode execution and mark whether each request was sent before or after
machine check completion. The host excludes setup traffic and turns only
campaign records into generation coverage.

### Validation status

PR #61 exercised each standalone host step on real `/dev/kvm` with the pinned
KASAN guest and promoted semantic Proxy. The gate recorded 3,314 remote-KCOV
PCs for its scenario generation and zero for its neutral generation. The
bounded campaign excluded 17 setup executions, accepted all 25 campaign
generations, and recorded three positive generations, including 3,278 PCs for
the exact seed. Replay completed with acknowledged activation and deactivation
and an intact journal. No Q2 internal error or torn journal tail was present.

This validates the concrete host/runtime/evidence path. It does not claim that
a live model and real vulnerability candidate have traversed the complete
Controller-to-host service path; issue #57 owns that campaign. Repository
campaign thresholds are also still placeholders, so automatic Stage 2 remains
off by default.

Run the complete service path as follows:

1. Bring a job to `s1_reached` with the Stage 1 service (its README).
2. Build the promoted Proxy and set `nfs_proxy` (the compiler) and
   `stage2.replay_proxy` to it.
3. Store the three judge profiles and put their digests in `stage2`.
   `q2.default_q2_profile()` is the reference Q2 profile.
4. Configure the `step` argv above. The base manager config remains immutable;
   the command copies it per lease and replaces only workdir, lane template,
   journal sockets and `experimental.nfs_proxy_evidence` with private paths.
5. `python -m agent_pipeline.stage1 --config stage1.json operator JOB start_stage2`,
   then `run --job JOB`. It stops in `crash_review`, `blocked_operator` or
   `parked`; `status --job JOB` shows the gate runs, campaign tally, triage
   items and replay outcome.
6. Keep `state_dir` (`stage2-runs/*/process.log`, `stage2-publications.sqlite`,
   Runner and receipt databases) and `artifact_root`, and check that
   `replay JOB` matches after a restart.
