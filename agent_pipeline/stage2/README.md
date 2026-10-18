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
  "argv": ["/opt/knfsd/bin/stage2-step", "{input}", "{output}"],
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

`JobPolicy.run_stage2` is false by default. With it false an operator
starts Stage 2 of a reached job (`operator JOB start_stage2`); a policy may
set it true. The campaign thresholds and `fuzz_budget_executions` are
placeholders until the repository owner sets them.

## KVM preflight

Before starting a real Stage 2 job, run the read-only readiness check:

```sh
python -m agent_pipeline.stage2.host preflight \
  --stage1 stage1-state/stage1.json \
  --collector stage1-state/collector.json \
  --manager stage2-manager.json
```

The check does not boot a VM or change pipeline state. It verifies access to
`/dev/kvm`, QEMU/SSH/SCP, the configured host command and its input/output
placeholders, every pinned harness file, the three judge profiles, each
binding's approved HCAP and promoted semantic subset, and that the Compiler
and replay Proxy report the promoted build. When a syz-manager config is
provided it also requires remote coverage, a crash-context window at least
as large as `crash_window_bound`, one KVM target-mode VM, a lane script that
matches `koov.lane_sha256`, disabled NFS local I/O and the journal channel.

Warnings identify an operator-start policy, repository placeholder campaign
thresholds, an omitted manager config, or separate Stage 1/Stage 2 resource
keys. Any failed check exits 2; `--json` emits the versioned
`stage2-kvm-preflight.v1` report for archiving with a run.

## First run on KVM (manual)

Nothing here has run on a real VM yet; `tests/agent_pipeline/test_stage2_service.py`
drives the whole path with a synthetic host command. For the first KVM run:

1. Bring a job to `s1_reached` with the Stage 1 service (its README).
2. Build the promoted Proxy and set `nfs_proxy` (the compiler) and
   `stage2.replay_proxy` to it.
3. Store the three judge profiles and put their digests in `stage2`.
   `q2.default_q2_profile()` is the reference Q2 profile.
4. Write the step command against the contract above. Gate: boot the
   harness guest with `rules.nfsprul1` installed, run `program.syz` and
   `neutral.syz` with `syz-execprog`, collect remote KCOV as Stage 1 does,
   and copy the lane's host journal segments. Campaign: run syz-manager with
   the rules, and per fuzz VM instance span write a segment with the Q2
   collector's facts and, on a crash, its crash log. Replay: boot a fresh
   VM, install `replay/rules.bin`, run `replay/programs.log` with
   `syz-execprog -procs=1 -repeat=1` into a new journal.
5. `python -m agent_pipeline.stage1 --config stage1.json operator JOB start_stage2`,
   then `run --job JOB`. It stops in `crash_review`, `blocked_operator` or
   `parked`; `status --job JOB` shows the gate runs, campaign tally, triage
   items and replay outcome.
6. Keep `state_dir` (`stage2-runs/*/process.log`, `stage2-publications.sqlite`,
   Runner and receipt databases) and `artifact_root`, and check that
   `replay JOB` matches after a restart.
