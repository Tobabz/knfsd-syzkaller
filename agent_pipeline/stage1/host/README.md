# Stage 1 on a real KVM host

`agent_pipeline.stage1.host` is what the wired service (`../README.md`) needs
to run one candidate on a real guest:

| Command | What |
|---|---|
| `generate SPEC` | Writes every host record `stage1.json` refers to, plus `stage1.json` and `collector.json` |
| `collect --config collector.json IN OUT` | The engine's host command: boots one guest, runs the harness program on lane 0 with remote KCOV, writes the capture |
| `probe --stage1 S --program P --out D` | Runs one program the same way, without the service. Use it first on a new host |
| `target-pcs --stage1 S --job J --out F` | Builds a verified `TargetPcMapping` for a submitted job from the pinned vmlinux |
| `check-pcs --stage1 S --coverage F` | Checks that the published PCs are coverage call sites, so they use the same form as `target-pcs` |

Everything is invoked as `uv run python -m agent_pipeline.stage1.host ...`.
The tests (`tests/agent_pipeline/test_stage1_host.py`) cover generation, the
collector with a scripted guest, and mapping on a gcc
`-fsanitize-coverage=trace-pc` binary, and they run a generated config to
`s1_reached`. They do not exercise a real guest, kernel or model: this
runbook does.

## What only the KVM host can provide

- `/dev/kvm`, `qemu-system-x86_64`, `ssh`/`scp`, binutils (`objdump`,
  `addr2line`, `nm`).
- The bootstrap env: the patched kernel tree, `bzImage`, `vmlinux`,
  `.config`, the baked image and the syzkaller binaries
  (`tools/bootstrap-kcov-env.py`).
- The parser bundle, built with Go **1.26.0** from the same syzkaller tree
  as the binaries (`tools/syzkaller/build.py`).
- `OPENAI_API_KEY` for the model in the job policy.
- The capability and policy statements in the spec. The template is a
  starting point that the operator approves, not a fact this code checks.

## Run

From the repository root, on the KVM host, at the commit under test:

```sh
uv sync --locked --extra agent-openai

# 1. Base image and bootstrap env (once per kernel; see tools/README.md)
sudo bash tools/make-base-image.sh --out artifacts
uv run python tools/bootstrap-kcov-env.py env \
    --base-image artifacts/bookworm-base.img \
    --ssh-key artifacts/bookworm.id_rsa \
    --deps-tar bundle/src/guest-deps-lane.tar.gz --version 4.1 --variant kasan

# 2. Parser bundle from the same syzkaller tree (Go 1.26.0)
uv run python tools/syzkaller/build.py --source env/syzkaller \
    --output "$PWD/syz-bridge" --go /path/to/go1.26.0/bin/go

# 3. Spec: copy the template and review every statement in it
mkdir -p stage1-host
cp agent_pipeline/stage1/host/template/* stage1-host/
$EDITOR stage1-host/host-spec.json

# 4. Generate records and configs (writes stage1-state/)
uv run python -m agent_pipeline.stage1.host generate stage1-host/host-spec.json

# 5. Probe: boot, fixture, lane, counters and coverage, no service
uv run python -m agent_pipeline.stage1.host probe \
    --stage1 stage1-state/stage1.json \
    --program bundle/corpus/nfs-normal/basic-v41-tcp.prog --out probe-1
uv run python -m agent_pipeline.stage1.host check-pcs \
    --stage1 stage1-state/stage1.json --coverage probe-1/pcs.txt

# 6. Submit a candidate and map its target PCs
S=stage1-state/stage1.json
uv run python -m agent_pipeline.stage1 --config $S submit \
    --commit "$(git -C env/linux rev-parse HEAD)" \
    --path fs/nfsd/nfs4proc.c --symbol nfsd4_open --policy kasan-default
uv run python -m agent_pipeline.stage1.host target-pcs --stage1 $S \
    --job <job id> --out stage1-state/mapping.json
uv run python -m agent_pipeline.stage1 --config $S add-mapping stage1-state/mapping.json

# 7. Run, then restart and replay
export OPENAI_API_KEY=...
uv run python -m agent_pipeline.stage1 --config $S run --job <job id>
uv run python -m agent_pipeline.stage1 --config $S status <job id>
uv run python -m agent_pipeline.stage1 --config $S replay <job id>
```

`run` stops at `s1_reached`, at a state that needs a person, or at the end.
If it stops at `s1_approval`, approve the job and run it again. `replay`
in a new process is the restart check. Keep `stage1-state/` whole: it
holds the Controller history, Runner receipts, Q1 publications, the CAS
and `runs/<task>/` with every lease's input, output and `process.log`.

## What to check on the first run

The probe answers the open questions this code could not settle without a
guest. Read `probe-1/probe.json`:

1. **Facts.** `boot_ok`, `fixture_ok`, `lane_ok`, `runner_completed`,
   `collection_completed` and `extra_present` should all be true, and
   `runtime_errors` should be empty, and `crash` should be null: a
   kernel crash on the serial console is reported there, not as a
   runtime error.
2. **Generation counters.** `generation_begin` and `aggregate_published`
   should both be 1. execprog's machine check runs its own extra-coverage
   request, which opens a generation, so the window does not cover the
   whole execprog run: execprog stops at `-gate` after the check
   (syzkaller patch 0022), the collector reads the "before" snapshot
   there, once every listed generation in `phase4_state` has settled, and
   then lets the program run. `execprog_gate` in `collector-result.json`
   should read `ready`. An execprog built without patch 0022 exits at the
   unknown flag and the run reports `execprog_failed_before_gate`.
3. **Counter names.** `counter_labels` lists every counter as the Judge
   will see it. A name printed by more than one stats file is qualified
   (`phase5_stats.remote_refs`). The `judge_profile` counters must use
   these labels. A counter that is missing makes a miss INCONCLUSIVE; a
   hit is unaffected.
4. **PC form.** `check-pcs` should report `callsites == published` and
   `callback_tail_jumps` 0. A GCC tail jump to `__sanitizer_cov_trace_pc`
   makes KCOV record the caller's return address instead of a call site;
   kernel patch 0005 builds KCOV objects with `-fno-optimize-sibling-calls`
   so there are none, and `target-pcs` refuses a vmlinux that still has
   them. If `callsite_plus_5` matches instead, the coverage file holds
   return addresses, and `target-pcs` must shift its PCs to match.

## KASAN and KCSAN from one spec

`variants` in the spec (in place of `variant`) lists the sanitizer builds
of the same harness, for example:

```json
"variants": [
  {"sanitizer": "kasan", "capability_evidence": {"HCAP-11": ["..."]}},
  {"sanitizer": "kcsan", "capability_evidence": {}}
]
```

Build each with `tools/bootstrap-kcov-env.py --variant <sanitizer>` into
`env/images/<sanitizer>`. The syzkaller build, admission profile, neutral
controls, judge profile and capability statements are shared. Each variant
gets its own kernel pins, instrumentation manifest, descriptor, support
boundary, HCAP revision, approval and binding, so the policy's sanitizer
selects the harness. KVM capability evidence is pinned to a descriptor, so
it is collected and listed per variant; a variant without it has those
capabilities without evidence. `collector.json` keeps each variant's
`bzimage` and `kernel` under `variant_files`, and the collector boots the
files of the lease's descriptor. `probe` and `check-pcs` take
`--variant kcsan`; a KCSAN harness also reports `BUG: KCSAN:` as a crash.

## How the pieces bind

- **Pins.** The descriptor names each host file (vmlinux as `kernel`,
  `bzimage`, `vm-image`, `lane-script`, `syz-executor`, `syz-execprog`,
  `syz-manager`) by the digest of a small `HostFilePin` record holding the
  file's SHA-256 and size. This keeps multi-GB files out of the CAS.
  `collect`, `probe` and `target-pcs` refuse a file that does not match its
  pin. `pins.json` caches digests by inode, size and mtime. Stage 2 preflight
  uses the manager pin to bind a campaign to the approved syzkaller build.
- **Build records.** `generate` refuses a kernel or syzkaller build whose
  bootstrap record (`images/<variant>/build.json`,
  `syzkaller/bin/build.json`) names another patch series than the checked-in
  one or another commit than the tree's HEAD, and a parser bundle whose
  series is not the checked-in syzkaller series. After a series change,
  rerun step 1 without `--skip-build` and step 2 into a new directory.
- **Instrumentation.** The `instrumentation` artifact is an
  `InstrumentationManifest` of the kernel patch series and `.config`. The
  support boundary's `instrumentation_sha256` is the same digest.
- **Kernel identity.** The descriptor command line must contain `nokaslr`,
  so the published PCs are link addresses and the relocation is zero. The
  collector adds the `koov.*` fixture parameters from the harness runtime
  selection.
- **Runtime selections.** The Agent can see capabilities but not the
  descriptor. `runtime_selection_capability` copies each allowed selection
  into that capability's constraints, so the plan can name one exactly.
- **Correlation.** Each lease boots a fresh guest and runs one program on
  one proc, which the executor binds to lane 0. The capture uses lane 0,
  generation 1 and a `vm_instance_id` of `<task>.g<generation>.<random>`.
- **Failures.** A host problem (pin mismatch, no `nokaslr`, bad config)
  exits nonzero, and the engine records `capture_failed`. A guest problem
  is written into the observation (a false fact or a runtime error), and
  the Judge returns `INCONCLUSIVE(infra)`. `console.log`, `executor.log`,
  `dmesg.log` and `collector-result.json` are sealed with the capture.
