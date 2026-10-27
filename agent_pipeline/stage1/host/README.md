# Stage 1 on a real KVM host

`agent_pipeline.stage1.host` is what the wired service (`../README.md`) needs
to run one candidate on a real guest:

| Command | What |
|---|---|
| `generate SPEC` | Writes every host record `stage1.json` refers to, plus `stage1.json` and `collector.json`; with a `stage2` section, the Stage 2 syz-manager config (`../../stage2/README.md`) |
| `collect --config collector.json IN OUT` | The engine's host command: boots one guest, runs the harness program on lane 0 with remote KCOV, writes the capture |
| `probe --stage1 S --program P --out D` | Runs one program the same way, without the service. Use it first on a new host |
| `target-pcs --stage1 S --job J --out F` | Builds a verified `TargetPcMapping` for a submitted job from the pinned vmlinux |
| `check-pcs --stage1 S --coverage F` | Checks that the published PCs are coverage call sites, so they use the same form as `target-pcs` |
| `validate --config validate.json IN OUT` | The validation command of a Harness Generation patch set (`generation.validation.argv`, see below) |

Everything is invoked as `uv run python -m agent_pipeline.stage1.host ...`.
The tests (`tests/agent_pipeline/test_stage1_host.py`) cover generation, the
collector with a scripted guest, and mapping on a gcc
`-fsanitize-coverage=trace-pc` binary, and they run a generated config to
`s1_reached`. They do not exercise a real guest, kernel or model: this
runbook does.

## What only the VM host can provide

- `qemu-system-x86_64`, `ssh`/`scp`, binutils (`objdump`, `addr2line`,
  `nm`). `/dev/kvm` is optional: with it the guests run under KVM, without
  it under TCG (software emulation, about ten times slower). The spec's
  `collector.accel` is `auto` by default; generation resolves it on the
  generating host, writes it to `collector.json`, and for TCG scales the
  boot, fixture and engine budgets and the execprog slowdown by 10. Set it
  to `kvm` or `tcg` to pin the choice; `KOOV_QEMU_ACCEL` does the same for
  `tools/bootstrap-kcov-env.py`, the baker and
  `tools/prepare-live-lane-config.py`.
- The bootstrap env: the patched kernel tree, `bzImage`, `vmlinux`,
  `.config`, the baked image and the syzkaller binaries
  (`tools/bootstrap-kcov-env.py`).
- The parser bundle, built with Go **1.26.0** from the same syzkaller tree
  as the binaries (`tools/syzkaller/build.py`).
- `OPENAI_API_KEY` for the model in the job policy.
- The capability and policy statements in the spec. The template is a
  starting point that the operator approves, not a fact this code checks.

## Run

From the repository root, on the VM host, at the commit under test:

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

# 3b. Optional, Harness Generation: the generation OS user, once per host,
#     then "generation": {} in the spec (see "Validating a Harness
#     Generation patch set")
sudo bash tools/setup-generation-user.sh --spec stage1-host/host-spec.json

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
`--variant kcsan`; a KCSAN harness also reports `BUG: KCSAN:` as a crash. A
`stage2` section writes one manager config per variant.

## Promotion criteria (#100)

Capability evidence must be typed: a `promotion-probe-evidence.v1`
campaign, or the capability's own KVM evidence model. Untyped evidence is
refused for every capability.

`generate.LEGACY_CAPABILITY_BASELINES` pins, for each capability the
checked-in specs held before the criteria, `capability_baseline_sha256` of
its entry (without `validated_layout` and evidence references). The
repository pins them, so a spec cannot exempt a capability. While an entry
still matches, it keeps its earlier status; that includes the live spec's
HCAP-14, which has been `experimental` since before the criteria. A new
capability, or one whose entry changed, needs all of the following, and
`generate` refuses the spec otherwise:

- a `contract` (entry points, boundary functions, fixed arguments and
  types; `docs/design/02-llm-agent/04-harness-capability-spec.md` §3.3);
- a `PromotionProbeEvidence` file in `capability_evidence` whose probes
  are the contract's boundary functions and whose minimal, generated and
  neutral run sets meet the thresholds in `agent_pipeline/promotion.py`
  (KVM only for a `time_dependent` contract);
- syz call arguments that carry no literal the contract does not fix. The
  check reads the pinned target's argument shapes through the parser
  bundle's `describe`, so the bundle must be built from this repository's
  bridge sources.

`probe-campaign` runs the campaign and writes the evidence:

```sh
uv run python -m agent_pipeline.stage1.host probe-campaign \
    --config campaign.json campaign-out
```

`campaign.json` is a `campaign.CampaignConfig`: `stage1` (and optionally
`collector`), the binding (`execution_harness_id`, `hcap_revision`; a
staged one boots from `staged_files`), `capability_id`, the candidate's
`withheld_program_sha256s`, the runtime `selection` index and `seed`. The
probes are the contract's boundary functions mapped to the binding's
coverage call sites (`probe-<name>.json`). The parser bundle's `generate`
makes a minimal program per entry syz call and distinct generated and
mutated programs over the admission profile's calls; each is parsed and
admitted as the Materializer would, and withheld or refused ones are
dropped. Each run boots a fresh guest: the minimal programs (3 runs), 16
generated programs twice each, and the selection's neutral control 3
times. `campaign-out/campaign.json` is `evidence` (then
`campaign-out/evidence.json` goes into `capability_evidence`), `refused`
(the criteria are not met, or the contract has no entry syz call) or
`inconclusive` (a guest did not boot or a run did not finish). The parser
bundle must be built from this repository's bridge sources, `generate.go`
included.

The command exits 0 whenever it wrote `campaign.json`; a nonzero exit is
an infrastructure end. For a staged harness the service runs it as
`generation.campaign`, which `generate` writes with this `stage1.json` and
`collector.json` (see "Promotion of a staged harness" in
[`../README.md`](../README.md)).

`gap_contracts` gives the contract a capability filling each gap ID must
declare; it is copied into the generated HCAP. A capability names the gap
it fills with `fills_gap`, and `generate` refuses it unless its contract is
that gap's. A capability that fills a gap also needs a campaign that names
the candidate's programs in `withheld_program_sha256s`.

The spec's `gap_contracts` are the operator's statement. A Harness
Generation patch set can change the spec, so on that path the Controller
passes the gap and its contract from its own state, with the spec the patch
set started from:

```sh
uv run python -m agent_pipeline.stage1.host generate SPEC \
    --gap gap.json --base-spec base-host-spec.json
```

`gap.json` is a `GapContract`. The spec cannot give that gap another
contract, and every capability the patch set adds or changes relative to
the base spec must fill that gap, and it may not remove a base capability.
Capabilities the base already holds are not the patch set's, whatever gap
they fill. The base spec must come from the Controller's own read-only
store, not from the generation worktree.

Outside the legacy baselines, "judged" means every generation: a capability
promoted after the criteria keeps its promotion only while its spec entry
lists a probe campaign bound to the generated harness. That is the same
binding the capability-specific KVM evidence has.

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

## Validating a Harness Generation patch set

With a `generation` section in the host spec, `generate` also writes
`stage1.json`'s `generation` (`../README.md`) and
`stage1-state/validate.json`, so each patch set the generation Agent
answers is validated by `validate` (`validate.py`;
`docs/design/02-llm-agent/07-harness-gap-issue.md` §5.2). Everything
follows this repository's layout:

| Where | What |
|---|---|
| this checkout | the clone the worktrees and patch sets start from; the spec must be inside it |
| `stage1-state/generation-worktrees/` | one worktree per generation |
| `stage1-state/validation-work/` | scratch per validation task (`tree`, `env`, `state`, `cas`) |
| the spec's `env_dir` and `syzkaller_bundle` | the base env and parser bundle of every rebuild |
| `tools/harness-generation-build.py` | the build step |
| `/usr/local/libexec/knfsd-harness-gen` | the launcher of `tools/setup-generation-user.sh` |

`tools/setup-generation-user.sh` (run once with `sudo`, like
`make-base-image.sh`) creates the system user `harness-gen`, installs the
launcher (a new network namespace, then `setpriv` to `harness-gen` with
no_new_privs and umask 002) with a sudoers rule that lets only the
invoking user run it, creates the two state directories setgid to the
`harness-gen` group, adds ACLs where `harness-gen` could not read the
clone, and checks the result. The invoking user joins the group at its
next login. Commands through sudo get its `secure_path`, so give the
build step tools outside it by absolute path (`--go`).

The spec section, all fields optional:

```json
"generation": {
  "user": "harness-gen",
  "launcher": null,
  "base_ref": "HEAD",
  "workers": 1,
  "build_args": ["--go", "/opt/go1.26.0/bin/go"],
  "build_timeout_s": 21600,
  "validation_timeout_s": 28800
}
```

`launcher` replaces the setup script's wrapper with another argv prefix
that runs as a separate user without network; `build_args` go to the
build step (`--go`, `--version`, `--kernel-repo`, `--syz-repo`,
`--jobs`). `validate.json` is a `validate.ValidateConfig`:

| Field | What |
|---|---|
| `repo` | the host's clone; a patch set names one of its commits |
| `work_root` | scratch per task; `env` is setgid 2775 so the generation user can write the build |
| `base_spec` | the host's own `host-spec.json`, never the tree's |
| `collector` | the service's `collector.json` (`staged_files`, key, timings) |
| `build_argv` | the build step, with `{tree}`, `{env}`, `{base_env}`, `{sanitizer}` |
| `launcher` | the generation OS user without network, as in `generation.launcher` |
| `build_timeout_s`, `build_env`, `allowed_paths`, `keep_work` | limits and debugging |

`tools/harness-generation-build.py` compares what each build reads
(kernel series and configs, syzkaller series, baker, lane, guest
dependencies) between the patched tree and this checkout. When nothing
changed it links the base env and bundle; otherwise it runs the tree's
`bootstrap-kcov-env.py` for the one variant with the base env's trees as
local mirrors, and `tools/syzkaller/build.py` when the syzkaller series
changed.

The build script writes a `tools/bootstrap-kcov-env.py` env into `{env}`
(`linux/`, `images/<variant>/`, `syzkaller/`) and the parser bundle into
`{env}/syz-bridge/` (`bundle/` and `checkout/`). It runs without network,
so give it local mirrors, and it may copy from `{base_env}` what the patch
set did not change (a spec-only patch set needs no rebuild). The new
build's host files are then copied to `collector.json`'s `staged_files`
(`<state>/staged-files/<sha256>/<name>`), where the collector finds a pin
the configured files do not match.

A patch set must add `stage1-host/generation/<gap id>/smoke.syz` (and
optionally `smoke-*.syz` and a `selection.json`). Its capabilities are
`experimental` with `fills_gap` and the gap's contract. The VM runs are
the smoke programs, the neutral control of their selection, and every
neutral control of the base spec as the regression.

A `mutation_engine` gap has no contract. Its patch set changes the Proxy
source and no spec capability, and adds `subset.json`, `rules.nfsprul1`
and `production.syz` under `stage1-host/generation/<gap id>/`. When the
Proxy source changed, the build script builds the guest Proxy into
`{env}/nfs-proxy-lane` with the tree's `tools/nfs-proxy/build-guest.sh`
(Docker, with `debian:bookworm` already pulled) and bakes it into the
guest dependencies. After the regression, `semantic.py` pins the subset
(M7 stage 1, crash survival pending): a target-mode production of the
program with the rule set, its replay in a fresh guest, the judgment and
`semantic_promotion.pin`. The staged HCAP's HCAP-10 references the pinned
registry. The Proxy runs on the host only under `launcher`; `proxy` in
`validate.json` names the tree's Proxy for a build that did not rebuild
it.
