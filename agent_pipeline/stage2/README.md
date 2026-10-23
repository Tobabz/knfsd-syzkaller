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
  "argv": ["/opt/knfsd/venv/bin/python", "-m",
           "agent_pipeline.stage2.host", "step", "--manager",
           "/var/lib/knfsd/stage2/manager.json", "--collector",
           "/var/lib/knfsd/stage1/collector.json",
           "--campaign-executions", "128", "--exec-slowdown", "1",
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
replay guests. Keep the default unless the durable host journal's measured
fsync latency requires a larger executor timeout; record any override in the
trusted Stage 2 argv. It does not alter syz-manager campaign timeouts.

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

Before starting a specific reached job, include its identity:

```sh
python -m agent_pipeline.stage2.host preflight \
  --stage1 stage1-state/stage1.json \
  --collector stage1-state/collector.json \
  --manager stage2-manager.json --job job-id
```

The check does not boot a VM or change pipeline state. It verifies access to
`/dev/kvm`, QEMU/SSH/SCP, the configured host command and its input/output
placeholders, every pinned harness file, the three judge profiles, each
binding's approved HCAP and promoted semantic subset, and that the Compiler
and replay Proxy report the promoted build. The required syz-manager config
must be an explicit Stage 2 command argument. Its kernel, image, lane script
and syzkaller binaries must match the approved harness pins; its SSH key and
QEMU must match the collector. It also requires remote coverage, program
snapshot mode disabled, a crash-context window at least as large as
`crash_window_bound`, one KVM target-mode VM, the exact approved base kernel
command line plus bounded `koov.*` fixture arguments, and one journal channel
per active proc. The report records the manager config's SHA-256. Regenerate
older Stage 1 harness configs so their descriptor also pins `syz-manager`; a
Stage 2 preflight intentionally rejects descriptors that pin only the
executor binaries.

The optional --job check reads the reached job and its materialized harness
without updating the Controller database. It requires the registered binding,
Stage 2 basis and manager fixture to match. nlm-knfsd jobs fail closed:
HCAP-13 currently authorizes Stage 1 only. The Proxy has an NLMv4 schema and
optional TCP route, but the lane's 2049 relay does not cover NLM on 4045.
The lane refuses NLM target-mode setup until that route is integrated and
validated. The host step refuses this fixture even when preflight is skipped.
A generic deployment preflight without
--job is not a claim of readiness for every job.

To add Stage 2 for this fixture, implement and validate the NLM data path as
separate promotion work: the Proxy now has an opt-in TCP NLM route in its
single event loop, but the lane does not enable it. The fixture needs a
non-conflicting 4045 listener and a distinct lockd backend port, including
rpcbind discovery and client callback routing. The optional
--nlm-preserve-client-ip backend bind now makes the loopback test backend
see the NLM client's source address (test_proxy.c). A non-local guest client
address needs IP_TRANSPARENT and an explicit return route; the lane does not
yet supply a distinct lockd backend endpoint or a verified route. Server lockd uses
the socket peer address for its callback host (Linux fs/lockd/host.c,
nlmsvc_lookup_host); moving the listener port alone cannot fix blocked-grant
callbacks. Preserve or explicitly bridge the client identity in the guest and validate
GRANTED callback delivery before lifting the lane's NLM target-mode block.
The isolated two-namespace experiment in tools/test-nlm-transparent-route.py
passes on the KVM host: a source-port policy route returns backend replies
to the transparent socket, while a separate callback reaches the real client.
This is a socket-level result, not a lockd validation. In a pinned KASAN KVM
guest, tools/test-lockd-netns-kvm.py verifies independent lockd TCP ports
(server 4050, second namespace 4051, initial namespace 0), a live TCP 4050
listener, and remote rpcbind discovery of TCP 4045 after the advertisement
helper runs. This does not show an NLM lock request traversing the Proxy.
The opt-in koov.nlm_relay_experiment=1 lane path moves server lockd to 4050,
advertises 4045, and configures transparent return routing before launching
the target Proxy. It remains an unpromoted experiment: Stage 2 preflight and
runtime refusal stay in place until traffic, callback, journal attribution,
replay and HCAP promotion are verified.
The Proxy's NLM (RPC program 100021) ProtocolSchema has bounded XDR decoding,
and its optional route carries a distinct journal context marker without
changing legacy NFS records. Next, validate TCP 4045 through the pinned
experimental lane while preserving program/generation ownership across callbacks,
then validate NLM mutation, durable journal, crash-context window and
independent production/replay coverage. Pin the resulting Proxy build and
guest assets, run independent KVM gate/campaign/replay checks (including
blocked grants and async replies), and only then revise the HCAP and manager
allowlist. NFSv3 program 100003 support alone does not satisfy this
requirement.

An earlier disposable KASAN KVM smoke test in tools/test-nlm-relay-kvm.py
demonstrated a narrower result. With the opt-in lane and an activated NLMv4
LOCK rule, two clients contend on one NFSv3 file; the waiting client obtains
the lock after the first unlocks. Kernel tracepoints in the same run record
one nlmclnt_grant and SUNRPC GRANTED_MSG/GRANTED_RES requests. The host
journal re-admits two generation-1 NLM LOCK exposures that replace l_offset
0 with 1 and have FORWARD_COMPLETE, with no rejections or torn tail.

GRANTED_MSG travels on a separate client-facing path, not through the Proxy's
4045 listener. For diagnostic attribution, tools/nlm-pcap.c records server
network namespace traffic and tools/nlm_callback_attribution.py matches the
forwarded LOCK's XID and complete framed-message SHA-256 to the journal's
EXPOSURE_INTENT output. It then matches file handle, owner, svid and range
to the callback, requiring a unique candidate within the activation window.
Cookie and callback XID are not lock identities. In the successful KVM run,
one observed callback was matched to generation 1. In a second KVM run,
generation 1 was deactivated while the lock was pending; the later callback
was recorded as outside_activation_window with no assigned generation. Both
runs completed the blocked-grant sequence and had no journal rejections.
The diagnostic does not modify the production journal or Stage 2 verdict.
It reads only complete, single-segment TCP RPC records from classic Ethernet
pcap; missed or split records cannot establish callback absence. Raw pcap
and the detailed VM result stay local and must not be published to GitHub.
The proposed fail-closed normalized evidence contract and failure table live
in docs/design/decisions/2026-10-23-nlm-callback-attribution-contract.md.
Its implementation remains diagnostic-only and is not wired into Stage 2.

The host-side comparator in tools/nlm_callback_verify.py now re-admits the
sealed journal and checks each NLM LOCK EXPOSURE_INTENT against its same-session,
same-generation, same-batch FORWARD_COMPLETE, XID, framed output length and
SHA-256, and the observed backend endpoint. It records the re-admitted request
digest and counts raw
packet observations separately from distinct TCP sequence records. On the two
local KVM captures, it found exact backend LOCK bytes for two and one journal
anchors respectively; each backend record appeared twice at the same TCP
sequence. It reports callback key/endpoint candidate counts only, without
claiming ordering or ownership. The command is

    .venv/bin/python -m tools.nlm_callback_verify --journal <local-journal-dir> \
        --name smoke --pcap <local-pcap> --vm-instance-id <local-vm-id>

The resulting JSON is diagnostic_only. Classic pcap has no drop counters or
authenticated VM provenance, the parser skips split RPC records, and journal
sequence numbers cannot be ordered against packet timestamps. A duplicate
packet at one TCP sequence may also be a capture duplicate or retransmission.
These constraints keep capture_complete false and prevent using this output
as the normalized attribution contract's matched input. Keep raw outputs local.

For bounded TCP/RPC reconstruction, add --reassemble to that command. This
opt-in v2 diagnostic handles out-of-order segments, coalesced RPC records,
multiple RPC fragments, sequence wrap, and identical overlaps. It requires
an observed SYN to anchor a direction, refuses gaps or conflicting overlaps,
and reports missing closure, resets, and ambiguous connection reuse. It keeps
the original framed-byte digest rather than normalizing fragment markers.
Connection IDs distinguish local tuple reuse, not VM identity. Resource limits
and parse failures are explicit in reassembly; packet indices describe only
the local file. Even observed_streams_complete=true never makes
capture_complete true or assigns callback ownership. Older normal/late pcaps
that started after fixture setup lack connection boundaries, so this stricter
mode cannot re-confirm their LOCK anchors; their packet-byte smoke remains a
separate observation.

Use --capture-lifecycle with --packet-capture to instrument only the disposable
lane copy. The collector then starts after the server namespace is ready and
before client connectivity or NLM setup, and it remains alive while fixture
cleanup closes the other server-namespace processes. Cleanup validates the
collector network namespace, PID, and start time, then requests shutdown with
a stop file after the remaining server-namespace processes terminate. Other
namespace cleanup follows the normal path. The lifecycle requires socket
statistics plus a clean-exit marker written after pcap, statistics, and socket
closure, avoids a PID-reuse signal race, and refuses stale or partial lifecycle
state. Two earlier real KASAN KVM runs (normal and
deactivate-before-grant) completed the lock sequence and cleanup with clean
journals before that final marker hardening. Their socket statistics reported
1,628/0 and 1,708/0 packets/drops. Both reconstructed 26 directional streams
with no structural issue, one unique exact backend LOCK anchor, and one
unordered callback candidate.

The disposable lane also requires lockd-netlink-port and nlm-rpcbind-front.
The KVM image used for the latest diagnostic campaign predated those helpers.
The first attempts therefore stopped at command -v lockd-netlink-port; a later
/proc/<pid>/ns/net cleanup error was secondary, not a kernel crash or namespace
race. When --proxy replaces the guest binary, test-nlm-relay-kvm.py now
requires --lockd-port-helper and --rpcbind-front-helper together and installs
both into the disposable guest before boot-fixture.sh runs. This is a local
experiment prerequisite, not promotion of the baked guest dependency set.

The final hardened lifecycle was run in normal and
deactivate-before-grant controls with mutation offset 0. Both clients completed
LOCK and UNLOCK, cleanup returned success with every leak counter at zero, and
their socket statistics were 1,628/0 and 1,709/0 packets/drops. Each bounded
reconstruction again contained 26 issue-free directional streams, one unique
exact backend LOCK anchor, and one unordered callback candidate. The normal
callback matched generation 1 diagnostically; the callback after deactivation
remained outside_activation_window and unassigned. No KASAN, KCSAN, Oops,
panic, or
warning signature was observed.

Two consecutive final-lifecycle normal runs with mutation offset 1 did not
complete the waiting client's fcntl lock. Offline decoding of both pcaps found
one GRANTED_MSG and one logical GRANTED_RES observed at the relay and backend;
the response status was LCK_DENIED in both runs. The client kernel trace also
reported LCK_DENIED. Linux nlmclnt_grant matches file handle, owner, svid,
server address and lock range, so changing offset 0 to 1 deliberately breaks
the identity of the request awaited by the client. A later synchronous LOCK
retry can still complete fcntl, which is independent of callback acceptance.
The offset-1 case is therefore a negative identity control, not evidence of
route unreliability.

The positive mutation control replaces only the LOCK request cookie with a
same-length four-byte opaque literal. The initial request cookie is not part
of Linux's blocked-lock lookup or nlmclnt_grant identity, and the server
creates a separate cookie for GRANTED_MSG. A passing typed diagnostic requires
the changed request to be observed at the backend, one GRANTED_MSG, both the
client trace and GRANTED_RES to report LCK_GRANTED, and the waiting fcntl to
complete. Callback receipt, client acceptance, reply status and syscall
completion remain separate fields. Cookie bytes are not copied to the result;
raw journal and pcap data remain local. All outcomes remain diagnostic_only
and capture_complete=false: pcap order is not authenticated activation order,
VM provenance is not sealed, and zero socket drops cannot prove that no entire
flow was missed.

The helper-complete KASAN KVM campaign produced one offset negative control and
two typed cookie positive controls. The offset-1 run changed two forwarded
LOCKs, received GRANTED_MSG, and observed LCK_DENIED in both the client trace
and GRANTED_RES. Its waiting fcntl later completed, but the result deliberately
records the completion source as callback_or_later_retry_unresolved. The
capture reported 1,536 captured IPv4/TCP frames and 1,642 packets with zero
drops. In the cookie normal and deactivate-before-grant runs, one forwarded
LOCK changed, GRANTED_MSG arrived, both typed statuses were LCK_GRANTED, and
the waiting fcntl completed. The normal callback matched generation 1
diagnostically; the late callback was outside_activation_window with no
generation. Their captures reported 1,526 frames each and 1,635/0 and 1,627/0
packets/drops. All three journals had no rejection, fixture cleanup succeeded
with every leak counter at zero, and the consoles contained no KASAN, KCSAN,
Oops, panic, or warning signature. These remain diagnostic_only with
capture_complete=false.

For a single read-only verdict over the two local KVM smoke runs, run:

    .venv/bin/python -m tools.nlm_stage2_readiness \
        --normal /tmp/knfsd-nlm-cookie-positive-20261023-r1 \
        --late /tmp/knfsd-nlm-cookie-positive-late-20261023-r1 \
        --stage1 /tmp/knfsd-issue75-nlm-kvm-state-20261022/stage1.json

It re-admits both journals, compares LOCK bytes with both pcaps, checks the
completed blocked-grant observations and the in-window/late callback pair,
and reports input digests. New runs must provide the typed cookie-mutation
acceptance fields; old result files are labeled
historical_callback_observation and retain only their earlier, weaker
callback-observation meaning. Exit 2 means the smoke passed but Stage 2 remains
blocked; exit 1 means smoke failed. The JSON's separate stage2_ready field
remains false. The fixed blockers
name proof not established by this diagnostic workflow. The Stage 2 state
and HCAP-13 template are also checked for configuration and authority. This
command does not run gate/campaign/replay, infer callback ownership, or change
an approved harness. Keep the raw inputs local and do not publish them.
The typed cookie pair passes every smoke check and uses
typed_callback_acceptance for both inputs, but the command exits 2 with
stage2_ready=false. The remaining blockers are complete ordered VM-bound
callback capture, crash-context/remote-KCOV attribution, a restart
counterexample, promoted production Proxy and guest pins, an independent
Stage 2 gate/campaign/strict-replay run, a configured Stage 2 backend, and
HCAP-13 Stage 2 authority.

These checks do not establish a Stage 2 crash-context window, durable
callback attribution across a crash, independent production/replay coverage,
or an approved/pinned production build. Keep the nlm-knfsd Stage 2 preflight
and runtime refusal in place until those checks and HCAP promotion are complete.

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
