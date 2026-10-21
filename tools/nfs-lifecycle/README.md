# Versioned NFS lifecycle scenarios

Lifecycle scenarios are timed fixture tests, not syzkaller corpus programs.
They deliberately wait for lease expiry or restart the server, so putting them
in `corpus.db` would stall ordinary mutation throughput.

The runner provides four native-version scenarios:

- `v40-lease-expiry`: create and unmount a temporary v4.0 client, then require
  `confirmed -> expired -> purged` for that client.
- `v41-control-restart`: stop/start knfsd, require the grace transition and
  successful v4.1 I/O after restart.
- `v41-client-expiry`: run a neutral NFSv4.1 I/O control first, then ask the
  bounded fixture broker to expire exactly lane 0 client 0 and require
  `admin_expired -> EXCHANGE_ID -> CREATE_SESSION` recovery. Each run must
  publish one settled remote-KCOV generation; controls must miss all supplied
  target PCs and every stimulus must hit at least one. The fixed programs in
  `programs/` differ only by `syz_nfsd_client_ctl$expire_client0` and remain
  validation inputs rather than mutation seeds.
- `v41-cld-lifecycle`: the HCAP-12 campaign. It runs four fixed programs in
  order, each `--repeat` times (at least 3): the neutral control, scenario A
  (`normal`: expiry then client0 recovery), scenario C (`reconnect`: expiry,
  one `syz_nfsd_cld_ctl$reconnect`, then recovery) and scenario B
  (`daemon_down`: expiry, nfsdcld held down past the 30 s upcall timeout, then
  recovery; fixture evidence only, never an admitted call). See below.
  `daemon_down` runs with `syz-execprog -program-timeout=90s` (syzkaller
  0029): the slowdown-derived budget stops at 15 s, before the upcall times
  out. A program that still exports `.meta` without `.extra` fails as an
  `execution:` error naming its unfinished calls, never as a probe miss.
- `v42-control-restart`: the same restart contract using a native v4.2 mount.

Run one iteration first:

```sh
tools/nfs-lifecycle/run.py \
  --scenario v40-lease-expiry \
  --output /tmp/nfs-lifecycle-v40
```

`--repeat 30` is available for variance measurement. A repeat count is evidence
about asynchronous stability; it does not change a scenario into a corpus seed
and is not the default acceptance policy.

The client-expiry scenario additionally needs one generated Stage1 collector
configuration, its exact execution descriptor and a verified target-PC mapping
with the same complete kernel identity:

```sh
tools/nfs-lifecycle/run.py \
  --scenario v41-client-expiry \
  --repeat 3 \
  --collector-config /path/to/stage1-state/collector.json \
  --descriptor /path/to/run/input/descriptor.json \
  --target-pcs /path/to/mapping-job.json \
  --output /tmp/nfs-v41-client-expiry
```

The runner verifies every pinned kernel, image, lane and syzkaller artifact
before boot and refuses a mapping from another execution harness. Its
shareable `result.json` contains identity/evidence digests and hit counts, not
candidate source metadata or target addresses. Per-run local files retain the
trace, lifecycle broker audit line, executor log, raw coverage, metadata,
generation counters and pre-window generation state, including on executor or
coverage-cardinality failures.

## nfsdcld/rpc_pipefs campaign (HCAP-12)

```sh
tools/nfs-lifecycle/run.py \
  --scenario v41-cld-lifecycle \
  --repeat 3 \
  --collector-config /path/to/stage1-state/collector.json \
  --descriptor /path/to/descriptor.json \
  --kernel-source env/linux \
  --output /tmp/nfs-v41-cld-lifecycle
```

The descriptor must expose the runtime selection that enables
`syz_nfsd_cld_ctl$reconnect`. No candidate mapping is used: before boot the
runner maps three public probes from the descriptor's kernel commit
(`--kernel-source` is a git tree that has it) to coverage call sites of the
pinned vmlinux:

| probe | source |
|---|---|
| `cld_create` | `nfsd4_cld_create` and `nfsd4_cld_create_v2` |
| `cld_create_error` | the error report after `out_err:` in both |
| `pipe_wait_for_open` | the no-reader `RPC_PIPE_WAIT_FOR_OPEN` branch of `rpc_queue_upcall` |

Every run waits for the broker to be idle, executes one gated program, waits
for the broker again and requires `lane.sh status` to pass. A broker that
failed, refused or replaced the wrong transaction, or a failed lane status, is
reported as a `fixture:` error and invalidates the campaign. It is never
turned into a probe miss. A run outside the validated behavior also fails the
campaign: a control that reaches a probe, a normal run that requeues without a
reader, or a reconnect run that misses the requeue. The OP_RECLAIM_COMPLETE
trace count and the create-failure dmesg count are recorded as diagnostics
only.

On success the output holds `result.json` (counts and digests only),
`hcap12-kvm.json` (typed `Hcap12KvmEvidence` bound to the harness and
`result.json`), `probe-*.json` (public probe ranges and call sites) and the
raw per-run artifacts, including each run's `cld.state` and dmesg.
