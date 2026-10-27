# Versioned NFS lifecycle scenarios

Lifecycle scenarios are timed fixture tests, not syzkaller corpus programs.
They deliberately wait for lease expiry or restart the server, so putting them
in `corpus.db` would stall ordinary mutation throughput.

The runner provides these native-version scenarios:

- `v40-lease-expiry`: create and unmount a temporary v4.0 client, then require
  `confirmed -> expired -> purged` for that client.
- `v41-control-restart`: stop/start knfsd, require the grace transition and
  successful v4.1 I/O after restart.
- `v41-courtesy-expiry`: the HCAP-11 campaign. See below.
- `v42-control-restart`: the same restart contract using a native v4.2 mount.
- `v3-nlm-lock`: the HCAP-13 campaign on the `nlm-knfsd` NFSv3 fixture. It
  runs four fixed programs (`v3-nlm-{control,lock,rpc,blocked}.prog`), each
  `--repeat` times (at least 3). See below.

Run one iteration first:

```sh
tools/nfs-lifecycle/run.py \
  --scenario v40-lease-expiry \
  --output /tmp/nfs-lifecycle-v40
```

`--repeat 30` is available for variance measurement. A repeat count is evidence
about asynchronous stability; it does not change a scenario into a corpus seed
and is not the default acceptance policy.

## Courtesy client expiry campaign (HCAP-11)

```sh
tools/nfs-lifecycle/run.py \
  --scenario v41-courtesy-expiry \
  --repeat 3 \
  --collector-config /path/to/stage1-state/collector.json \
  --descriptor /path/to/descriptor.json \
  --kernel-source env/linux \
  --output /tmp/nfs-v41-courtesy-expiry
```

Every trigger is an NFS client action. `programs/v41-courtesy-expiry.prog`
creates `lock0` read-write from client0, which gets it a write delegation,
then `syz_nfs_lane_link$partition_client0` (syzkaller patch 0032) gives
client0's only link in its own lane network namespace a blackhole root qdisc
for 15 s, past the 10 s lease: the link stays up with its addresses and
routes, and everything client0 sends is silently dropped. The courteous
server keeps the lapsed client as a courtesy client. client1 then opens
`lock0`; the delegation recall finds the courtesy client0 and the server
expires it to grant the open. `syz_nfs_lane_link$heal_client0` deletes the
qdisc and client0's `statx`/`getdents64` drive its recovery with a new
clientid. client0 unlinks `lock0` at the end: knfsd gives no delegation on a
file whose delegation it recalled in the last 30 to 60 s, so each run must
create its `lock0` afresh (mode 0x2 opens with `O_CREAT`), or it finds no
delegation and no conflict. The neutral control
(`programs/v41-client-io-control.prog`) is client0 lane I/O only. The fork
server deletes the qdisc after every program.

The descriptor must expose the `knfsd-v41` single runtime selection with the
partition and heal calls. The stimulus runs with a raised syzkaller program
budget (`-program-timeout`, 90 s scaled by min(slowdown, 3)), the same one
the Stage 1 collector gives any partitioning program. Before boot the runner
maps three public probes from the descriptor's kernel commit to coverage call
sites of the pinned vmlinux:

| probe | source | runs in |
|---|---|---|
| `break_deleg` | `nfsd_break_deleg_cb` | client1's OPEN |
| `exchange_id` | `nfsd4_exchange_id` | client0's recovery |
| `create_session` | `nfsd4_create_session` | client0's recovery |

Each run must publish one settled remote-KCOV generation; the control must
miss every probe and every stimulus must hit all three. The stimulus trace
must read `nfsd_cb_recall -> nfsd_mark_client_expired -> nfsd_clid_purged ->`
client1 `OP_OPEN` granted `-> nfsd_clid_fresh -> OP_EXCHANGE_ID ->
nfsd_slot_seqid_unconf -> nfsd_clid_confirmed -> OP_CREATE_SESSION` with a
new clientid, and neither phase may touch the lifecycle broker. After every
run `lane.sh status` must report the single fixture and dmesg must hold no
crash. On success the output holds `result.json`, `hcap11-kvm.json` (typed
`Hcap11KvmEvidence`), `probe-*.json` and the raw per-run artifacts.

The runner verifies every pinned kernel, image, lane and syzkaller artifact
before boot. Its shareable `result.json` contains identity/evidence digests
and hit counts, not target addresses. Per-run local files retain the trace,
executor log, raw coverage, metadata, generation counters and pre-window
generation state, including on executor or coverage-cardinality failures.

The first HCAP-11 asked the fixture broker to write `expire` to the server's
`/proc/fs/nfsd/clients/<id>/ctl`. That is not an NFS client action, so the
`v41-client-expiry` campaign was replaced (#96); the
`syz_nfsd_client_ctl` executor call and the broker stay for fixture work.

The former `v41-cld-lifecycle` campaign (HCAP-12) was removed with that
capability (#98): it stopped and restarted the server's nfsdcld, which no NFS
client can do. The `syz_nfsd_cld_ctl` executor call and the nfsdcld broker stay
for fixture work.

## NLM lockd campaign (HCAP-13)

```sh
tools/nfs-lifecycle/run.py \
  --scenario v3-nlm-lock \
  --repeat 3 \
  --collector-config /path/to/stage1-state/collector.json \
  --descriptor /path/to/descriptor.json \
  --kernel-source env/linux \
  --output /tmp/nfs-v3-nlm-lock
```

The descriptor must expose the `knfsd-v3` / `nfs_version 3` / `nlm-knfsd`
runtime selection; the guest boots with `koov.nfs_fixture=nlm-knfsd` and the
runner requires `lane.sh status` to report that fixture before and after every
run. Before boot it maps public lockd probes from the descriptor's kernel
commit to coverage call sites of the pinned vmlinux:

| probe | source | use |
|---|---|---|
| `svc_lock` | `nlmsvc_lock` | required |
| `svc_unlock` | `nlmsvc_unlock` | required |
| `svc_testlock` | `nlmsvc_testlock` | required |
| `svc_share` | `nlmsvc_share_file` | required |
| `clnt_grant` | `nlmclnt_grant` | required |
| `svc_grant_blocked` | `nlmsvc_grant_blocked` | required |
| `svc_grant_callback` | `nlmsvc_grant_callback` | required |
| `svc_grant_reply` | `nlmsvc_grant_reply` | diagnostic |

| phase | program | must reach in every run |
|---|---|---|
| `control` | lane `getdents64` only | no lockd probe |
| `lock` | kernel client F_SETLK, F_GETLK, unlock on `lock0` | `svc_lock`, `svc_unlock`; never `clnt_grant`, `svc_grant_blocked` or `svc_grant_callback` |
| `rpc` | raw NLMv4 LOCK, TEST, UNLOCK, SHARE, UNSHARE on `lock1` | `svc_lock`, `svc_unlock`, `svc_testlock`, `svc_share` |
| `blocked` | client1 locks `lock2`; client0 raw blocking LOCK; client1 unlocks; 1 s sleep; raw CANCEL and UNLOCK | `svc_lock`, `svc_unlock`, `clnt_grant`, `svc_grant_blocked`, `svc_grant_callback` |

`clnt_grant` is the client0 lockd serving the server's GRANTED_MSG callback.
The grant itself runs in the server lockd thread (`svc_grant_blocked`) and
the callback's completion in rpciod (`svc_grant_callback`); kernel patch 0006
attributes both to the program whose LOCK created the block (context
`lockd`). On success the
output holds `result.json`, `hcap13-kvm.json` (typed `Hcap13KvmEvidence`),
`probe-*.json` and the raw per-run artifacts, including each run's dmesg.
