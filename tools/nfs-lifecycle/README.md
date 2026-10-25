# Versioned NFS lifecycle scenarios

Lifecycle scenarios are timed fixture tests, not syzkaller corpus programs.
They deliberately wait for lease expiry or restart the server, so putting them
in `corpus.db` would stall ordinary mutation throughput.

The runner provides these native-version scenarios:

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
