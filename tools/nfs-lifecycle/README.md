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

The client-expiry scenario additionally needs the patched syzkaller binaries
and a verified target-PC mapping:

```sh
tools/nfs-lifecycle/run.py \
  --scenario v41-client-expiry \
  --repeat 3 \
  --syzkaller env/syzkaller \
  --target-pcs /path/to/mapping-job.json \
  --output /tmp/nfs-v41-client-expiry
```

Its output keeps the trace, lifecycle broker audit line, executor log, remote
coverage, metadata, generation counters and pre-window generation state for
every control and stimulus execution.
