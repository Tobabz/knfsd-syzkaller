# Versioned NFS lifecycle scenarios

Lifecycle scenarios are timed fixture tests, not syzkaller corpus programs.
They deliberately wait for lease expiry or restart the server, so putting them
in `corpus.db` would stall ordinary mutation throughput.

The runner provides three native-version scenarios:

- `v40-lease-expiry`: create and unmount a temporary v4.0 client, then require
  `confirmed -> expired -> purged` for that client.
- `v41-control-restart`: stop/start knfsd, require the grace transition and
  successful v4.1 I/O after restart.
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
