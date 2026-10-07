# Normal-scenario NFS mutation corpus

This directory contains 12 canonical syzkaller programs. They are valid NFS
scenarios chosen as starting points for mutation; they are not a validation-only
suite. `manifest.json` schema 3 records each seed's native backend/version
profile, hash, call count, capabilities, functional oracle, and evidence limit.

## Stable profiles

Stable campaigns use only the seeds native to one profile. A higher NFS version
does not automatically inherit lower-version seeds: protocol negotiation, state
machines, callbacks, and operation availability differ even where user-visible
file operations are compatible.

| Profile | Backend/version | Seeds |
| --- | --- | ---: |
| `knfsd-v3` | knfsd NFSv3 | 3 |
| `knfsd-v40` | knfsd NFSv4.0 | 2 |
| `knfsd-v41` | knfsd NFSv4.1 | 3 |
| `knfsd-v42` | knfsd NFSv4.2 | 3 |
| `ganesha-v41` | Ganesha NFSv4.1 | 1 |

Mount-based seeds use `syz_open_nfs_lane_profile`; the profile is therefore an
explicit, immutable syscall argument rather than a mutable path string. The raw
NFSv3 duplicate-request seed uses `syz_socket_connect_nfs` because it sends its
own RPC records rather than opening a mounted directory.

Build a fresh profile DB (the output and its JSON sidecar must not exist):

```sh
tools/build-normal-corpus.py /tmp/knfsd-v42/corpus.db \
  --profile knfsd-v42
```

The builder validates manifest hashes, packs with `syz-db`, unpacks the result,
runs `syz-db bench`, and writes `corpus.db.json` with the exact selected inputs
and tool/database hashes. Generated DBs remain local artifacts and must not be
shared between stable profiles.

## Experimental broad fixture

`broad-knfsd` mounts NFSv3, v4.0, v4.1, and v4.2 simultaneously for both
clients. It includes all 11 knfsd seeds and excludes Ganesha:

```sh
tools/prepare-live-lane-config.py manager.cfg manager-broad.cfg \
  --broad-knfsd
tools/build-normal-corpus.py /tmp/broad-knfsd/corpus.db \
  --fixture broad-knfsd
```

This is a screening experiment, initially for 30 minutes. It does not replace
the stable version-specific campaigns and cannot be promoted automatically.
Compare execution rate, signal growth, NFS-reaching program retention, and
timeouts against the sum of the four stable knfsd campaigns before deciding
whether to continue it. The first bounded result is recorded in
[`docs/experiments/2026-10-07-broad-knfsd-screening.md`](../../../docs/experiments/2026-10-07-broad-knfsd-screening.md).

## Lifecycle boundary

Lease expiry and server restart require deliberate waiting or fixture control,
so they are not corpus programs. Use `tools/nfs-lifecycle/run.py` for the native
v4.0 lease-expiry scenario and the v4.1/v4.2 control-restart scenarios. Repeated
runs measure asynchronous stability; a repeat count is not part of the seed's
meaning.

Parsing a `.prog` proves only syntax acceptance. The manifest's oracle and
evidence fields distinguish expected behavior from what prior bounded runs
actually established. pNFS, LOCALIO, NFSv3 NLM, NFSv2, UDP, and RDMA remain out
of scope for this corpus milestone.
