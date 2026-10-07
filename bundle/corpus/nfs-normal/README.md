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

`prepare-live-lane-config.py --profile PROFILE` narrows `enable_syscalls` to
the two exact `client0`/`client1` variants for that profile. Use a fresh workdir
when changing profiles: syz-manager can retain old corpus entries even after a
syscall is removed from the enabled set.
The unversioned raw NFS socket calls remain enabled only in `knfsd-v3` and
`broad-knfsd`; enabling them in a v4-only profile would allow raw NFSv3-shaped
programs to cross the version boundary.

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
The broad runtime deliberately permits programs containing more than one of
the four knfsd profile roots. Such mixed-profile programs are part of the
topology experiment, but they are not eligible for a stable corpus.
The first bounded result is recorded in
[`docs/experiments/2026-10-07-broad-knfsd-screening.md`](../../../docs/experiments/2026-10-07-broad-knfsd-screening.md).
An equal 30-minute, 4-VM/16-proc comparison found 6.39% more combined
`fs/nfsd` + `net/sunrpc` PCs but 14.25% fewer executions than the union of four
stable campaigns. Broad therefore continues as a coverage-discovery adjunct,
not the default; see
[`docs/experiments/2026-10-07-broad-vs-stable-equal-budget.md`](../../../docs/experiments/2026-10-07-broad-vs-stable-equal-budget.md).

## Broad-to-stable promotion gate

A broad result is only a candidate until it has an NFS root, contains exactly
one profile (with no raw/profile hybrid), and completes in that profile's
single-version fixture. Raw-only RPC candidates are restricted to `knfsd-v3`.
Programs with no NFS root, mixed profiles, a Ganesha root, or missing/failed
matching replay evidence must not be added to the canonical corpus.

Record replay evidence as JSON and audit the candidate before copying it into
this directory or editing `manifest.json`:

```json
{
  "schema": 1,
  "fixture": "single",
  "profile": "knfsd-v41",
  "results": [
    {"sha256": "<candidate-sha256>", "passed": true, "runs": 1}
  ]
}
```

```sh
tools/audit-normal-corpus.py candidate.prog \
  --promotion-profile knfsd-v41 --replay-evidence replay.json
```

To report the composition of a live broad DB without making a promotion
decision, use:

```sh
tools/audit-normal-corpus.py workdir/corpus.db --fixture broad-knfsd \
  --syz-db env/syzkaller/bin/syz-db --output broad-audit.json
```

Add `--strict-runtime` when every inspected program must retain an allowed NFS
root. Runtime audit failure is a measurement result; it does not by itself make
the broad experiment a stable corpus.

Use `--profile PROFILE --strict-runtime` for the equivalent stable-runtime
audit. This checks root/profile admission but does not claim that a newly found
program passed its functional oracle; `--promotion-profile` remains the only
mode that consumes replay evidence.

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
