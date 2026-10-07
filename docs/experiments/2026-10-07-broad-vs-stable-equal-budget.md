# broad-knfsd versus stable profiles: equal-budget A/B

Date: 2026-10-07

## Question and controls

This experiment asks whether the experimental four-version `broad-knfsd`
fixture is an efficient replacement for four version-specific knfsd campaigns.
It is not a functional seed-validation run and does not promote any generated
program.

Both arms used the same v7.3-rc5 KASAN kernel, syzkaller build, qcow2 image
(SHA-256 `109e8f0212ddf5cc3aee3c4bd202cea4b5aad8c08319f1e6db092bfa345e4ea7`),
11 canonical knfsd mutation seeds, 4 VMs, 16 vCPUs, 16 executor procs, remote
coverage, edge coverage, and 30 minutes after machine check. The legacy public
broad run and one unrelated long-lived 4-vCPU VM remained active during both
sequential arms, so host contention was held approximately constant.

- Broad: one manager, four VMs, four procs per VM, eight exact knfsd profile
  constructors, and raw NFS enabled for its v3 seed.
- Stable: four managers in parallel, one VM and four procs each, one native
  profile and native seed DB per manager. Raw NFS was enabled only for
  `knfsd-v3`.

Coverage comparisons use the union of raw PCs, not the sum of per-manager
coverage counters. Corpus composition comes from `audit-normal-corpus.py`.
The live DB was sampled after coverage collection, so corpus size is a few
seconds later than the metric snapshot.

## Configuration corrections exercised

The original generic profile name enabled all ten variants, including Ganesha
variants absent from broad. The corrected broad config enabled the eight knfsd
variants and produced zero Ganesha-profile programs. Stable configs enabled
only two client variants for their selected profile.

An initial five-minute stable preflight also found one raw-only program in the
v4.2 DB because the unversioned raw socket root was still enabled. That
preflight was discarded. The config generator was tightened and the measured
stable arm was restarted from fresh DBs; all three v4 managers then exposed
zero raw socket constructors.

## Operational observations before comparison

The corrected broad arm completed its bounded run with zero crashes and all
four fixtures healthy. Its VMs nevertheless recorded 43, 46, 51, and 57
`nfs4_schedule_state_manager: kthread_run` failures. The older generic-variant
public run later produced three `SYZFAIL: NFS fuzz lane executor hung` reports
(`EAGAIN`, `EAGAIN`, and `EBADF`) without KASAN, oops, or panic output. These
are fixture-health failures, not kernel-crash findings.

The stable v4.0, v4.1, and v4.2 fixtures passed their final four-lane status
checks. The v3 status command initially stopped at its `tcp_connections >= 4`
assertion even though both backend mounts for both clients were present in all
four lanes with the expected NFSv3 source and options. Each lane retained the two actively fuzzed
knfsd transports; Ganesha had reclaimed its two idle NFSv3 transports. The
status check now requires two persistent transports for v3, continues to
require four for v4, and still validates every knfsd and Ganesha mount/source.

## Results

| Measure | broad-knfsd | four stable profiles | Broad delta |
| --- | ---: | ---: | ---: |
| Executions | 132,439 | 154,439 | -14.25% |
| All raw coverage PCs (union) | 25,202 | 23,410 | +7.65% |
| `fs/nfsd` PCs (union) | 3,295 | 3,121 | +5.58% |
| `net/sunrpc` PCs (union) | 984 | 901 | +9.21% |
| Combined server PCs | 4,279 | 4,022 | +6.39% |
| Crashes | 0 | 0 | -- |

The server-PC intersection was 3,092 in `fs/nfsd` and 879 in `net/sunrpc`.
Broad contributed 203 and 105 unique PCs in those trees; stable contributed 29
and 22. Thus the broad result is not just the sum of noisy per-manager counters:
under this one equal-budget run it reached more server code despite executing
fewer programs.

The final broad DB contained 576 programs: 486 retained an admitted NFS root,
90 had no NFS root, 40 mixed profiles, and 12 mixed a profile root with a raw
root. Its profile occurrence counts were v3 115, v4.0 127, v4.1 89, and v4.2
182. The stable DBs contained 891 programs in total: 676 retained their native
NFS root, 215 had no NFS root, and none crossed profiles or violated the raw
policy. Only v3 contained raw-only programs (20).

No arm produced KASAN, oops, panic, or syz-manager crash records during the
bounded interval. The four stable dmesg snapshots also had no lost-lock or
state-manager-start failures. Broad's state-manager-start failures and the
legacy run's later executor hangs remain operational costs that the PC result
does not erase.

## Decision

`broad-knfsd` is valid as an experimental coverage-discovery campaign and is
worth continuing: this run found 308 server PCs not found by the stable union.
It is not a replacement for stable profiles. It has lower throughput,
background renewal/session traffic, uneven profile selection, mixed-profile
programs that cannot be attributed to one protocol version, and a weaker
long-run fixture-health record.

Keep profile-specific fixtures as the default mutation and regression lanes.
Run broad as an adjunct, audit its DB, and promote only a single-profile
candidate that passes replay in the matching stable fixture. One 30-minute
pair establishes feasibility, not statistical superiority; repeat equal-budget
runs before making a capacity-allocation decision.
