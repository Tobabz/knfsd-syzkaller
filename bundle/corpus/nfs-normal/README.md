# Normal NFS syzkaller corpus

This directory contains six parser-checked TCP inputs: one NFSv3, one NFSv4.0
and four NFSv4.1/4.2. The current
[flow scope and completion criteria](../../../report/normal-flow-corpus.md)
describe their targets and gaps. `manifest.json` records each seed's hash,
version, fixture, functional oracle and execution status.

The lane fixture provides four client mounts: `nfs-lane/client0` and
`client1` share the knfsd export, while `client0-ganesha` and
`client1-ganesha` share the separate Ganesha export. It runs four lanes,
so syz-manager uses `procs=4`. The image and host lane script are prepared
as described in the [root usage guide](../../../README.md#3-using-the-result-with-syz-manager).

Parsing a `.prog` proves only that syzkaller accepts its syntax. Functional
success, NFS traffic, thread handoffs and KCOV each require separate checks.

## Execution scope (2026-10-02)

Run knfsd and Ganesha as separate campaigns, one backend at a time. Each has
its own syz-manager config, workdir and `corpus.db`. Initialize a new DB from
only its backend's canonical 34-call seed; resume an existing DB without
repacking it. Do not merge these DBs, import the former combined corpus, or
connect the campaigns to a shared corpus hub.

| Backend | Initial seed | Client paths under `nfs-lane/` | `experimental.remote_cover` | Local HTTP endpoint |
| --- | --- | --- | --- | --- |
| knfsd | `basic-v41-tcp.prog` | `client0`, `client1` | `true` | `127.0.0.1:56753` |
| Ganesha | `basic-v41-ganesha-tcp.prog` | `client0-ganesha`, `client1-ganesha` | `false` | `127.0.0.1:56754` |

The current local campaigns are stored as:

```text
cache/manager-separated-v41-20261002/
+-- knfsd/
|   +-- manager.cfg
|   +-- inputs/basic-v41-tcp.prog
|   +-- workdir/corpus.db
|   +-- triage.log
+-- ganesha/
    +-- manager.cfg
    +-- inputs/basic-v41-ganesha-tcp.prog
    +-- workdir/corpus.db
    +-- triage.log
```

From the repository root, resume knfsd with:

```sh
env/syzkaller/bin/syz-manager -config cache/manager-separated-v41-20261002/knfsd/manager.cfg -mode fuzzing
```

Stop that manager and wait for shutdown before starting Ganesha:

```sh
env/syzkaller/bin/syz-manager -config cache/manager-separated-v41-20261002/ganesha/manager.cfg -mode fuzzing
```

Each local config uses `procs=4`, one KASAN VM with `vm.snapshot: true`, `cover=true`,
`cover_edges=true`, and `reproduce=false`. Enabled syscalls are
`open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`,
`statx`, `lseek`, `read`, `flock`, `renameat2`, and `unlinkat`.
Ganesha's current coverage feedback is from the local client kernel, not
Ganesha user-space code.

Snapshot mode runs one program at a time with one proc, so these campaigns
used lane 0 only and did not exercise parallel lanes. Lanes exist for
parallel fuzzing, which is required: set `vm.snapshot` to `false` for regular
campaigns. Four-lane parallel runs with this topology are not yet validated.

These validated configs pin the baked-script V15.6 v4.1 image
`env/images/bookworm-kcov-v41-ganesha-v15.6.qcow2`. For the reusable
`bookworm-kcov-fresh.qcow2` image, prepare each backend's config separately
with `tools/prepare-live-lane-config.py --version 4.1`, as described in the
[root usage guide](../../../README.md#3-using-the-result-with-syz-manager).
The helper preserves the workdir and coverage settings. Changing only the
image path is insufficient for the reusable image's host-script boot model.
The cache configs and DBs are local artifacts, not committed repository assets.

Both separate managers completed `corpus-triage` with exit 0 and are stopped
after validation. The saved DBs were unpacked and checked for backend path
literals:

| Saved corpus | Programs | Own backend path | Opposite backend path | Both backend paths | Neither expected path |
| --- | ---: | ---: | ---: | ---: | ---: |
| knfsd | 100 | 22 | 0 | 0 | 78 |
| Ganesha | 109 | 20 | 0 | 0 | 89 |

Evidence: `cache/manager-separated-v41-20261002/{knfsd,ganesha}/triage.log`,
the corresponding `triage-unpacked/` directories, and `maintenance.json`
in the campaign root. These are bounded corpus checks, not proof that every
program reaches NFS or that long runs retain this distribution.

Separate managers do not splice programs from each other's corpus. Ordinary
generation, path mutation and minimization remain enabled: calls or paths may
disappear, and another path can still be generated. The fixture still exposes
both backend mount pairs, so separation does not enforce backend-only execution.
An absent path literal alone does not prove that a program cannot reach NFS.
The two campaigns also do not produce identical mutations or paired replay.

Proxy-managed backend selection remains a future extension. The current
relay uses fixed backend paths.

## Intended scenarios -> corpus contract

Each scenario/backend pair has one `.prog`. The NFS version is selected
when the VM boots; the basic v4.1 fuzzing campaigns use the backend-specific
seed shown above.

| Input | Target | Functional oracle | Current verification limit |
| --- | --- | --- | --- |
| `basic-v41-tcp.prog` | knfsd v4.1/TCP, two clients | 34 calls; peer lock conflict at call 14 returns errno 11, other calls return 0; create/read/write/rename/unlink work across both mounts | One KASAN snapshot passed; knfsd remote `.extra` was nonempty. No request handoff trace. |
| `basic-v41-ganesha-tcp.prog` | Ganesha v4.1/TCP, two clients | Same 34-call errno and file-operation oracle | One KASAN snapshot passed; client-kernel KCOV was present. Ganesha user-space coverage was not collected. |
| `async-copy-v42-tcp.prog` | knfsd v4.2/TCP COPY | 11 calls, 32 MiB `copy_file_range` return and successful close/fsync | One KASAN snapshot passed with nonempty `.extra`. The current fixture has no direct callback or handoff trace for this run. |
| `delegation-recall-v41-tcp.prog` | knfsd v4.1/TCP delegation conflict | Delegation grant, ordered recall, client ACK and return | One KASAN execution on 2026-10-05; the recall and return chain over the session backchannel was observed in trace events (S3b in the thread report). |
| `basic-v3-tcp.prog` | knfsd v3/TCP, two clients | 25 calls, all errno 0. No `flock`: the v3 mounts use `nolock`, so `flock` is client-local and no peer conflict occurs. | One KASAN execution on 2026-10-05 completed 25 calls. Thread transitions S1-01 to S1-11 were observed. NLM locking is not reached (`nolock`, no `rpc.statd`). |
| `deleg-recall-v40-tcp.prog` | knfsd v4.0/TCP delegation conflict | 16 calls, all errno 0. Client0 opens read-only; client1 opens for write and its first OPEN is delayed (`NFS4ERR_DELAY`) until the recall completes. | One KASAN execution on 2026-10-05 completed 16 calls. Thread transitions S2-01 to S2-13 were observed, including the separate callback connection. |

Thread transitions are judged from kernel trace events, not from PCs. The rules, the
judge and the recorded evidence are described in the
[thread-transition report](../../../report/normal-flow-threads.md); the tools are in
`tools/flow-trace/`.

## Parser and measurement limits

The parser command is:

```sh
env/syzkaller/bin/syz-prog2c -os linux -arch amd64 -prog ABSOLUTE_INPUT_PATH
```

The parser binary hash and seed hashes are in `manifest.json`. A parser
pass does not prove a VM execution. A nonempty `.extra` demonstrates collected
kernel coverage; it does not identify every RPC or prove a cross-thread
handoff. Ganesha user-space coverage requires a different feedback channel.

The [flow scope](../../../report/normal-flow-corpus.md) lists the state of each
flow. The periodic and state-lifetime work (NF-B2, NF-E1–E4) is judged with the
shell script `tools/flow-trace/stimulus/s4-state-lifetime.sh`, not with a seed:
the enabled syscalls have no `nanosleep`, and the client renews its lease
automatically. NLM locking (NF-G2) is judged with the shell scripts S5 and S5b: the lane mounts use nolock, so a seed cannot reach it. NF-E5 is not reached. NFSv2, UDP, RPC-over-RDMA,
LOCALIO and NAT remain outside the verified execution scope.
