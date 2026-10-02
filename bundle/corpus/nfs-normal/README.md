# Normal NFS syzkaller corpus

This directory contains four parser-checked NFSv4/TCP inputs. The current
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

Each local config uses `procs=4`, one KASAN VM snapshot, `cover=true`,
`cover_edges=true`, and `reproduce=false`. Enabled syscalls are
`open$dir`, `openat`, `getdents64`, `close`, `write`, `fsync`,
`statx`, `lseek`, `read`, `flock`, `renameat2`, and `unlinkat`.
Ganesha's current coverage feedback is from the local client kernel, not
Ganesha user-space code.

These validated configs pin the baked-script V15.6 v4.1 image
`env/images/bookworm-kcov-v41-ganesha-v15.6.qcow2`. For the reusable
`bookworm-kcov-fresh.qcow2` image, prepare each backend's config separately
with `tools/prepare-live-lane-config.py --minor 1`, as described in the
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
| `delegation-recall-v41-tcp.prog` | knfsd v4.1/TCP delegation conflict | Delegation grant, ordered recall, client ACK and return | Input is present; the full callback/backchannel chain has not been revalidated with the current fixture. |

## Parser and measurement limits

The parser command is:

```sh
env/syzkaller/bin/syz-prog2c -os linux -arch amd64 -prog ABSOLUTE_INPUT_PATH
```

The parser binary hash and seed hashes are in `manifest.json`. A parser
pass does not prove a VM execution. A nonempty `.extra` demonstrates collected
kernel coverage; it does not identify every RPC or prove a cross-thread
handoff. Ganesha user-space coverage requires a different feedback channel.

The [flow scope](../../../report/normal-flow-corpus.md) lists NF-B1/B2 and
NF-E1–E5 as missing an input or event-bound fixture. The current lane fixture
passed basic mounts and cross-client reads/writes for NFSv3 and NFSv4.0, but
their normal-flow seeds and oracles are not included in this corpus. NFSv2,
UDP, RPC-over-RDMA, LOCALIO and NAT remain outside the verified execution scope.
