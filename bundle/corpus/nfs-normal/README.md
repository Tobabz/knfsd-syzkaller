# Normal NFS syzkaller corpus

This directory contains normal-flow TCP inputs for NFSv3, v4.0, v4.1 and v4.2.
[manifest.json](manifest.json) identifies each seed's version, backend, fixture,
functional oracle and content hash.

The lane fixture provides four client mounts: `nfs-lane/client0` and `client1`
share the knfsd export, while `client0-ganesha` and `client1-ganesha` share the
separate Ganesha export. Prepare the image and host lane script using the
[root usage guide](../../../README.md#3-using-the-result-with-syz-manager).

## Campaign setup

Run knfsd and Ganesha as separate campaigns, one backend at a time. Each has
its own manager config, HTTP endpoint, workdir and `corpus.db`. Initialize a
new DB with its backend's basic seed and preserve the DB when resuming.
Keep the DBs separate and do not connect the campaigns to a shared corpus hub.

| Backend | Initial seed | Client paths under `nfs-lane/` | `experimental.remote_cover` |
| --- | --- | --- | --- |
| knfsd | `basic-v41-tcp.prog` | `client0`, `client1` | `true` |
| Ganesha | `basic-v41-ganesha-tcp.prog` | `client0-ganesha`, `client1-ganesha` | `false` |

Set `procs` to the fixture's lane count and top-level `snapshot` to `false`
(or omit it) for parallel execution. `vm.snapshot` controls temporary disk
writes independently and defaults to `true`.

Separate managers keep their input corpora apart. Ordinary program generation,
path mutation and minimization remain enabled, and the fixture exposes both
backend mount pairs. Corpus separation does not restrict execution to one backend
or provide identical mutations and paired replay. The proxy-based
[NFS-specific Mutation Engine](../../../tools/nfs-proxy/README.md) uses fixed backend paths.

## Seeds

Select the NFS version when the VM boots and choose a seed for that version
and backend. Exact expected results and hashes are defined in [manifest.json](manifest.json).

| Input | Target | Scenario |
| --- | --- | --- |
| `basic-v41-tcp.prog` | knfsd v4.1/TCP, two clients | File operations and peer lock conflict |
| `basic-v41-ganesha-tcp.prog` | Ganesha v4.1/TCP, two clients | File operations and peer lock conflict |
| `async-copy-v42-tcp.prog` | knfsd v4.2/TCP | Asynchronous COPY |
| `delegation-recall-v41-tcp.prog` | knfsd v4.1/TCP | Delegation recall through the session backchannel |
| `basic-v3-tcp.prog` | knfsd v3/TCP, two clients | File operations on the `nolock` mounts |
| `deleg-recall-v40-tcp.prog` | knfsd v4.0/TCP | Delegation conflict and recall through a separate callback connection |

## Parsing and tracing

Check a seed's syntax with the syzkaller parser built by bootstrap:

```sh
env/syzkaller/bin/syz-prog2c -os linux -arch amd64 -prog ABSOLUTE_INPUT_PATH
```

Parsing checks syntax. A nonempty `.extra` contains kernel coverage and does
not identify every RPC or establish a cross-thread handoff. Ganesha feedback
comes from the client kernel; it does not measure the user-space server.
[flow-trace](../../../tools/flow-trace/README.md) provides event-based transition analysis.

The NFSv3 lane mounts use `nolock`, so file locks are client-local.
The S5/S5b tracing scripts use a separate loopback configuration for NLM/NSM.
The state-lifetime script exercises periodic work outside the seed programs.

## Related documents

- [Normal-flow scope](../../../report/normal-flow-corpus.md)
- [Execution and validation history](../../../report/validation-history.md)
