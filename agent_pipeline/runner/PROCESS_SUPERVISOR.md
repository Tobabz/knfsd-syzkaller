# Lease-aware local process supervisor

`process_supervisor.py` implements a host process primitive without changing
`WorkLease`, `LeaseControl`, Runner completion, or evidence contracts. A concrete
execution engine may use its bounded stdout/stderr result, but must still create
host execution facts, seal evidence, and let the Runner fence publication. This
module does not launch a VM or create a Judge verdict.

```python
from pathlib import Path
from agent_pipeline.runner.process_supervisor import (
    HostCommand, ProcessLimits, ProcessSupervisor,
)

supervisor = ProcessSupervisor(Path("/var/lib/runner/process-ownership"))
result = supervisor.run(
    HostCommand(
        argv=("/opt/runner/bin/capture", "--lane", "1"),
        cwd=Path("/var/lib/runner/lane-1"),
        env={"LANG": "C.UTF-8"},
    ),
    lease,
    control,
    resource_key="host-a/lane-1",
    limits=ProcessLimits(timeout_s=60, max_output_bytes=1_048_576),
)
```

The host owns the command, absolute executable, working directory, environment,
resource key and limits. Do not build these from candidate/model output. No
shell is inserted, stdin is closed, and the caller environment is not inherited.
Invoking an interpreter or script is an explicit host trust decision. The command
configuration is bounded to 48 KB; combined captured stdout/stderr is capped by
`max_output_bytes`. Once the cap is exceeded, the process is stopped while pipes
continue to drain without retaining additional bytes.

## Resource ownership and restart

All callers for the **same physical host resource** must use the same persistent
state directory and exact resource key, independent of task, worker, lease token
or generation. Separate keys are safe only for genuinely independent resources.
This is a host-local advisory lock; it does not coordinate different machines.
The state directory must be owned by the Runner uid with mode 0700, on a local
filesystem supporting `flock`, atomic rename and durable `fsync`. Ancestors,
helper/interpreter files and mount namespace must be trusted. Do not delete,
replace, edit or restore an old copy of active ownership files or lock inodes.

The caller locks the resource before writing an admission tombstone and a
`reserved` record. It passes the *same open lock description* to a standalone
guardian. The guardian records `active` durably **before** spawning the payload.
Thus parent death between spawn and record cannot free a living guardian's lock;
guardian death in that window leaves an unclean record that refuses replacement.
The guardian channel (socketpair and selector) is allocated before the
admission records are written, so descriptor exhaustion there changes no state.
If writing the records fails (including the directory sync after `reserved`
is in place), the supervisor closes the channel and records `clean`.
A later failure before `active` (guardian spawn, a missing kernel interface, a
lost configuration) records `clean` with `spawn_failed` or `guardian_failed`
instead; the supervisor closes its channel first so the record write has a
descriptor. The payload starts only after `active`, so a `reserved` record
under the held lock proves nothing ran.
The payload does not inherit either the lock descriptor or control socket.

The guardian uses Linux `PR_SET_CHILD_SUBREAPER`. It terminates and reaps its
direct children, including adopted grandchildren, with pidfds; it never signals
a numeric PID from a prior record. A normally exited process can leave a child
holding output pipes: that child is also terminated and reaped before success.
Tests also cover a child that creates a new session, but this is not a general
containment guarantee for hostile daemons or workloads manipulating the host.

Only after the entire owned descendant tree is empty does the guardian persist
`clean`, acknowledge completion, and exit. The parent also retains its lock copy
until it has drained output and reaped the guardian. On parent crash the guardian
detects control EOF, cleans the tree, and leaves a durable `clean` record for a
restarted caller. The old lease remains admitted and cannot execute twice.

| Condition | Behavior |
| --- | --- |
| A living parent/guardian owns the lock | Immediate `ResourceBusy`; no replacement process |
| Durable `clean` state and a new current lease | Admit the new attempt |
| Previously admitted lease, even after failure/restart | `DuplicateExecution` |
| `reserved`, `active`, malformed or `quarantined` state after lock acquisition | `RecoveryRequired`; no signal to stored PIDs and no execution |
| TERM/KILL cleanup cannot prove an empty tree within its deadlines | `CleanupIncomplete` (an `ExecutionNotStopped`: the Runner task ends only at lease expiry); living guardian retains the lock and continues cleanup |
| Guardian is killed and its dirty state is retained | The running call raises `ExecutionUncertain` (a `RecoveryRequired` and an `ExecutionNotStopped`: the Runner task ends only at lease expiry); `RecoveryRequired` on the next admission |
| Complete ownership namespace loss or rollback | Not automatically detectable; the operator must externally fence the resource before recovery |

Boot id, guardian/child PID and process start ticks are audit data, not authority
to kill an old PID. No automatic "force unlock", stale-PID kill or metadata reset
is provided. An operator must independently fence the physical resource and
prove no old owner can use it before rebuilding an uncertain state namespace.
An absent namespace is treated as fresh; absence does not prove that an old
owner stopped. Namespace deletion or rollback therefore requires external
fencing even if this module would otherwise admit a new process.
Admission tombstones are intentionally retained; the bounded journal refuses
new admissions after `max_attempts` instead of silently allowing old duplicates.
Retention/namespace rotation requires a separately fenced maintenance procedure.

## Lease and deadline behavior

The parent validates the supplied control owner, checks cancellation, renews
before admission, and continues cancellation/renewal checks while draining output.
Renewal must preserve the full owner identity and cannot shorten expiry. Polling
and renewal intervals should be comfortably smaller than the lease duration;
allow for process startup and durable writes when configuring lease duration.

The guardian independently enforces the absolute lease deadline, a monotonic
lease-time bound, a heartbeat deadline, and a total execution timeout. It receives
only expiry timestamps, never a lease bearer. Control disconnect, expiry, failed
renewal, timeout, cancellation or output overflow trigger bounded TERM followed
by KILL and descendant reap. The payload starts in a new session; signals are
sent only to proven direct children through pidfds. The guardian does not call
`preexec_fn`, broadcast signals to stored process groups, or buffer output.

**Lease-control callbacks must return in bounded time.** The API is synchronous;
it cannot bound an arbitrary blocking `stop_requested()` or `renew()` callback.
If a caller callback hangs after launch, the independent guardian watchdog still
terminates the payload and protects resource cleanup, but `run()` cannot return
until that callback returns. Filesystem and OS operations likewise require a
responsive host. An unkillable kernel task is quarantined, not declared stopped.
A quarantined guardian retains its resource lock; one daemon waiter in the
parent retains the process handle and reaps it when cleanup eventually finishes.
Returning `CleanupIncomplete` does not leave an eventual zombie waiting for
another supervisor invocation. The waiter neither signals nor unlocks the guardian.

`ProcessResult` is returned only after durable cleanup acknowledgement and
guardian reap. Its `reason` includes `completed`, `stop_requested`, `lease_lost`,
`timed_out`, `output_limit`, `heartbeat_lost`, `parent_lost`, `spawn_failed` or
`guardian_failed`; `completed` still requires inspecting the child's exit code.
`LeaseControl.stop_requested()` combines cancellation and revoked ownership, so
`stop_requested` does not claim to distinguish those two cases. A result contains
no bundle reference or authority to complete a lease.

Only the task/resource hashes, generation, token **hash**, lifecycle state and
process identity metadata are persisted. Raw stdout/stderr is not written to the
ownership journal. A bearer in configured argv/env is rejected, and a complete
bearer accidentally echoed in captured output is redacted before return. This
does not make arbitrary child output safe for logging; applications must apply
their own artifact and secret policies.

## Deployment boundary and verification

Require Linux `/proc` with `/proc/<pid>/task/<tid>/children`
(`CONFIG_PROC_CHILDREN`), pidfds, permission to signal owned children, subreaper
support and local Unix `SOCK_SEQPACKET`. The guardian probes pidfds and the
children file before spawning and otherwise refuses with `guardian_failed`. The workload is a trusted, cooperative
local process. It must not tamper with the ownership namespace, signal the
guardian, fork indefinitely, move work to another host/service, pass resource
handles outside the supervised tree, or detach a separately managed VM/device.
Same-uid isolation, adversarial guests, cgroup fencing, VM teardown and external
side effects require a separate execution adapter and containment boundary.

Focused tests use real local Python children for capture, overflow, lease
renewal/loss, cancellation, TERM resistance, grandchildren, shared-resource
contention/reclaim, parent crash/restart, guardian death before child identity is
recorded, stale PID metadata refusal, and descriptor/process cleanup. They launch
no VMs and touch no existing fuzzing processes. Environments that deny Unix socket
traffic or process signalling must run these tests in an approved local host
test context; a sandbox denial is not a passing lifecycle test.

```sh
python -m pytest -q tests/agent_pipeline/test_process_supervisor.py
```
