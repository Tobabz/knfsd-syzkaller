# Attribution forcing hooks

`tools/attr_hooks.py` emits the guest commands consumed by checkbox 7. Its
stable format remains `attr-hook/v1`, and all existing manifest IDs remain
unchanged. The `v4`/`v5` text embedded in old hook IDs is compatibility text,
not the authoritative variant. The B/V mappings below are authoritative.

```sh
python3 tools/attr_hooks.py --list
python3 tools/attr_hooks.py --dry-run v6.retry-same-cookie-same-socket \
  --args-json '{"hook_dir":"/tmp/evidence","phase7_probe":"/opt/frozen-phase7/phase7-probe"}'
```

`FORCEABLE` in this interface means that the hook has an executable,
non-sleeping selection mechanism. It does not close a matrix cell. `UNFORCEABLE`
(exit 2) is used only after concrete guest attempts failed the required
transition or cleanup contract. A cell stays `NEW` until a baked-VM run records
the listed counter transition, coverage oracle, drain, diagnostics, and
unchanged image hash. The evidence level in `requirements[]` distinguishes
source-supported candidates from a confirmed transition. The current task-5
schema uses ordered `{id,args}` hook objects. `--args-json` accepts those args,
validates each hook's keys and renders deterministic environment assignments
without changing the `attr-hook/v1` result shape. Task 5's current
`_hook_contract` accepts both forceable and typed-unforceable results; a runner
must stop rather than execute an unforceable result.

## Boundary and variant map

| Boundary / variant | Stable hook ID | Trigger and transition witness | Evidence state |
| --- | --- | --- | --- |
| B04-V2 | `v4.abort-next-deferred` | exact `abort-next-deferred` write; require `deferred_abort_before_grant`, `deferred_owner_none`, `deferred_dropped` +1 | Kernel control and prior Gate 8 mechanism exist; no new task-6 VM run |
| B05-V2 | `v4.abort-next-async` | exact `abort-next-async` write; require corresponding async counters +1 | Kernel control and prior Gate 8 mechanism exist; no new task-6 VM run |
| B04-V3 | `v4.pause-release-deferred-after-grant` + `v4.generation-abort-ioctl` | arm, observe entered, invoke the guest C `_IOW('c',112,struct kcov_remote_generation)` helper on the inherited owner fd, then release | **UNFORCEABLE in the current checkbox-7 SSH scenario runner**: its separate guest command cannot inherit the executor's live owner fd/generation, so preflight rejects this composition. The standalone inherited-fd helper remains VM-proven (`generation_aborted` +1). |
| B05-V3 | `v4.pause-release-async-after-grant` + `v4.generation-abort-ioctl` | same ordered protocol for async saved work | **UNFORCEABLE in the current checkbox-7 SSH scenario runner** for the same live-owner-fd reason. This runner limitation does not invalidate the VM-proven standalone inherited-fd helper or preclude a future integrated owner-fd design. |
| B04-V4 | `v5.cancel-saved-work` | tested `ss -K` on one isolated saved request, then tested isolated nfsd service teardown | **UNFORCEABLE with current fixture**: `ss -K` returned EINVAL; service teardown dropped saved work but did not cancel the root and could not restore nfsd/cleanly drain |
| B04-V5 | `v5.redefer-cache-revisit` | stop/flush mountd for first defer; arm after-grant pause; resume first cache response; after entered, stop responder and flush again; release; require `deferred_redeferred` +1, then resume the second responder before executor completion/drain | Prior standalone VM transition confirmed re-deferred +1 and full drain, but the current scenario runner does not dynamically resolve the active fixture's `server_pid`; B04-V5 remains **NEW and not yet runnable** until task 8 supplies that runtime binding and a manifest. |
| B01/B02/B03/B11/B12-V6 | `v6.retry-same-cookie-same-socket` | execute Phase 7 `retry-final`: raw NEW, RETRY, RETRY\|FINAL; LD_PRELOAD audit verifier requires one TCP `socket`, one `connect`, and three `sendmsg` calls on that fd; require raw retry counters | Exact emitted hook VM PASS: socket fd 4, one connect, three sends, no reconnect, and expected retry counter deltas; cells remain NEW pending each boundary's coverage oracle |
| B03/B04/B05/B11-V7 | `v7.concurrent-cross-lane` | fixed Gate 9 lane 0/1 workers announce READY; coordinator issues and acknowledges GO1/DONE1 then GO2/DONE2 in lane0/lane1/lane0/lane1 order; manifest requires `owner_lane_match delta_ge 1` and `cross_lane_attribution delta_eq 0` | Task-5 run contract accepts this non-narrowed predicate; interleaver remains **NEW** pending per-lane VM counter and coverage proof |

B05-V4 is not claimed by the current transport-cancel candidate: the command
isolates a B04 deferred request and does not identify an async COPY saved object.
No `work_owner_none_after_abort` claim is made for B04-V4 because that counter
requires generation abort semantics, not mere saved-object cancellation.

## Exact stage protocols

The JSON command bytes emitted by `--dry-run` are normative and are pinned by
SHA-256 in `tools/tests/test_attr_hooks.py`. Tests additionally compare the
complete abort, pause, generation ioctl, and selected-socket commands.

### V2 and V3 controls

All control writes target
`/sys/kernel/debug/sunrpc_fuzz/phase8_control`. Pause sequencing is `arm`,
`observe-entered`, caller-scheduled generation abort, then `release`. Release is
also mandatory cleanup. `*_pause_after_grant_timed_out` must have delta zero.
The generation hook no longer depends on guest Python. It emits and compiles a
small C helper using `_IOW('c', 112, struct kcov_remote_generation)` and invokes
it on an inherited live `KCOV_FD`. A disposable standalone VM launcher created a
live generation, inherited the fd into the exact hook, observed helper status 0
and `generation_aborted` +1, then drained and cleaned the fixture. The current
checkbox-7 runner executes hooks through a separate SSH command, which cannot
inherit the syzkaller executor's live owner fd/generation. Therefore that
runner-specific pause+abort composition is **UNFORCEABLE** and rejected before
boot; the classification is scoped to this interface, not to the proven helper.

### V4 cancellation result

Two baked-VM attempts isolated exactly one deferred request with
`live_saved_work=1`. The transport attempt captured one established client TCP
socket, but `ss -K dst 10.77.0.1 dport = :2049` returned `RTNETLINK answers:
Invalid argument`; no socket teardown occurred. The service attempt wrote zero
to the isolated server's nfsd thread control. That deterministically changed
`deferred_dropped` 0 -> 1 and `live_saved_work` 1 -> 0, but
`root_token_canceled` and `work_owner_none_after_abort` remained zero. Writing
four threads back failed with debugfs `EIO`; fixture cleanup timed out. The image
hash remained unchanged. Because neither tested action proves requested root
ownerlessness while restoring/draining the fixture, the hook now returns typed
`UNFORCEABLE` and no unsafe command.

### V5 re-defer candidate

Required environment: `ATTR_HOOK_DIR` and `ATTR_SERVER_PID`. The active server
PID is stored at `<active_root>/lane0/server.pid`, but the current scenario
runner renders static manifest args before boot and does not substitute that
runtime value. Dynamic PID resolution is therefore a task-8 prerequisite; a
literal placeholder or stale host PID is not executable evidence. The protocol uses
the existing deferred after-grant pause as the replay barrier. Checkbox 7 must
subscribe to `deferred_pause_after_grant_entered` before resuming the first
cache response, perform the second cache invalidation only after entered,
release, then subscribe to `deferred_redeferred` before resuming mountd for
cleanup. No fixed sleep appears in the emitted commands; the only wait is a
bounded poll for the STOP state caused by the hook itself. The disposable VM
trial observed `deferred_redeferred=1`, entered/released=1/1, timed_out=0, a
passing deferred probe, and exact resource drain. Its enclosing artifact later
failed during the separate cancel attempt, so only this captured subtrial is
claimed, not an overall Gate 8 PASS. The artifact is also not hygiene-clean:
its dmesg contains pre-trigger KCSAN reports in `d_alloc_parallel /
simple_lookup` and `get_nr_inodes`, and it records
`deferred_child_rejected=2`. Those facts do not erase the captured transition
but prohibit using it as a full clean scenario verdict.

### V6 same-socket proof

Required environment: `ATTR_HOOK_DIR`; `ATTR_PHASE7_PROBE` is optional. The
hook builds a small user-space `LD_PRELOAD` socket audit, runs `phase7-probe
retry-final`, and checks the audit with `awk`. C records use actual newline
separators. Both the Python seam and emitted awk require exactly one socket
record, one connect record, and three sendmsg records on that selected fd; an
extra CONNECT or SENDMSG on another fd fails both. A local real-producer test
compiles the emitted C and runs the emitted verifier. The exact baked-guest hook
also passed with socket fd 4, three sends, and no reconnect. Probe JSON must
report `status=pass`, `scenario=retry-final`, `sends=3`, and `replies=3`. The old
`fault-arm sunrpc-retry` control is intentionally absent because its caller
executes `kernel_sock_shutdown(..., SHUT_RDWR)` and forces reconnect.

### V7 interleaving

Required environment: `ATTR_PHASE9_ROOT`, `ATTR_HOOK_DIR`, and executable
`ATTR_LANE0_WORKLOAD` / `ATTR_LANE1_WORKLOAD` segment drivers. Each worker is
entered through its fixed Gate 9 client mount/network namespace. FIFO READY,
GO, DONE and final process completion are exact events, not timing proxies.
This satisfies interleaving; simultaneous CPU execution is neither required nor
claimed. The hook's positive proof threshold is consumed against a manifest
`delta_ge: 1`; task 5's real `_run_contract` now accepts that predicate rather
than requiring exactly one owner/lane match. `cross_lane_attribution` remains
`delta_eq: 0`. Historical Gate 9 captures establish feasibility of fixed lanes
but do not confirm this new command or close any V7 cell.
