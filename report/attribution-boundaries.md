# knfsd remote-KCOV attribution boundaries

> Inventory scope (2026-09-28): these are known instrumentation/attribution
> boundaries, not a completed inventory of all normal NFS execution flows.
> Expand from normal operations and scheduling sites, including uninstrumented
> transitions, as specified in [normal-flow-corpus.md](normal-flow-corpus.md).

This inventory describes the kernel at `/home/idealinsane/kcsan-env-0012/linux`,
commit `02102ee22924`. The old `kcov_remote_sunrpc.patch` is useful history but
is not the current contract: current server coverage requires a request root,
a child token, an exact owner/generation mapping, a remote ticket, and checked
START_GRANTED admission. A wire `rq_kcov_handle` is provenance only and is
explicitly cleared before admission.

Citation syntax is `cite:relative/path:line:anchor:role` inside square brackets,
where role is `call`, `assign`, or name-table `name`. The checker requires the
declared entity on that exact executable/definition line. `tools/attr-cite-check.py`
checks every citation and the required cells of every boundary row.

## Inventory

| ID | Boundary | Context before -> after | Current kernel site(s) | Handle / saved field(s) | Grant / start / stop | Status | Observing counters | Coverage sentinel |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B01 | Client RPC transmit / skb tag | syscall or RPC creator -> rpciod/socket transmit; generic forks inherit owner/generation via `kcov_task_init` | logical RPC initialization `[cite:net/sunrpc/sched.c:1125:sunrpc_fuzz_logical_init:call]`; temporary owner/generation installation around transport send `[cite:net/sunrpc/xprt.c:1604:fuzz_attributable:assign]` | `rpc_task.tk_fuzz.{owner,root,request_cookie}` and `current->{kcov_handle,kcov_handle_generation}` | root initialized at task birth; wire child is granted later at first-byte reservation; transmit restores both current fields | attributed | `root_token_created`, `wire_attempt_created`, `wire_attempt_committed`, `sunrpc_logical_retry` | `xprt_request_transmit` |
| B02 | Server receive / wire-work handoff | softirq/socket receive -> nfsd svc thread and `svc_rqst` | TCP metadata capture `[cite:net/sunrpc/svcsock.c:413:svc_data_ready:call]`; completed-record mapping `[cite:net/sunrpc/svcsock.c:1225:sunrpc_fuzz_svc_record_received:call]`; provenance copy `[cite:net/sunrpc/svcsock.c:1244:rq_kcov_handle:assign]` | `svc_sock.sk_kcov_handle`, `svc_rqst.rq_kcov_handle`, authoritative `rq_fuzz_wire_work` | peer record consumes the wire token and attaches work; no KCOV start occurs in receive | attributed | `wire_token_server_consumed`, `wire_work_attached`, `wire_work_ownerless`, `record_ownerless` | `svc_tcp_recvfrom` (receive witness, before checked start) |
| B03 | `svc_process` checked admission | queued svc request -> executing nfsd service thread | grant and checked start `[cite:net/sunrpc/svc.c:1670:kcov_request_remote_start_checked:call]`; common terminal stop `[cite:net/sunrpc/svc.c:1761:sunrpc_fuzz_svc_remote_terminal:call]` | `rq_fuzz_wire_work` or `rq_fuzz_saved_work` -> `rq_fuzz_remote_ticket`; `rq_kcov_handle` is cleared | `sunrpc_fuzz_svc_remote_grant`; `kcov_request_remote_start_checked`; terminal calls `kcov_request_remote_stop_checked` through helper | attributed | `remote_grant_attempt`, `remote_start_granted`, `remote_start_ok`, `remote_stop`, `remote_ticket_completed` | `svc_process_common` (called after successful checked start) |
| B04 | `svc_defer` save / cache replay / re-defer | active nfsd svc thread -> deferred cache revisit -> another svc thread | child save `[cite:net/sunrpc/svc_xprt.c:1320:sunrpc_fuzz_svc_continuation_save:call]`; replay restore `[cite:net/sunrpc/svc_xprt.c:1355:sunrpc_fuzz_svc_continuation_restore:call]`; deferred svc grant `[cite:net/sunrpc/fuzz_conn.c:2118:sunrpc_fuzz_saved_work_grant:call]`; checked start `[cite:net/sunrpc/svc.c:1670:kcov_request_remote_start_checked:call]` | `svc_deferred_req.fuzz_saved_work`, `svc_rqst.rq_fuzz_saved_work`, continuation token, remote ticket | save child token; restore; `sunrpc_fuzz_svc_remote_grant` -> saved-work grant; checked start in `svc_process`; terminal checked stop; re-defer saves a fresh child before stop | attributed | `deferred_child_created`, `deferred_restored`, `deferred_redeferred`, `deferred_grant_ok`, `deferred_start_ok`, `deferred_completed`, `deferred_dropped` | restore witness: `svc_deferred_recv`; positive post-start sentinel: `svc_process_common`, paired with `deferred_start_ok` |
| B05 | NFSv4.2 asynchronous COPY | active COMPOUND svc thread -> COPY kthread -> callback enqueue | save before kthread creation `[cite:fs/nfsd/nfs4proc.c:2264:sunrpc_fuzz_svc_continuation_save:call]`; kthread grant/start wrapper `[cite:fs/nfsd/nfs4proc.c:2151:sunrpc_fuzz_saved_work_start:call]`; checked stop `[cite:fs/nfsd/nfs4proc.c:2203:sunrpc_fuzz_saved_work_stop:call]` | `nfsd4_async_copy.cp_fuzz_saved_work`, continuation token, local `fuzz_ticket` | save ASYNC child; grant/start in `nfsd4_do_async_copy`; stop after copy and callback enqueue | attributed | `async_child_created`, `async_grant_ok`, `async_start_ok`, `async_completed`, `async_dropped`, `aggregate_entries_published` | `nfsd4_do_copy` (post-start COPY body) |
| B06 | NFSv4.1+ same-connection backchannel | callback CALL received on shared connection -> `svc_process_bc` -> synchronous callback reply; callback REPLY received by server -> `receive_cb_reply` | callback CALL dispatch `[cite:net/sunrpc/svc_xprt.c:983:svc_process_bc:call]`; current CALL body has no checked admission `[cite:net/sunrpc/svc.c:1774:svc_process_bc:call]`; callback REPLY path `[cite:net/sunrpc/svcsock.c:1254:receive_cb_reply:call]` then reset `[cite:net/sunrpc/svcsock.c:1255:sunrpc_fuzz_svc_rqst_reset:call]`; CALL-send classification `[cite:net/sunrpc/xprtsock.c:3146:sunrpc_fuzz_note_record_class:call]` | shared `rpc_rqst` / `svc_rqst`; neither current CALL processing nor REPLY receive attaches an authoritative request ticket | no grant/start/stop in current `svc_process_bc`; historical fixed common-handle admission is not current behavior | ownerless | `record_backchannel` observes callback CALL transmission class only; no counter directly proves CALL execution or REPLY receipt | negative sentinels `svc_process_bc` and `receive_cb_reply` must be absent from an unrelated owner's `on_only` coverage |
| B07 | Separate outbound NFSv4 callback | nfsd operation or callback work item -> client callback workqueue -> async RPC task | callback workqueue body `[cite:fs/nfsd/nfs4callback.c:1849:nfsd4_run_cb_work:call]`; ownerless async RPC creation `[cite:fs/nfsd/nfs4callback.c:1891:rpc_call_async:call]` | `nfsd4_callback.cb_work`; `rpc_task.tk_fuzz` receives no explicit `fuzz_origin` | no saved request child/token/ticket; normal RPC transmit therefore remains unattributed | ownerless | `record_background`/`record_ownerless` observe resulting TCP records, not callback worker execution; no verified direct callback-worker observer exists on this baseline, so downstream execution remains unverified/UNFORCEABLE | `nfsd4_run_cb_work` (negative absent-on-only sentinel) |
| B08 | NFSv4 laundromat delayed work | timer/delayed-work queue -> laundry workqueue | delayed worker calls laundromat `[cite:fs/nfsd/nfs4state.c:7759:nfs4_laundromat:call]`; reschedule `[cite:fs/nfsd/nfs4state.c:7760:queue_delayed_work:call]` | `nfsd_net.laundromat_work`; no request handle field | none; intentionally no request child/token/ticket | ownerless | no direct debugfs counter or verified direct execution observer; `CONFIG_FUNCTION_TRACER` is disabled and no guest kprobe was registered; effect tracepoints such as `nfsd_mark_client_expired` are secondary, while request counters are no-leak invariants only | `laundromat_main` is only a candidate negative coverage sentinel; without an execution observer this boundary remains unverified/UNFORCEABLE downstream |
| B09 | Recovery/grace nfsdcld upcall | nfsd lifecycle/recovery context -> rpc_pipefs userspace daemon exchange | grace-start upcall `[cite:fs/nfsd/nfs4recover.c:1292:nfsd4_cld_grace_start:call]`; pipe handoff `[cite:fs/nfsd/nfs4recover.c:1305:cld_pipe_upcall:call]` | `cld_upcall` / `cld_msg`; no request handle field | none; lifecycle work is not descended from one admitted request | ownerless | no direct debugfs counter or verified direct execution observer; rpc_pipefs status/completion observes an upcall only when captured, and no guest kprobe was registered | `nfsd4_cld_grace_start` is only a candidate negative coverage sentinel; without captured rpc_pipefs evidence this boundary remains unverified/UNFORCEABLE downstream |
| B10 | Coalesced filecache GC, delegation recall, and state shrinker | delayed/system work, lease break, or generic shrink request -> GC/callback/laundry workqueue | filecache worker `[cite:fs/nfsd/filecache.c:609:nfsd_file_gc_worker:call]` with removal trace `[cite:fs/nfsd/filecache.c:605:trace_nfsd_file_gc_removed:call]`; delegation recall queues callback `[cite:fs/nfsd/nfs4state.c:3675:nfsd4_run_cb:call]`; state shrinker worker `[cite:fs/nfsd/nfs4state.c:7808:nfsd4_state_shrinker_worker:call]` | global `nfsd_filecache_laundrette`, `nfs4_delegation.dl_recall`, or `nfsd_net.nfsd_shrinker_work`; no unique request owner | none; coalesced work cannot safely inherit one request; callback follows B07 | ownerless | no common direct debugfs counter; static `nfsd_file_gc_removed` observes a GC effect but not a zero-removal worker run; delegation recall and state shrinker have no verified direct observer, and request counters are no-leak invariants only | candidate negative sentinels `nfsd_file_gc_worker` and `nfsd4_state_shrinker_worker`; cells lacking a captured static effect remain unverified/UNFORCEABLE |
| B11 | Multi-proc owner lane -> connection domain | per-proc attributed RPC -> lane-bound connection reservation; generic fork inheritance supports per-program children | owner/lane decision and wire child grant `[cite:net/sunrpc/fuzz_conn.c:1188:kcov_request_try_get_child_token:call]`; direct diagnostic decision `[cite:net/sunrpc/fuzz_conn.c:1182:owner_lane_match:assign]` | `sunrpc_fuzz_conn.key.lane_id`, `sunrpc_fuzz_rqst.{owner,root,request_cookie}`, wire token | wire child token is granted only from the request root; B02/B03 consume and start it | attributed | `owner_lane_match`, `cross_lane_attribution`, `phase9_lane_seen_mask` | `sunrpc_fuzz_wire_token_acquire` |
| B12 | Raw `TCP_SUNRPC_FUZZ` request origin | attributed userspace `sendmsg` -> persistent raw tag/logical RPC -> socket transmit | current-origin capture and logical-root creation `[cite:net/sunrpc/fuzz_conn.c:1540:sunrpc_fuzz_origin_capture_current:call]`; auto-finish logical init `[cite:net/sunrpc/fuzz_conn.c:1544:sunrpc_fuzz_logical_init_auto_finish:call]` | `sunrpc_fuzz_raw_tag.logical.{owner,root,request_cookie}` keyed by `user_tag` | NEW captures owner/generation; RETRY reuses the same logical root; final/cancel completes it; shared wire reservation machinery then carries it | attributed | `raw_tag_created`, `raw_cmsg_new`, `raw_cmsg_retry`, `raw_retry_same_cookie`, `raw_tag_completed` | `raw_sendmsg` |

All listed counter spellings come from the current name tables: Phase 3 and
Phase 8 `[cite:net/sunrpc/fuzz_conn.c:104:record_ownerless:name]`
`[cite:net/sunrpc/fuzz_conn.c:240:deferred_child_created:name]`, Phase 9
`[cite:net/sunrpc/fuzz_conn.c:206:owner_lane_match:name]`, request lifetime
`[cite:kernel/kcov_request.c:77:generation_created:name]`, and checked remote
admission `[cite:kernel/kcov_request.c:321:remote_start_granted:name]`.

Generic task creation is supporting context, not another knfsd boundary:
`copy_process` invokes `[cite:kernel/fork.c:987:kcov_task_init:call]`, whose
definition copies both current handle and generation
`[cite:kernel/kcov.c:493:kcov_task_init:call]` while clearing ticket/controller state.

Observer availability is baseline-specific: `.config:5419` disables
`CONFIG_FUNCTION_TRACER`. Although `CONFIG_KPROBE_EVENTS=y`, no guest kprobe
registration was run or verified for these workers, so this inventory does not
claim dynamic function probes. A boundary with no static direct observer stays
unverified/UNFORCEABLE in downstream scenario work.

## Scope and out-of-fixture boundaries

The fixture is the frozen direct-veth TCP/NFSv4.x setup. The following are
real transport/context boundaries but are **out-of-fixture**, not silently
treated as covered:

| Boundary | Why it is out of fixture | Relevant current site |
| --- | --- | --- |
| UDP receive | The fixture deliberately exercises TCP only; datagrams carry skb provenance but do not exercise the TCP connection-domain ordinal/token handoff. | `[cite:net/sunrpc/svcsock.c:630:svc_udp_recvfrom:call]` |
| NAT | Address rewriting can invalidate direct-veth connection pairing; frozen Phase 9 explicitly excludes NAT. | connection pairing mechanism `[cite:net/sunrpc/fuzz_conn.c:928:sunrpc_fuzz_svc_pair:call]` |
| LOCALIO | Runtime boot uses `nfs.localio_enabled=N`, so the local filehandle bypass is not entered. | LOCALIO entry `[cite:fs/nfsd/localio.c:47:nfsd_open_local_fh:call]` |
| RPC-over-RDMA | No RDMA device, transport, or fixture is provisioned; its receive path is distinct from TCP skb/record mapping. | RDMA receive entry `[cite:net/sunrpc/xprtrdma/svc_rdma_recvfrom.c:944:svc_rdma_recvfrom:call]` |

## Evidence interpretation

`frozen_phase8.md` proves B04/B05 normal and abort-path behavior but explicitly
limits async propagation to server-side COPY and leaves callbacks, recovery,
laundromat, and coalesced work ownerless. `frozen_phase9.md` proves the
direct-veth TCP lane mapping and explicitly excludes NAT, LOCALIO, UDP, and
RDMA; it also limits callbacks to the same-connection backchannel. Those
checkpoint statements determine the status labels above, while all mechanism
and line claims come from the current kernel, not the historical base patch.

No additional request/thread transition was found in the required current-tree
search for `kcov_request_`, `kcov_remote_start`, `kcov_remote_stop`,
`fuzz_ticket`, `tk_fuzz`, and `rq_kcov`. B12 is the one additional real origin
boundary exposed by that search; the remaining matches are helper
implementations, diagnostics/selftests, or fields already assigned to B01-B11.
