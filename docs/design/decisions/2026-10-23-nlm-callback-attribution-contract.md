# NLMv4 GRANTED callback attribution contract (prototype)

Status: diagnostic only. This proposed evidence boundary does not authorize
nlm-knfsd Stage 2 or alter the HCAP-13 approval.

## Observed boundary

The NLM LOCK crosses the opt-in Proxy 4045 listener to the separate lockd
backend 4050. The later server GRANTED_MSG is a new RPC call on a
client-facing connection; it does not traverse that Proxy listener. The
Proxy's current-generation counter, callback XID, and NLM cookie cannot
establish which LOCK caused it. Local KVM smoke tests found one in-window
match to generation 1 and one post-deactivation callback left unassigned.
Both are diagnostic observations, not sealed Stage 2 evidence.

## Proposed evidence boundary

The normalized contract in agent_pipeline/stage2/nlm_callback_contract.py
is isolated from Stage2HostFacts, the production journal, and the judges.
Its inputs must eventually come from a host-owned capture/verifier, never
from a guest assertion:

1. Pin the VM instance, capture digest, ordered sequence interval, and loss
   counters. Complete capture starts before the LOCK and ends after the
   callback and closure, covering both server and client paths. A packet
   limit, unresolved split RPC record, failed collector, or unknown drop count means
   incomplete evidence.
2. Re-admit the sealed host journal. Bind each normalized LOCK to one
   EXPOSURE_INTENT by session/lane/generation/batch, request digest, XID,
   and full framed output SHA-256. Require FORWARD_COMPLETE and byte-identical
   forwarded LOCK on the backend path. A forwarded LOCK without mutation
   exposure needs a separately specified host anchor; this prototype does
   not accept it.
3. Extract the full NLMv4 lock tuple (file handle, owner, svid, offset,
   length) from LOCK and GRANTED_MSG, hash it without exposing raw values,
   and bind both to the same client/server endpoint and VM instance.
   Retransmissions, duplicate callbacks, or two matching LOCKs across
   sessions or generations remain ambiguous even if bytes are equal.
4. Bind activation open and close to host-observed ordering. The callback
   must follow the one forwarded LOCK and precede that generation's close.
   A callback after close is not reassigned. Use a monotonic capture sequence;
   wall-clock timestamps across hosts or VMs are not ordering authority.

The prototype returns matched only for unique, in-window normalized inputs;
every result is diagnostic_only. A match does not imply remote KCOV ownership.
That requires a kernel lifetime mechanism carrying the original generation
into lockd/rpciod work. Journal ACK plus packet capture do not prove this
across a crash or restart.

## Failure rules

| Condition | Diagnostic result | Stage 2 use |
| --- | --- | --- |
| Unique LOCK and callback in one complete open window | matched | none yet |
| Capture gap, truncated/unresolved split RPC, missing interval endpoint | capture_incomplete | unavailable |
| Retransmitted LOCK, multiple candidates, missing/failed forward | ambiguous_or_unmatched_lock | unavailable |
| Duplicate or retransmitted callback | duplicate_callback | unavailable |
| Callback after close, before open, missing/ambiguous activation | outside_activation_window | unavailable |
| VM crash, Proxy restart, unfinished batch | no positive attribution without new verified identity and capture | unavailable |

The normalized attribution prototype itself does not authenticate its inputs.
The disposable host verifier described below now re-admits journal frames,
reassembles TCP, checks the packet-socket loss counter, and maps packet intervals
onto one collector-owned event sequence. Production Stage 2 does not call this
verifier.
The separate host comparator in tools/nlm_callback_verify.py now re-admits
journal frames and checks observed backend LOCK bytes against same-batch
FORWARD_COMPLETE. It does not fill the remaining capture or ordering gaps;
its callback counts are unordered candidates, not attribution. Identical TCP
sequence observations are counted but cannot be classified as capture
duplication versus retransmission from this pcap alone.

The comparator's explicit --reassemble mode uses tools/nlm_tcp_capture.py.
It anchors each direction on an observed SYN, separates changed TCP initial
sequence numbers into local connection epochs, and reconstructs split,
coalesced, and multi-fragment RPC records. Exact framed bytes, including all
RPC fragment markers, determine the digest. Bounded limits apply to capture
size, streams, segments, bytes per stream, RPC records, and RPC fragments.
Holes and conflicting overlaps reject the direction; identical overlaps are
reported without deciding whether capture duplication or retransmission
caused them. Missing starts, ends, resets, and ambiguous connection reuse
remain explicit issues. A control-only direction also participates in the
stream report. Records reconstructed before a later incomplete RPC may remain
diagnostic observations, with that stream issue attached to the report.

observed_streams_complete means only that the supported parser found no
structural issues in the observed streams; it does not authenticate TCP
handshakes, validate every RPC/XDR field, or prove no entire flow was missed.
Packet indices are local pcap ordinals, including duplicate observations,
not host/journal event order. The new v2 report always retains
capture_complete=false and diagnostic_only. Default v1 packet parsing and
the readiness smoke checks remain unchanged. Reprocessing the existing normal
and late KVM pcaps with SYN-anchored reconstruction cannot re-confirm their
backend LOCK anchors because the captures lack the required connection
boundaries. This does not invalidate the older packet-byte observations; it
demonstrates their insufficient capture scope for a complete-stream claim.

The disposable AF_PACKET collector can emit PACKET_STATISTICS on clean
stop-file shutdown into a separate local stats file. The capture-lifecycle mode
starts it after the server namespace is ready but before the first client
ping, daemon, mount, or NLM connection setup. Cleanup first stops the other
server-namespace processes, waits for their traffic, and then requests clean
collector shutdown through the stop file. Collector handling is restricted to
the namespace whose network-namespace identity matches the recorded collector;
other namespace cleanup follows the normal path. Cleanup also requires the
same collector PID/start-time identity to exit cleanly, avoiding a PID-reuse
signal race. A distinct completion marker is created only after the pcap,
socket statistics, and socket close succeed. Stale lifecycle files are removed
before launch. These changes apply only to an instrumented disposable lane
copy.

The ordered disposable mode gives one collector authority over both packet
observations and activation markers. The host creates a fresh VM instance ID
and two 256-bit marker nonces for every run. The same VM ID binds the host
journal and the collector event-log header. After the activation ACK, the host
runner asks the collector's Unix datagram endpoint to append the open nonce and
waits for the collector sequence ACK. It records and acknowledges the close
marker before sending the deactivation request, conservatively excluding
callbacks that race with that request rather than assigning them. Packet and
marker receive timestamps come from `SO_TIMESTAMPNS`; the collector drains the
packet queue before accepting a marker and records ambiguity if timestamps cross.
The packet socket rejects only outgoing loopback copies before accounting, while
retaining outbound callback traffic on other interfaces. The same attached
IPv4/TCP filter makes the remaining packet-socket count and pcap observation set
identical. A non-zero drop count, a count mismatch, a timestamp crossing, or a
missing/reordered marker makes `ordered_observations_complete` false.
On shutdown the collector first installs a reject-all socket filter, then
rebinds the AF_PACKET socket from `ETH_P_ALL` to `ETH_P_IP`. The protocol
change unregisters the old receive hook and waits for network synchronization;
the replacement hook drops packets before queueing or packet-socket accounting.
The collector then drains only packets queued before the rebind and reads the
final packet statistics.

After clean capture shutdown and host-journal closure, the runner writes a
content-addressed manifest over the exact collector binary, pcap, event log,
stats, completion record, sealed-journal manifest, marker set, VM identity, and
parser version. Offline verification recomputes every digest and rejects a
wrong VM, torn log, non-contiguous packet mapping, structural stream issue, TCP
overlap, dirty journal, duplicate LOCK/callback, invalid FORWARD_COMPLETE, or
artifact mutation. A normal unique callback can then be `matched` diagnostically;
the late control remains `outside_activation_window` without an owner.

This narrows only the disposable diagnostic blocker. Both the manifest and
attribution retain `status=diagnostic_only` and `capture_complete=false`; the
more precise field is `ordered_observations_complete`. It neither supplies a
production capture service nor proves callback crash-context/remote-KCOV
ownership. HCAP-13, production Proxy/guest pins, and the Stage 2 refusal are
unchanged.

Four KASAN KVM controls used the pre-freeze ordered collector binary: three
normal runs and one deactivate-before-grant run. Every run completed the
cookie mutation, accepted the callback, completed the waiting `fcntl`, observed
one LOCK and one callback, and accounted for 1,022 captured packets out of
1,022 packet-socket observations with zero drops. Journals and reconstructed
streams were clean, and no KASAN, KCSAN, Oops, panic, or warning signature was
found. Each run nevertheless observed a small packet-timestamp inversion, set
`ordering_ambiguous=1`, and returned an ownerless `capture_incomplete` result.
These are exact-source negative fail-closed observations, not complete ordered
positive evidence; the timestamp-crossing rule remains unchanged.

Two intermediate KASAN KVM controls used collector SHA-256
`be69ac50a75a31b3301d7e544e937894a990c4bd004ee5adc3ac0373dd973bab`.
Their protocol-zero bind did not detach the existing `ETH_P_ALL` hook because
`packet_do_bind()` preserves the current protocol for a zero value. Those runs
remain historical functional and fail-closed observations, but are not evidence
for the current collector's shutdown freeze.

Two current-source KASAN KVM controls used collector SHA-256
`633114ed8586e416c4b35b277bd123c8c76338a3f21662f9195d648696da0c72`
with the reject-all filter and forced protocol rebind described above. Both the
normal and deactivate-before-grant runs completed mutation, callback, the
waiting `fcntl`, and `LCK_GRANTED`; each observed one LOCK and one callback,
accounted for 1,022/1,022 packets with zero drops, kept the journal and streams
clean, and had no KASAN, KCSAN, Oops, panic, or warning signature. The normal
run found an ordering ambiguity and failed closed as ownerless
`capture_incomplete`; its pcap SHA-256, canonical manifest digest, and result
file SHA-256 values are
`929cc434e8d9e0c88df880a2843bfe324564ae2eed5c2808e12ec2751eb63140`,
`9147ac76a87f504f2f341ee837c6ea64b264db40d852e818557f24e2f7efcd1b`,
and `e72ce2078705ee8ebd9564ff1d64c8add9e658bf3d52aacc41910c8cb5b645c6`.
The deactivate-before-grant run found no ordering ambiguity, set
`ordered_observations_complete=true`, and classified the late callback as
ownerless `outside_activation_window`; its corresponding pcap SHA-256,
canonical manifest digest, and result file SHA-256 values are
`63f873c166851b713aa59583760dd9e0fa197a5debeb27e2a7f82784a14ce100`,
`695779cc09406bc436c82b22a149e4dcb0713c1c25eeb06f2dc8852d2020e262`,
and `57a15fe24edb5f642221558494203bf946d3e6be83490305a52a382aaebbb9cf`.
Both remain `status=diagnostic_only` and `capture_complete=false`; there is no
complete ordered-positive ownership claim.

Two earlier real KASAN KVM runs exercised the connection-setup-through-cleanup
scope before the collector gained its final clean-completion marker. The normal
and deactivate-before-grant cases captured 1,526 and 1,524 IPv4/TCP frames;
their socket packet/drop counters were 1,628/0 and 1,708/0. In each run the
bounded reassembler reported 26 directional streams, no structural stream
issue, one unique byte-identical backend LOCK anchor, and one unordered
callback candidate. Both completed the blocked-grant sequence, had a clean
journal and fixture cleanup, and showed no KASAN, KCSAN, Oops, panic, or
warning signature. The legacy diagnostic placed the normal callback inside
generation 1 and left the late callback unassigned as
outside_activation_window. These remain historical diagnostic observations.

The final lifecycle, including collector-network-namespace matching,
PID/start-time validation, stop-file shutdown, and a completion marker written
only after pcap, statistics, and socket closure, was then run with an unchanged
LOCK range (mutation offset 0). The normal and deactivate-before-grant controls
each captured 1,526 IPv4/TCP frames; their socket packet/drop counters were
1,628/0 and 1,709/0. Both clients completed LOCK and UNLOCK, fixture cleanup
returned success with every leak counter at zero, and the same 26-stream,
one-anchor, one-callback diagnostic shape was reconstructed without a
structural issue. The normal callback matched generation 1 diagnostically; the
post-deactivation callback remained unassigned as
outside_activation_window. Neither console contained a KASAN, KCSAN, Oops,
panic, or warning signature. This confirms the hardened diagnostic lifecycle
and its late-callback distinction, not production attribution.

The disposable fixture depends on lockd-netlink-port and nlm-rpcbind-front.
The diagnostic image used here did not contain them, so initial runs stopped at
command -v lockd-netlink-port. A subsequent /proc/<pid>/ns/net error came from
cleanup after that failure; it was not evidence of a kernel crash or namespace
race. The relay runner now requires both helper paths whenever it installs a
replacement Proxy and copies them into the disposable guest before starting
boot-fixture.sh. This makes the experiment self-contained without changing or
promoting the approved guest dependency archive.

The final lifecycle's offset-1 runs are a negative identity control, not a
route-reliability test. Linux nlmclnt_grant matches file handle, owner, svid,
server address and lock range. The forwarded offset 1 GRANTED_MSG therefore
cannot wake a client waiting for offset 0. Re-decoding both captures found one
logical GRANTED_RES, observed at two relay points, with LCK_DENIED; the client
trace reported the same status. A later synchronous LOCK retry may separately
complete fcntl. Callback receipt, client acceptance, GRANTED_RES status and
final syscall completion must consequently be reported independently.

The diagnostic positive control mutates the LOCK request cookie to a fixed,
same-length four-byte opaque value. This changes forwarded bytes without
changing the lock identity used by blocked-request lookup or nlmclnt_grant;
the server creates a distinct cookie for GRANTED_MSG. Its success contract is
a byte-changing backend exposure, GRANTED_MSG receipt, LCK_GRANTED in both the
client trace and GRANTED_RES, and completed waiting fcntl. The result records
only the mutation mode and counts, never the cookie bytes. The raw sealed
journal and pcap remain local. This positive control still does not establish
production callback attribution or authorize Stage 2.

With those helpers installed, a new offset-1 negative control changed two
forwarded LOCKs and received one GRANTED_MSG, but both the client trace and
GRANTED_RES reported LCK_DENIED. The waiting fcntl later completed through an
unresolved callback-or-retry path, confirming why syscall completion is not a
callback-acceptance signal. The capture reported 1,536 IPv4/TCP frames and
1,642 packets with zero drops.

The typed cookie normal and deactivate-before-grant controls each changed one
forwarded LOCK, received GRANTED_MSG, reported LCK_GRANTED in both the client
trace and GRANTED_RES, and completed the waiting fcntl. The normal callback
matched generation 1 diagnostically. The callback after deactivation was
outside_activation_window and had no generation. Both captured 1,526 frames;
their socket counters were 1,635/0 and 1,627/0 packets/drops. Across all three
runs the journal had no rejection, fixture cleanup returned success with every
leak counter at zero, and no KASAN, KCSAN, Oops, panic, or warning signature was
found. The reports remain diagnostic_only and capture_complete=false.

Running nlm_stage2_readiness over the typed cookie pair passed every smoke
check and selected typed_callback_acceptance for both inputs. It still exited 2
with stage2_ready=false. The unresolved gates are complete ordered VM-bound
callback capture, crash-context and remote-KCOV attribution, a restart
counterexample, promoted production Proxy and guest pins, independent Stage 2
gate/campaign/strict-replay evidence, a configured Stage 2 backend, and HCAP-13
Stage 2 authority.

A zero drop count narrows one capture-loss mode, but does not establish VM
provenance, monotonic ordering with the journal, or that an entire unseen flow
was not missed. An absent stats or completion file is unknown/incomplete loss.
Accordingly all v2 reports retain capture_complete=false and diagnostic_only.
Do not publish raw pcap, lock tuples, candidate locations, target PCs, or
coverage. Retain the current Stage 2 preflight/runtime refusal until
independent KVM gate/campaign/replay, crash-window validation, a pinned build,
and HCAP owner approval establish the production path.
