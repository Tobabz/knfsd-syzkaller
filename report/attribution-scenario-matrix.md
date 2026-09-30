# Attribution boundary x variant scenario matrix

> Historical regression scope (2026-09-28): current corpus work follows
> [normal-flow-corpus.md](normal-flow-corpus.md). This table retains the earlier
> attribution-variant results; closing all its cells is not a corpus prerequisite.

The rows are the complete B01-B12 inventory from `report/attribution-boundaries.md`.
Variants are V1 normal, V2 abort before grant, V3 abort after grant, V4 cancel
saved work, V5 re-defer, V6 retry/final, and V7 concurrent cross-lane. An
ownerless V1 means that the ownerless worker runs while an attributed request
is active and the negative oracle proves its sentinel is absent from that
request's published coverage.

No existing artifact has both baseline-eligible six-input provenance and the
complete oracle required to close a cell. In particular, the SHA-matched B05
ON-only trial has no paired coverage verdict, so B05-V1 remains NEW. Gate 8 and
Gate 9 artifacts are not SHA-eligible. No cell is UNFORCEABLE before the
forcing attempts in task 6.

| Boundary | V1 | V2 | V3 | V4 | V5 | V6 | V7 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B01 | NEW(B01-V1) | NEW(B01-V2) | NEW(B01-V3) | NA(client transmit has no saved-work object to cancel) | NA(client transmit does not defer or revisit work) | NEW(B01-V6) | NEW(B01-V7) |
| B02 | NEW(B02-V1) | NEW(B02-V2) | NEW(B02-V3) | NA(receive attaches wire work but creates no saved-work object) | NA(record receive has no re-defer transition) | NEW(B02-V6) | NEW(B02-V7) |
| B03 | NEW(B03-V1) | NEW(B03-V2) | NEW(B03-V3) | NA(checked admission consumes work but does not save cancellable work) | NA(checked admission itself cannot re-defer) | NEW(B03-V6) | NEW(B03-V7) |
| B04 | NEW(B04-V1) | NEW(B04-V2) | NEW(B04-V3) | NEW(B04-V4) | NEW(B04-V5) | NEW(B04-V6) | NEW(B04-V7) |
| B05 | NEW(B05-V1) | NEW(B05-V2) | NEW(B05-V3) | NEW(B05-V4) | NA(async COPY work is single-shot and has no defer revisit) | NEW(B05-V6) | NEW(B05-V7) |
| B06 | NEW(B06-V1) | NA(ownerless backchannel processing has no request grant) | NA(ownerless backchannel processing has no request grant) | NA(backchannel processing stores no request saved-work object) | NA(backchannel processing has no defer revisit) | NEW(B06-V6) | NEW(B06-V7) |
| B07 | NEW(B07-V1) | NA(ownerless callback work has no request grant) | NA(ownerless callback work has no request grant) | NA(callback work stores no request saved-work object) | NA(callback work has no defer revisit) | NEW(B07-V6) | NEW(B07-V7) |
| B08 | NEW(B08-V1) | NA(ownerless laundromat work has no request grant) | NA(ownerless laundromat work has no request grant) | NA(laundromat work stores no request saved-work object) | NA(laundromat rescheduling is periodic work not request re-defer) | NA(laundromat work has no RPC retry or final transition) | NEW(B08-V7) |
| B09 | NEW(B09-V1) | NA(ownerless recovery work has no request grant) | NA(ownerless recovery work has no request grant) | NA(recovery upcalls store no request saved-work object) | NA(recovery upcalls have no defer revisit) | NA(recovery lifecycle has no request retry or final transition) | NEW(B09-V7) |
| B10 | NEW(B10-V1) | NA(ownerless coalesced work has no request grant) | NA(ownerless coalesced work has no request grant) | NA(coalesced workers store no request saved-work object) | NA(coalesced scheduling is not request re-defer) | NA(coalesced workers have no request retry or final transition) | NEW(B10-V7) |
| B11 | NEW(B11-V1) | NEW(B11-V2) | NEW(B11-V3) | NA(lane reservation creates wire work not saved work) | NA(lane mapping has no defer revisit) | NEW(B11-V6) | NEW(B11-V7) |
| B12 | NEW(B12-V1) | NEW(B12-V2) | NEW(B12-V3) | NA(raw request origin stores logical and wire work not saved work) | NA(raw request origin has no defer revisit) | NEW(B12-V6) | NEW(B12-V7) |
