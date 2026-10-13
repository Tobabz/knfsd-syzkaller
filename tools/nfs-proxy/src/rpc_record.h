/* Canonical RpcRecord: one complete RPC message without its record marker.
 *
 * WHY THIS EXISTS
 *
 *   framing.c hands the relay a record exactly as it was read, fragment
 *   headers included, because the legacy path must be able to re-emit it
 *   byte-for-byte.  That coordinate space is wrong for the semantic layer: a
 *   field's offset would depend on how the sender chose to fragment the
 *   message, and a multi-fragment record would have a fragment header in the
 *   middle of its RPC bytes.  The target contract (design 03-nfs-proxy/01 §1,
 *   02 §6) fixes the coordinate origin at RpcRecord.rpc_payload[0]: the first
 *   RPC byte, with every record marker removed.
 *
 *   This unit is the adapter between the two.  It turns a framed record into
 *   its marker-free payload, and turns a payload back into a framed record.
 *   Nothing above it ever sees a fragment header; nothing below it ever sees a
 *   semantic offset.
 *
 * TWO COORDINATE SYSTEMS, NEVER MIXED
 *
 *   legacy  (walk.c, edit.c, NFSPARM1/2)  offset 0 = first fragment header
 *   target  (rpc_decode.c and above)       offset 0 = rpc_payload[0]
 *
 *   For a single-fragment record the two differ by exactly
 *   NFSP_FRAG_HEADER_LEN.  For a multi-fragment record there is no constant
 *   translation, which is why the legacy walk refuses fragmented records and
 *   the target path canonicalises them instead.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 *   No RPC or XDR.  An empty or nonsensical payload is still a payload; saying
 *   what it means is rpc_decode.c's job.
 */
#ifndef NFSP_RPC_RECORD_H
#define NFSP_RPC_RECORD_H

#include <stddef.h>
#include <stdint.h>

/* One proxied bidirectional transport connection (design 03 §2).
 *
 * connection_id is the identity: never zero, unique within one proxy run, and
 * never reused, even when the same conns[] slot or file descriptor is.  client
 * and backend are the route and are deliberately NOT part of the identity --
 * several connections may share one route at the same time. */
struct nfsp_connection_ref {
	uint64_t connection_id;
	unsigned client, backend;
};

/* The canonical record (design 01 §1).  `direction` is NFSP_DIR_C2S or
 * NFSP_DIR_S2C from proxy.h.  rpc_payload is a read-only view that is valid
 * only for the duration of the callback that received it.  nfrags is how many
 * fragments the sender used; it is transport detail, carried for diagnosis
 * and tests, and must never influence semantic meaning. */
struct nfsp_rpc_record {
	struct nfsp_connection_ref conn;
	int direction;
	const uint8_t *rpc_payload;
	size_t rpc_payload_len;
	uint32_t nfrags;
};

enum nfsp_record_err {
	NFSP_RECORD_OK = 0,
	NFSP_RECORD_ERR_INVAL,		/* NULL argument */
	NFSP_RECORD_ERR_SHORT,		/* input ends inside a header or body */
	NFSP_RECORD_ERR_TRAILING,	/* bytes after the last fragment */
	NFSP_RECORD_ERR_ZERO_FRAG,	/* zero-length fragment, not last */
	NFSP_RECORD_ERR_FRAG_COUNT,	/* more than NFSP_FRAG_COUNT_LIMIT */
	NFSP_RECORD_ERR_TOO_LONG,	/* payload cannot fit one fragment */
	NFSP_RECORD_ERR_NOMEM
};

/* A caller-owned growable buffer, reused across records so a stream of
 * multi-fragment messages does not allocate per message. */
struct nfsp_record_buf {
	uint8_t *p;
	size_t cap;
};

void nfsp_record_buf_free(struct nfsp_record_buf *b);

/* Canonicalise one complete framed record, framed[0..framed_len).
 *
 * The input must be exactly one record: every fragment complete, the last
 * one flagged, nothing after it.  The fragment walk is repeated here rather
 * than trusted from the caller, so a caller that passes the wrong length gets
 * an error instead of a payload with a header inside it.
 *
 * A single-fragment record yields a view into `framed` and does not touch
 * `scratch`.  A multi-fragment record is concatenated into `scratch`, and the
 * view points there.  Either way the view lives no longer than the input and
 * the next use of `scratch`.
 *
 * Returns NFSP_RECORD_OK, or an error with the out-parameters zeroed. */
enum nfsp_record_err nfsp_rpc_payload(const uint8_t *framed, size_t framed_len,
				      struct nfsp_record_buf *scratch,
				      const uint8_t **payload,
				      size_t *payload_len, uint32_t *nfrags);

/* Frame payload[0..len) as one last fragment into `out`, for the Edit Applier
 * output path (design 06 §3).  The result is
 * [last | len][payload], so a payload larger than NFSP_FRAG_LEN_MASK is
 * refused rather than split: a split choice would be a decision about the
 * wire that belongs to whoever chooses it, not to this adapter.
 *
 * `payload` must not point into `out`. */
enum nfsp_record_err nfsp_rpc_frame(const uint8_t *payload, size_t len,
				    struct nfsp_record_buf *out,
				    const uint8_t **framed, size_t *framed_len);

const char *nfsp_record_strerror(enum nfsp_record_err err);

#endif /* NFSP_RPC_RECORD_H */
