/* Transaction Context: a live RPC CALL and its REPLY, correlated (M3).
 *
 * WHAT IT IS FOR
 *
 *   A REPLY repeats only the XID of its CALL.  The procedure, the minor
 *   version and the request's operations, which the reply's schema and any
 *   request-dependent check need, are only in the CALL.  This table keeps
 *   them for a bounded time between the two (design 03-nfs-proxy/03).
 *
 * THE KEY (design 03 §3, §4)
 *
 *   connection_id + call_direction + xid.  call_direction is the direction
 *   the CALL travelled: a CALL's own direction, the opposite of a REPLY's.
 *   On one connection an NFSv4.1 backchannel CALL (S2C) and a forechannel
 *   CALL (C2S) may carry the same XID; they are two transactions.  No fd,
 *   slot or route is part of the key, and connection_id is never reused.
 *
 * WHAT IS NEVER DONE
 *
 *   A wrong match attaches one request's meaning to another's reply, which
 *   is the false positive the design ranks first.  So nothing here guesses:
 *   - a live key that sees a different CALL becomes ambiguous, never
 *     overwritten (§11);
 *   - a REPLY with no live entry is missing, never matched to a recent one
 *     (§13);
 *   - a full table refuses a new CALL (capacity_exhausted) and never
 *     reclaims a live one (§16);
 *   - a key that expired or became ambiguous is not given to a new CALL
 *     while it is retained: the old CALL's reply may still come (§13).
 *   Only `found` may feed a reply decode or a request-dependent check.
 *
 * BOUNDS (design 03 §15-§17)
 *
 *   Outstanding entries (awaiting a reply) are bounded in total and per
 *   connection, and expire after a timeout without traffic.  Entries that
 *   ended (replied, expired, or ambiguous and answered) are kept a short
 *   while for diagnosis, bounded in number and age, and are the only ones
 *   ever reclaimed.  Times are milliseconds of a monotonic clock that the
 *   caller passes in, so tests control them.
 *
 * Single-threaded: the proxy's event loop calls everything in order.  An
 * entry pointer is valid until the next call that inserts, ticks or closes.
 */
#ifndef NFSP_TXN_H
#define NFSP_TXN_H

#include <stddef.h>
#include <stdint.h>

#include "nfs_decode.h"

/* Request operations kept per entry (design 03 §16 "semantic_context size
 * bound").  knfsd runs at most NFSD_MAX_OPS_PER_COMPOUND (200). */
#define NFSP_TXN_MAX_OPS	256u

/* Initial bounds (design 03 §15-§17, "한계와 미결 사항"), to be revisited
 * against a real workload's peak. */
#define NFSP_TXN_DEFAULT_MAX_OUTSTANDING	4096u
#define NFSP_TXN_DEFAULT_MAX_PER_CONNECTION	1024u
#define NFSP_TXN_DEFAULT_MAX_RETAINED		1024u
#define NFSP_TXN_DEFAULT_TIMEOUT_MS		(300u * 1000u)
#define NFSP_TXN_DEFAULT_RETENTION_MS		(10u * 1000u)

struct nfsp_txn_key {
	uint64_t connection_id;
	int call_direction;	/* NFSP_DIR_C2S or NFSP_DIR_S2C */
	uint32_t xid;
};

enum nfsp_txn_state {
	NFSP_TXN_AWAITING_REPLY = 0,
	NFSP_TXN_REPLIED,
	NFSP_TXN_AMBIGUOUS,
	NFSP_TXN_EXPIRED
};

enum nfsp_txn_result {
	NFSP_TXN_INSERTED = 0,		/* CALL: a new entry */
	NFSP_TXN_DUPLICATE_EQUIVALENT,	/* CALL: retransmission of a live one */
	NFSP_TXN_AMBIGUOUS_CALL,	/* CALL: a different CALL on a live key */
	NFSP_TXN_CAPACITY_EXHAUSTED,	/* CALL: no room, nothing recorded */
	NFSP_TXN_FOUND,			/* REPLY: the one CALL it answers */
	NFSP_TXN_MISSING,		/* REPLY: no entry for the key */
	NFSP_TXN_AMBIGUOUS_REPLY,	/* REPLY: the key saw two CALLs */
	NFSP_TXN_EXPIRED_ENTRY		/* REPLY: the CALL timed out */
};

/* Which CALL the peer was given (design 03 §6, issue #7).  Until the
 * Resolver (M4) exists the observer sees the record before any rewrite: it
 * is the original, and it is what was forwarded unless a legacy rewrite
 * hook may have changed it, in which case the forwarded view is unknown and
 * request-dependent checks must not use it. */
enum nfsp_txn_forwarded {
	NFSP_TXN_FWD_ORIGINAL = 0,
	NFSP_TXN_FWD_UNKNOWN
};

/* What the CALL's semantic decode said, kept for its REPLY (design 03 §9). */
struct nfsp_txn_request {
	int decoded;			/* 0 until nfsp_txn_enrich() */
	enum nfsp_decode_status status;
	int has_minor;
	uint32_t minor_version;
	uint32_t nops;			/* operations decoded */
	int ops_truncated;		/* more than NFSP_TXN_MAX_OPS */
	uint32_t opcodes[NFSP_TXN_MAX_OPS];
};

struct nfsp_txn_entry {
	struct nfsp_txn_key key;
	uint32_t program, version, procedure;
	uint32_t cred_flavor;
	uint64_t activation_generation;	/* 0: outside any activation (M4) */
	struct nfsp_txn_request original;
	enum nfsp_txn_forwarded forwarded;
	enum nfsp_txn_state state;
	enum { NFSP_TXN_NOT_EXPIRED = 0, NFSP_TXN_EXPIRED_TIMEOUT }
		expiry;
	uint64_t created_ms, last_seen_ms, reply_seen_ms;
	uint32_t duplicate_calls, replies;

	/* internal */
	uint64_t fp[2];			/* CALL fingerprint (§11) */
	size_t fp_len;
	uint64_t ended_ms;		/* when it left the outstanding set */
	int32_t hnext, prev, next;
	int used, outstanding;
};

struct nfsp_txn_cfg {
	uint32_t max_outstanding;	/* 0: default */
	uint32_t max_per_connection;
	uint32_t max_retained;
	uint32_t timeout_ms;
	uint32_t retention_ms;
};

struct nfsp_txn_stats {
	uint64_t inserted, enriched, duplicate_equivalent, ambiguous_calls;
	uint64_t capacity_exhausted, superseded;
	uint64_t found, missing, ambiguous_replies, expired_replies;
	uint64_t duplicate_replies;
	uint64_t expired_timeout, expired_connection_closed;
	uint64_t retired, reclaimed;
	uint32_t outstanding, retained, peak_outstanding;
};

struct nfsp_txn {
	struct nfsp_txn_cfg cfg;
	struct nfsp_txn_entry *slots;
	uint32_t nslots;
	int32_t *buckets;
	uint32_t nbuckets;
	int32_t free_head;
	int32_t out_head, out_tail;	/* outstanding, oldest last_seen first */
	int32_t ret_head, ret_tail;	/* retained, oldest end first */
	struct nfsp_txn_stats stats;
};

/* 0 on success, -1 on a bad bound or no memory. */
int nfsp_txn_init(struct nfsp_txn *t, const struct nfsp_txn_cfg *cfg);
void nfsp_txn_free(struct nfsp_txn *t);

/* A CALL with a valid envelope.  `payload` is its whole rpc_payload; its
 * fingerprint decides whether a CALL on a live key is a retransmission (the
 * same bytes) or a different CALL (ambiguous).  A key whose last CALL was
 * answered may carry a new CALL; a key still retained after it expired or
 * became ambiguous may not, since the old CALL's reply may still come: the
 * new CALL makes it ambiguous.  *entry is set for INSERTED,
 * DUPLICATE_EQUIVALENT and AMBIGUOUS_CALL (the key's entry), else NULL.
 * Expires timed-out entries first. */
enum nfsp_txn_result nfsp_txn_call(struct nfsp_txn *t,
				   const struct nfsp_txn_key *key,
				   uint32_t program, uint32_t version,
				   uint32_t procedure, uint32_t cred_flavor,
				   uint64_t activation_generation,
				   enum nfsp_txn_forwarded forwarded,
				   const uint8_t *payload, size_t len,
				   uint64_t now_ms,
				   struct nfsp_txn_entry **entry);

/* Attach the CALL's semantic decode to the entry nfsp_txn_call() just
 * INSERTED (design 03 §6 "entry enrichment").  Only the operations before
 * a failure are kept; a refused decode keeps no operations. */
void nfsp_txn_enrich(struct nfsp_txn *t, struct nfsp_txn_entry *entry,
		     const struct nfsp_decoded_msg *m);

/* A REPLY: `key` is the CALL's key, call_direction already reversed.
 * *entry is set for every result that has an entry (FOUND, AMBIGUOUS_REPLY,
 * EXPIRED_ENTRY) so its diagnostics can be read; only FOUND may be used.
 * FOUND moves an awaiting entry to replied.  Expires timed-out entries
 * first. */
enum nfsp_txn_result nfsp_txn_reply(struct nfsp_txn *t,
				    const struct nfsp_txn_key *key,
				    uint64_t now_ms,
				    const struct nfsp_txn_entry **entry);

/* The reply_dispatch a FOUND entry gives the decoder (design 02 §14):
 * source TRANSACTION_ENTRY, the CALL's program, version, procedure and
 * credential flavor, and its minor version when the CALL's decode read
 * one. */
void nfsp_txn_dispatch(const struct nfsp_txn_entry *e,
		       struct nfsp_reply_dispatch *rd);

/* The connection is gone (design 03 §14): every entry it had is dropped,
 * awaiting ones counted as expired(connection_closed).  Its connection_id
 * is never seen again, so nothing of it is kept. */
void nfsp_txn_connection_closed(struct nfsp_txn *t, uint64_t connection_id);
/* The same, and `dropped` (when not NULL) sees the activation_generation of
 * every entry still outstanding, so a generation's reply debt can be
 * settled as connection_closed rather than resolved. */
void nfsp_txn_connection_closed_cb(struct nfsp_txn *t, uint64_t connection_id,
				   void (*dropped)(uint64_t generation,
						   void *arg),
				   void *arg);

/* Record what the peer was given for the CALL on `key` once that is known
 * (target mode forwards a CALL only after its journal answer).  0, or -1
 * when the key has no entry. */
int nfsp_txn_mark_forwarded(struct nfsp_txn *t, const struct nfsp_txn_key *key,
			    enum nfsp_txn_forwarded forwarded);

/* Expire outstanding entries older than the timeout and drop ended ones
 * older than the retention. */
void nfsp_txn_tick(struct nfsp_txn *t, uint64_t now_ms);

const char *nfsp_txn_strresult(enum nfsp_txn_result r);

#endif /* NFSP_TXN_H */
