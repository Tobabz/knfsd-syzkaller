/* Semantic observer: RpcRecord -> envelope -> Transaction Context -> decode.
 *
 * WHERE IT SITS
 *
 *   The proxy hands every complete record to on_rpc_record (proxy.h) before
 *   the legacy on_record hook can rewrite it.  This observer is that hook in
 *   M3: it reads the RPC envelope (rpc_decode.h), records a CALL in the
 *   Transaction Context (txn.h) and decodes its body (nfs_decode.h), and for
 *   a REPLY looks up the CALL it answers and decodes the result with that
 *   CALL's dispatch.  It never changes or refuses a record: it observes, so
 *   it always returns 0 and the relay is unchanged by it.
 *
 * ORDER (design 03-nfs-proxy/03 §6, §7)
 *
 *   CALL   envelope -> nfsp_txn_call (minimal entry) -> body decode ->
 *          nfsp_txn_enrich.  The entry exists even when the body decode
 *          fails, so a REPLY still finds its procedure.
 *   REPLY  envelope -> nfsp_txn_reply(call_direction = opposite of the
 *          REPLY's) -> body decode with the entry's dispatch only when the
 *          lookup is `found`; otherwise no dispatch, which the decoder
 *          reports as transaction_context_missing.
 *
 *   A record whose envelope is invalid touches no entry.
 *
 * WHAT A CONSUMER GETS
 *
 *   on_decoded, when set, sees every record's outcome (struct
 *   nfsp_semantic_event).  It is how tests and the Resolver (M4) consume the
 *   decode; everything it points at is valid only during the call.
 */
#ifndef NFSP_SEMANTIC_H
#define NFSP_SEMANTIC_H

#include <stdint.h>
#include <stdio.h>

#include "nfs_decode.h"
#include "rpc_decode.h"
#include "rpc_record.h"
#include "schema.h"
#include "txn.h"

#define NFSP_SEMANTIC_NSTATUS	(NFSP_DECODE_PARTIAL + 1)

struct nfsp_semantic_event {
	const struct nfsp_rpc_record *record;
	enum nfsp_rpc_status rpc_status;
	/* The rest only when rpc_status is NFSP_RPC_OK. */
	const struct nfsp_rpc_envelope *rpc;
	enum nfsp_txn_result txn;
	/* CALL: the live entry (INSERTED, DUPLICATE_EQUIVALENT,
	 * AMBIGUOUS_CALL).  REPLY: the entry looked up (FOUND,
	 * AMBIGUOUS_REPLY, EXPIRED_ENTRY), for diagnosis; only FOUND gave the
	 * dispatch.  NULL otherwise. */
	const struct nfsp_txn_entry *entry;
	/* REPLY, FOUND, the forwarded CALL is the one decoded, and its decode
	 * was decoded or partial (design 03 §6, §9): the request summary a
	 * request-dependent check may use.  NULL whenever it may not. */
	const struct nfsp_txn_request *request;
	const struct nfsp_decoded_msg *msg;
};

struct nfsp_semantic_stats {
	uint64_t records, rpc_invalid, calls, replies;
	uint64_t call_status[NFSP_SEMANTIC_NSTATUS];
	uint64_t reply_status[NFSP_SEMANTIC_NSTATUS];
	uint64_t connections_opened, connections_closed;
};

struct nfsp_semantic {
	const struct nfsp_schema_family *const *families;
	size_t nfamilies;
	/* What the peer is given for a CALL (txn.h).  ORIGINAL unless a
	 * legacy rewrite hook runs after this observer. */
	enum nfsp_txn_forwarded forwarded;
	/* Monotonic milliseconds; NULL: CLOCK_MONOTONIC. */
	uint64_t (*clock_ms)(void *arg);
	void *clock_arg;
	void (*on_decoded)(const struct nfsp_semantic_event *ev, void *arg);
	void *on_decoded_arg;

	struct nfsp_txn txn;
	struct nfsp_decoded_msg msg;
	struct nfsp_semantic_stats stats;
};

/* Zero *s, then set families, forwarded and the optional hooks before or
 * after this; it initialises the table.  0, or -1 on a bad bound or no
 * memory. */
int nfsp_semantic_init(struct nfsp_semantic *s,
		       const struct nfsp_txn_cfg *cfg);
void nfsp_semantic_free(struct nfsp_semantic *s);

/* proxy.h hooks; arg is the struct nfsp_semantic. */
int nfsp_semantic_record(const struct nfsp_rpc_record *record, void *arg);
void nfsp_semantic_connection(const struct nfsp_connection_ref *conn,
			      int event, void *arg);
void nfsp_semantic_tick(void *arg);

/* One `semantic ...` and one `txn ...` line of counters. */
void nfsp_semantic_report(const struct nfsp_semantic *s, FILE *out);

#endif /* NFSP_SEMANTIC_H */
