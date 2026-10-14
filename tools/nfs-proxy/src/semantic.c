/* Semantic observer (design 03-nfs-proxy/03 §6-§7, 06 §26).  See semantic.h. */
#define _POSIX_C_SOURCE 200809L
#include "semantic.h"
#include "proxy.h"

#include <string.h>
#include <time.h>

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t now_ms(struct nfsp_semantic *s)
{
	return s->clock_ms ? s->clock_ms(s->clock_arg) : monotonic_ms();
}

int nfsp_semantic_init(struct nfsp_semantic *s,
		       const struct nfsp_txn_cfg *cfg)
{
	memset(&s->msg, 0, sizeof(s->msg));
	memset(&s->stats, 0, sizeof(s->stats));
	return nfsp_txn_init(&s->txn, cfg);
}

void nfsp_semantic_free(struct nfsp_semantic *s)
{
	nfsp_txn_free(&s->txn);
	nfsp_decoded_msg_free(&s->msg);
}

static void decode(struct nfsp_semantic *s, const struct nfsp_rpc_record *r,
		   const struct nfsp_rpc_envelope *rpc,
		   const struct nfsp_reply_dispatch *rd)
{
	struct nfsp_decode_input in;

	memset(&in, 0, sizeof(in));
	in.payload = r->rpc_payload;
	in.len = r->rpc_payload_len;
	in.rpc = rpc;
	in.reply_dispatch = rd;
	nfsp_nfs_decode(s->families, s->nfamilies, &in, &s->msg);
}

int nfsp_semantic_record(const struct nfsp_rpc_record *r, void *arg)
{
	struct nfsp_semantic *s = arg;
	struct nfsp_semantic_event ev;
	struct nfsp_rpc_envelope rpc;
	struct nfsp_txn_key key;
	uint64_t now = now_ms(s);

	memset(&ev, 0, sizeof(ev));
	ev.record = r;
	s->stats.records++;
	ev.rpc_status = nfsp_rpc_decode(r->rpc_payload, r->rpc_payload_len,
					&rpc);
	if (ev.rpc_status != NFSP_RPC_OK) {
		/* No key can be trusted: touch no entry (design 03 §6). */
		s->stats.rpc_invalid++;
		goto out;
	}
	ev.rpc = &rpc;
	key.connection_id = r->conn.connection_id;
	key.xid = rpc.xid;
	if (rpc.msg_type == NFSP_RPC_CALL) {
		struct nfsp_txn_entry *e;

		key.call_direction = r->direction;
		ev.txn = nfsp_txn_call(&s->txn, &key, rpc.prog, rpc.vers,
				       rpc.proc, rpc.cred.flavor, 0,
				       s->forwarded, r->rpc_payload,
				       r->rpc_payload_len, now, &e);
		ev.entry = e;
		decode(s, r, &rpc, NULL);
		/* Only a new entry takes this decode: a retransmission is the
		 * same bytes, and an ambiguous key has no one request. */
		if (ev.txn == NFSP_TXN_INSERTED)
			nfsp_txn_enrich(&s->txn, e, &s->msg);
		s->stats.calls++;
		s->stats.call_status[s->msg.status]++;
	} else {
		const struct nfsp_txn_entry *e;
		struct nfsp_reply_dispatch rd;

		key.call_direction = r->direction == NFSP_DIR_C2S ?
				     NFSP_DIR_S2C : NFSP_DIR_C2S;
		ev.txn = nfsp_txn_reply(&s->txn, &key, now, &e);
		ev.entry = e;
		if (ev.txn == NFSP_TXN_FOUND) {
			nfsp_txn_dispatch(e, &rd);
			/* Only a request that decoded may feed a
			 * request-dependent check (design 03 §6). */
			if (e->forwarded == NFSP_TXN_FWD_ORIGINAL &&
			    e->original.decoded &&
			    (e->original.status == NFSP_DECODE_DECODED ||
			     e->original.status == NFSP_DECODE_PARTIAL))
				ev.request = &e->original;
			decode(s, r, &rpc, &rd);
		} else {
			/* Never another entry's dispatch (design 03 §7). */
			decode(s, r, &rpc, NULL);
		}
		s->stats.replies++;
		s->stats.reply_status[s->msg.status]++;
	}
	ev.msg = &s->msg;
out:
	if (s->on_decoded)
		s->on_decoded(&ev, s->on_decoded_arg);
	return 0;
}

void nfsp_semantic_connection(const struct nfsp_connection_ref *conn,
			      int event, void *arg)
{
	struct nfsp_semantic *s = arg;

	if (event == NFSP_CONN_OPENED) {
		s->stats.connections_opened++;
	} else {
		s->stats.connections_closed++;
		nfsp_txn_connection_closed(&s->txn, conn->connection_id);
	}
}

void nfsp_semantic_tick(void *arg)
{
	struct nfsp_semantic *s = arg;

	nfsp_txn_tick(&s->txn, now_ms(s));
}

void nfsp_semantic_report(const struct nfsp_semantic *s, FILE *out)
{
	const struct nfsp_semantic_stats *st = &s->stats;
	const struct nfsp_txn_stats *t = &s->txn.stats;

	fprintf(out, "semantic records=%llu rpc_invalid=%llu calls=%llu "
		"replies=%llu conn_opened=%llu conn_closed=%llu",
		(unsigned long long)st->records,
		(unsigned long long)st->rpc_invalid,
		(unsigned long long)st->calls,
		(unsigned long long)st->replies,
		(unsigned long long)st->connections_opened,
		(unsigned long long)st->connections_closed);
	for (int i = 0; i < NFSP_SEMANTIC_NSTATUS; i++) {
		const char *name =
			nfsp_decode_strstatus((enum nfsp_decode_status)i);

		if (st->call_status[i])
			fprintf(out, " call_%s=%llu", name,
				(unsigned long long)st->call_status[i]);
		if (st->reply_status[i])
			fprintf(out, " reply_%s=%llu", name,
				(unsigned long long)st->reply_status[i]);
	}
	fprintf(out, "\n");
	fprintf(out, "txn inserted=%llu duplicate_equivalent=%llu "
		"ambiguous_calls=%llu capacity_exhausted=%llu superseded=%llu "
		"found=%llu duplicate_replies=%llu missing=%llu "
		"ambiguous_replies=%llu expired_replies=%llu "
		"expired_timeout=%llu expired_connection_closed=%llu "
		"reclaimed=%llu outstanding=%u retained=%u peak_outstanding=%u\n",
		(unsigned long long)t->inserted,
		(unsigned long long)t->duplicate_equivalent,
		(unsigned long long)t->ambiguous_calls,
		(unsigned long long)t->capacity_exhausted,
		(unsigned long long)t->superseded,
		(unsigned long long)t->found,
		(unsigned long long)t->duplicate_replies,
		(unsigned long long)t->missing,
		(unsigned long long)t->ambiguous_replies,
		(unsigned long long)t->expired_replies,
		(unsigned long long)t->expired_timeout,
		(unsigned long long)t->expired_connection_closed,
		(unsigned long long)t->reclaimed,
		t->outstanding, t->retained, t->peak_outstanding);
}
